#!/usr/bin/env python3
import argparse
import html
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path

PROJECTS = {
    "dev": "",
    "qa": "",
    "stag": "",
}
SYSTEM_NAME = "TMS"
ENV_LABELS = {"dev": "DEV", "qa": "QA", "stag": "STAGING"}
CPU_RE = re.compile(r"^([0-9.]+)(m?)$")
MEM_RE = re.compile(r"^([0-9.]+)(Ki|Mi|Gi|Ti)?$")


def esc(value):
    return html.escape(str(value if value is not None else ""), quote=True)


def cpu_m(value):
    if value is None:
        return 0.0
    match = CPU_RE.match(str(value))
    if not match:
        return 0.0
    number = float(match.group(1))
    return number if match.group(2) == "m" else number * 1000.0


def mem_mib(value):
    if value is None:
        return 0.0
    match = MEM_RE.match(str(value))
    if not match:
        return 0.0
    number = float(match.group(1))
    unit = match.group(2) or ""
    return {
        "": number / (1024 * 1024),
        "Ki": number / 1024,
        "Mi": number,
        "Gi": number * 1024,
        "Ti": number * 1024 * 1024,
    }.get(unit, 0.0)


def read_json(path, default):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return default


def parse_top(path):
    result = {}
    try:
        for line in Path(path).read_text(encoding="utf-8").splitlines():
            parts = line.split()
            if len(parts) < 4:
                continue
            pod, _container, cpu, mem = parts[:4]
            item = result.setdefault(pod, {"cpu_m": 0.0, "mem_mib": 0.0})
            item["cpu_m"] += cpu_m(cpu)
            item["mem_mib"] += mem_mib(mem)
    except Exception:
        pass
    return result


def pod_reason(pod):
    status = pod.get("status", {})
    phase = status.get("phase", "Unknown")
    reasons = []
    for cs in status.get("containerStatuses", []) or []:
        state = cs.get("state", {}) or {}
        waiting = state.get("waiting") or {}
        terminated = state.get("terminated") or {}
        if waiting.get("reason"):
            reasons.append(waiting["reason"])
        elif terminated.get("reason") and terminated.get("reason") != "Completed":
            reasons.append(terminated["reason"])
    return ", ".join(sorted(set(reasons))) or phase


def severity(reason, restarts):
    text = (reason or "").lower()
    critical_words = (
        "crashloopbackoff", "imagepullbackoff", "errimagepull", "oomkilled",
        "failed", "error", "createcontainerconfigerror", "runcontainererror"
    )
    if any(word in text for word in critical_words):
        return "critical"
    if restarts >= 5:
        return "warning"
    if any(word in text for word in ("pending", "containercreating", "terminating", "unknown")):
        return "warning"
    return "ok"


def analyze_env(data_dir, env):
    base = Path(data_dir)
    pods = read_json(base / f"{env}_pods.json", {"items": []}).get("items", [])
    deployments = read_json(base / f"{env}_deployments.json", {"items": []}).get("items", [])
    events = read_json(base / f"{env}_events.json", {"items": []}).get("items", [])
    error_logs = read_json(base / f"{env}_errors.json", [])
    top = parse_top(base / f"{env}_top.txt")

    rows = []
    req_cpu = req_mem = use_cpu = use_mem = 0.0
    healthy = warning = critical = restarts_total = 0

    for pod in pods:
        name = pod.get("metadata", {}).get("name", "")
        spec = pod.get("spec", {}) or {}
        status = pod.get("status", {}) or {}
        container_statuses = status.get("containerStatuses", []) or []
        restarts = sum(int(item.get("restartCount", 0) or 0) for item in container_statuses)
        restarts_total += restarts

        pod_req_cpu = pod_req_mem = 0.0
        for container in spec.get("containers", []) or []:
            requests = ((container.get("resources", {}) or {}).get("requests", {}) or {})
            pod_req_cpu += cpu_m(requests.get("cpu"))
            pod_req_mem += mem_mib(requests.get("memory"))
        req_cpu += pod_req_cpu
        req_mem += pod_req_mem

        actual = top.get(name, {})
        pod_cpu = actual.get("cpu_m", 0.0)
        pod_mem = actual.get("mem_mib", 0.0)
        use_cpu += pod_cpu
        use_mem += pod_mem

        reason = pod_reason(pod)
        sev = severity(reason, restarts)
        if sev == "critical":
            critical += 1
        elif sev == "warning":
            warning += 1
        else:
            healthy += 1

        rows.append({
            "name": name,
            "phase": status.get("phase", "Unknown"),
            "reason": reason,
            "restarts": restarts,
            "req_cpu_m": round(pod_req_cpu, 1),
            "cpu_m": round(pod_cpu, 1),
            "req_mem_mib": round(pod_req_mem, 1),
            "mem_mib": round(pod_mem, 1),
            "severity": sev,
        })

    metrics_available = bool(top)
    cpu_eff = (use_cpu / req_cpu * 100) if req_cpu > 0 and metrics_available else None
    mem_eff = (use_mem / req_mem * 100) if req_mem > 0 and metrics_available else None
    cpu_waste = max(0, req_cpu - use_cpu) if metrics_available else None
    mem_waste = max(0, req_mem - use_mem) if metrics_available else None

    # Score simple de salud actual. Los reinicios se limitan para evitar que un histórico viejo domine todo el score.
    score_penalty = critical * 12 + warning * 3 + min(15, sum(1 for r in rows if r["restarts"] > 0))
    health_score = max(0, 100 - score_penalty)

    warning_events = []
    for event in events[-150:]:
        event_type = event.get("type", "")
        reason = event.get("reason", "")
        message = event.get("message", "") or ""
        if event_type == "Warning" or reason in {"Failed", "BackOff", "Unhealthy", "FailedMount", "FailedScheduling"}:
            warning_events.append({
                "reason": reason,
                "message": message[:350],
                "object": (event.get("involvedObject", {}) or {}).get("name", ""),
            })

    # Agrega una muestra de errores de Cloud Logging para detectar señales como PERMISSION_DENIED, Pub/Sub o secretos.
    if isinstance(error_logs, list):
        for entry in error_logs[-50:]:
            payload = entry.get("textPayload") or ""
            if not payload and isinstance(entry.get("jsonPayload"), dict):
                jp = entry.get("jsonPayload") or {}
                payload = jp.get("message") or jp.get("msg") or json.dumps(jp, ensure_ascii=False)
            resource_labels = ((entry.get("resource") or {}).get("labels") or {})
            obj = resource_labels.get("pod_name") or resource_labels.get("container_name") or "Cloud Logging"
            if payload:
                warning_events.append({"reason": "Cloud Logging", "message": str(payload)[:350], "object": obj})

    rows_sorted = sorted(
        rows,
        key=lambda row: ({"critical": 0, "warning": 1, "ok": 2}[row["severity"]], -row["restarts"], row["name"]),
    )
    return {
        "project": PROJECTS[env],
        "pods": len(rows),
        "deployments": len(deployments),
        "healthy": healthy,
        "warning": warning,
        "critical": critical,
        "restarts": restarts_total,
        "health_score": health_score,
        "req_cpu_m": round(req_cpu, 1),
        "use_cpu_m": round(use_cpu, 1),
        "req_mem_mib": round(req_mem, 1),
        "use_mem_mib": round(use_mem, 1),
        "cpu_eff": None if cpu_eff is None else round(cpu_eff, 1),
        "mem_eff": None if mem_eff is None else round(mem_eff, 1),
        "cpu_waste_m": None if cpu_waste is None else round(cpu_waste, 1),
        "mem_waste_mib": None if mem_waste is None else round(mem_waste, 1),
        "metrics_available": metrics_available,
        "rows": rows_sorted,
        "events": warning_events[-30:],
    }


def load_catalog(path, namespace):
    raw = read_json(path, [])
    result = []
    for item in raw if isinstance(raw, list) else []:
        copied = dict(item)
        query = str(copied.get("query", "") or "")
        # El Excel original contiene ejemplos WMS; se adapta al namespace TMS en el HTML.
        query = query.replace('namespace="wms"', f'namespace="{namespace}"')
        query = query.replace("namespace='wms'", f"namespace='{namespace}'")
        query = query.replace('namespace=~"wms"', f'namespace=~"{namespace}"')
        copied["query"] = query
        result.append(copied)
    return result


def catalog_lookup(catalog):
    return {item.get("service"): item for item in catalog}


def recommended_checks(analyses, catalog):
    lookup = catalog_lookup(catalog)
    reasons = []
    total_critical = sum(a["critical"] for a in analyses.values())
    total_restarts = sum(a["restarts"] for a in analyses.values())
    low_cpu = [ENV_LABELS[e] for e, a in analyses.items() if a["cpu_eff"] is not None and a["cpu_eff"] < 30]
    low_mem = [ENV_LABELS[e] for e, a in analyses.items() if a["mem_eff"] is not None and a["mem_eff"] < 50]

    if total_critical:
        reasons.append(("GKE_POD_HEALTH", f"Hay {total_critical} pod(s) crítico(s) en los ambientes analizados."))
    if total_restarts:
        reasons.append(("GKE_LATENCY", f"Se observan {total_restarts} reinicios acumulados; priorizar hotspots y causas actuales."))
    if low_cpu or low_mem:
        envs = sorted(set(low_cpu + low_mem))
        reasons.append(("GKE_FINOPS", f"Hay señales de baja utilización frente a requests en: {', '.join(envs)}."))
        reasons.append(("GKE_CAPACITY", "Comparar memoria usada vs solicitada antes de hacer rightsizing."))

    corpus = []
    for analysis in analyses.values():
        corpus.extend(row["reason"] + " " + row["name"] for row in analysis["rows"])
        corpus.extend(event["message"] + " " + event["reason"] for event in analysis["events"])
    text = " ".join(corpus).lower()
    if "permission_denied" in text or "permission denied" in text or "forbidden" in text:
        reasons.append(("IAM", "Se detectaron señales de permisos/autorización; validar roles mínimos y Service Accounts."))
    if "pubsub" in text or "subscription" in text or "topic" in text:
        reasons.append(("PUBSUB", "Se detectaron referencias a Pub/Sub; revisar backlog y permisos de consumidores."))
    if "secret" in text:
        reasons.append(("SECRET_MANAGER", "Se detectaron referencias a secretos/credenciales; validar versiones y acceso."))
    if "sql" in text or "database" in text or "connection refused" in text:
        reasons.append(("CLOUDSQL", "Se detectaron señales de conectividad/base de datos; validar utilización y conexiones."))

    output = []
    seen = set()
    for service, why in reasons:
        if service in seen or service not in lookup:
            continue
        seen.add(service)
        item = dict(lookup[service])
        item["why"] = why
        output.append(item)
    return output[:8]


def pct_bar(label, value, max_value=100):
    width = 0 if value is None else max(0, min(max_value, float(value))) / max_value * 100
    text = "N/D" if value is None else f"{value:.1f}%"
    return f"""
      <div class="metric-row">
        <div class="metric-head"><span>{esc(label)}</span><strong>{text}</strong></div>
        <div class="bar"><span style="width:{width:.1f}%"></span></div>
      </div>"""


def env_card(env, analysis):
    metrics_note = "" if analysis["metrics_available"] else (
        '<div class="notice">Sin <code>kubectl top</code>: no hay consumo real de CPU/Memoria. '
        'Valida Metrics Server para habilitar esta sección.</div>'
    )
    return f"""
    <section class="env-card">
      <div class="env-title">
        <div><h2>{ENV_LABELS[env]}</h2><small>{esc(analysis['project'])}</small></div>
        <div class="score">{analysis['health_score']}<small>/100</small></div>
      </div>
      <div class="kpis">
        <div><span>Pods</span><b>{analysis['pods']}</b></div>
        <div><span>OK</span><b>{analysis['healthy']}</b></div>
        <div><span>Alerta</span><b>{analysis['warning']}</b></div>
        <div><span>Crítico</span><b>{analysis['critical']}</b></div>
        <div><span>Restarts</span><b>{analysis['restarts']}</b></div>
        <div><span>Deployments</span><b>{analysis['deployments']}</b></div>
      </div>
      {pct_bar('Eficiencia CPU (uso/request)', analysis['cpu_eff'])}
      {pct_bar('Eficiencia Memoria (uso/request)', analysis['mem_eff'])}
      <div class="waste"><span>CPU potencialmente sobredimensionada</span><b>{'N/D' if analysis['cpu_waste_m'] is None else f"{analysis['cpu_waste_m']:.0f} mCPU"}</b></div>
      <div class="waste"><span>Memoria potencialmente sobredimensionada</span><b>{'N/D' if analysis['mem_waste_mib'] is None else f"{analysis['mem_waste_mib']:.0f} MiB"}</b></div>
      {metrics_note}
    </section>"""


def health_rows(analyses):
    rows = []
    for env, analysis in analyses.items():
        total = max(1, analysis["pods"])
        ok = analysis["healthy"] / total * 100
        warn = analysis["warning"] / total * 100
        crit = analysis["critical"] / total * 100
        rows.append(f"""
        <div class="health-line">
          <div class="health-label"><b>{ENV_LABELS[env]}</b><span>{analysis['pods']} pods</span></div>
          <div class="stack" title="OK {analysis['healthy']} | Alertas {analysis['warning']} | Críticos {analysis['critical']}">
            <span class="seg ok" style="width:{ok:.2f}%"></span>
            <span class="seg warning" style="width:{warn:.2f}%"></span>
            <span class="seg critical" style="width:{crit:.2f}%"></span>
          </div>
          <div class="health-counts"><span>{analysis['healthy']} OK</span><span>{analysis['warning']} alerta</span><span>{analysis['critical']} crítico</span></div>
        </div>""")
    return "".join(rows)


def build_hotspots(analyses, limit=10):
    rows = []
    for env, analysis in analyses.items():
        for row in analysis["rows"]:
            if row["restarts"] > 0 or row["severity"] != "ok":
                rows.append({**row, "env": env})
    rows.sort(key=lambda item: (item["severity"] != "critical", -item["restarts"]))
    top = rows[:limit]
    maximum = max([item["restarts"] for item in top] + [1])
    html_rows = []
    for item in top:
        width = max(3, item["restarts"] / maximum * 100) if item["restarts"] else 3
        html_rows.append(f"""
        <div class="hotspot">
          <div class="hotspot-title"><span class="pill env">{ENV_LABELS[item['env']]}</span><b>{esc(item['name'])}</b><span class="pill {item['severity']}">{esc(item['reason'])}</span></div>
          <div class="hotspot-bar"><span class="{item['severity']}" style="width:{width:.1f}%"></span></div>
          <small>{item['restarts']} reinicios acumulados</small>
        </div>""")
    return "".join(html_rows) if html_rows else '<p class="explain">No se detectaron pods con reinicios o estados de alerta.</p>'


def catalog_category_bars(catalog):
    counts = Counter(item.get("category", "Otros") for item in catalog)
    maximum = max(counts.values(), default=1)
    rows = []
    for category, count in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
        rows.append(f"""
        <div class="catalog-bar-row">
          <div class="catalog-bar-label"><span>{esc(category)}</span><b>{count}</b></div>
          <div class="catalog-bar"><span style="width:{count/maximum*100:.1f}%"></span></div>
        </div>""")
    return "".join(rows)


def recommendation_cards(recommendations):
    if not recommendations:
        return '<p class="explain">No se generaron recomendaciones automáticas con la muestra actual.</p>'
    cards = []
    for item in recommendations:
        cards.append(f"""
        <article class="rec-card">
          <div class="rec-head"><span class="pill service">{esc(item.get('service'))}</span><small>{esc(item.get('category'))}</small></div>
          <p><b>Por qué:</b> {esc(item.get('why'))}</p>
          <p><b>Validar:</b> {esc(item.get('validate'))}</p>
          <p><b>Acción sugerida:</b> {esc(item.get('correct'))}</p>
          <details><summary>Ver consulta / CLI</summary>
            <div class="code-label">Query / filtro</div><pre>{esc(item.get('query'))}</pre>
            <div class="code-label">gcloud CLI</div><pre>{esc(item.get('gcloud_cli'))}</pre>
          </details>
        </article>""")
    return "".join(cards)


def catalog_rows(catalog):
    rows = []
    for item in catalog:
        searchable = " ".join(str(item.get(key, "")) for key in ("service", "category", "extract", "validate", "correct", "notes")).lower()
        rows.append(f"""
        <tr data-category="{esc(item.get('category'))}" data-search="{esc(searchable)}">
          <td><span class="pill service">{esc(item.get('service'))}</span></td>
          <td>{esc(item.get('category'))}</td>
          <td>{esc(item.get('extract'))}</td>
          <td>{esc(item.get('validate'))}</td>
          <td>{esc(item.get('correct'))}</td>
          <td>
            <details><summary>Ver detalle</summary>
              <div class="code-label">Query / filtro</div><pre>{esc(item.get('query'))}</pre>
              <div class="code-label">gcloud CLI</div><pre>{esc(item.get('gcloud_cli'))}</pre>
              <div class="code-label">Notas</div><div class="detail-note">{esc(item.get('notes'))}</div>
            </details>
          </td>
        </tr>""")
    return "".join(rows)


def build_html(analyses, catalog, namespace):
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    recommendations = recommended_checks(analyses, catalog)
    total_pods = sum(item["pods"] for item in analyses.values())
    total_critical = sum(item["critical"] for item in analyses.values())
    total_warning = sum(item["warning"] for item in analyses.values())
    total_restarts = sum(item["restarts"] for item in analyses.values())
    category_count = len(set(item.get("category") for item in catalog))

    env_json = json.dumps({
        env: {key: value for key, value in analysis.items() if key not in ("rows", "events")}
        for env, analysis in analyses.items()
    }, ensure_ascii=False)

    pod_rows = []
    for env, analysis in analyses.items():
        for row in analysis["rows"]:
            pod_rows.append(f"""
            <tr data-env="{env}" data-sev="{row['severity']}">
              <td><span class="pill env">{ENV_LABELS[env]}</span></td>
              <td>{esc(row['name'])}</td>
              <td><span class="pill {row['severity']}">{esc(row['reason'])}</span></td>
              <td>{row['restarts']}</td>
              <td>{row['cpu_m']:.0f} / {row['req_cpu_m']:.0f} m</td>
              <td>{row['mem_mib']:.0f} / {row['req_mem_mib']:.0f} MiB</td>
            </tr>""")

    events = []
    for env, analysis in analyses.items():
        for event in analysis["events"]:
            events.append(f"""
            <div class="event">
              <span class="pill env">{ENV_LABELS[env]}</span>
              <b>{esc(event['reason'])}</b>
              <span>{esc(event['object'])}</span>
              <small>{esc(event['message'])}</small>
            </div>""")

    categories = sorted(set(item.get("category", "Otros") for item in catalog))
    category_options = "".join(f'<option value="{esc(cat)}">{esc(cat)}</option>' for cat in categories)

    return f"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Observabilidad {esc(SYSTEM_NAME)} - Shift Left</title>
<style>
:root {{
  --bg:#0b1020; --panel:#121a2d; --panel2:#18233a; --panel3:#0e1628; --text:#eef3ff; --muted:#9aa8c7;
  --ok:#28c76f; --warn:#ffb020; --crit:#ff5c5c; --accent:#58a6ff; --accent2:#7d5cff; --line:#273451;
}}
*{{box-sizing:border-box}} html{{scroll-behavior:smooth}}
body{{margin:0;background:var(--bg);color:var(--text);font:14px/1.45 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}}
a{{color:#83bdff;text-decoration:none}} a:hover{{text-decoration:underline}}
header{{padding:20px 28px;border-bottom:1px solid var(--line);position:sticky;top:0;background:rgba(11,16,32,.96);backdrop-filter:blur(8px);z-index:10}}
.header-row{{display:flex;justify-content:space-between;gap:18px;align-items:center;max-width:1600px;margin:auto}}
header h1{{margin:0 0 4px;font-size:24px}} header p{{margin:0;color:var(--muted)}}
nav{{display:flex;gap:8px;flex-wrap:wrap}} nav a{{padding:7px 10px;border:1px solid var(--line);border-radius:999px;background:var(--panel2);font-size:12px}}
main{{padding:24px;max-width:1600px;margin:auto}}
.grid{{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:18px}}
.row2{{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-top:18px}}
.row3{{display:grid;grid-template-columns:1.2fr .8fr;gap:18px;margin-top:18px}}
.env-card,.panel{{background:var(--panel);border:1px solid var(--line);border-radius:16px;padding:18px}}
.panel h2,.panel h3{{margin-top:0}}
.env-title{{display:flex;justify-content:space-between;gap:12px;align-items:flex-start}}
.env-title h2{{margin:0;font-size:22px}} small,.explain{{color:var(--muted)}} .score{{font-size:30px;font-weight:800}} .score small{{font-size:12px}}
.summary-strip{{display:grid;grid-template-columns:repeat(6,1fr);gap:10px;margin-bottom:18px}}
.summary-strip div{{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:14px}}
.summary-strip span{{display:block;color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.04em}} .summary-strip b{{font-size:24px}}
.kpis{{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin:16px 0}}
.kpis div{{background:var(--panel2);border-radius:10px;padding:10px}} .kpis span{{display:block;color:var(--muted);font-size:11px}} .kpis b{{font-size:20px}}
.metric-row{{margin:14px 0}} .metric-head{{display:flex;justify-content:space-between;margin-bottom:5px}}
.bar,.catalog-bar,.hotspot-bar{{height:10px;background:#202c47;border-radius:999px;overflow:hidden}} .bar>span,.catalog-bar>span{{display:block;height:100%;background:linear-gradient(90deg,var(--accent),var(--accent2))}}
.waste{{display:flex;justify-content:space-between;gap:12px;padding:8px 0;border-top:1px dashed var(--line)}}
.notice{{margin-top:10px;padding:9px;border:1px solid #624a18;background:#2a2212;border-radius:9px;color:#ffd47a}}
.chart{{height:280px;display:flex;align-items:flex-end;gap:28px;padding:20px 12px 30px;border-left:1px solid var(--line);border-bottom:1px solid var(--line)}}
.group{{flex:1;display:flex;gap:8px;align-items:flex-end;height:100%;justify-content:center;position:relative}} .col{{width:28px;min-height:2px;border-radius:6px 6px 0 0}}
.c1{{background:#58a6ff}} .c2{{background:#7d5cff}} .group label{{position:absolute;bottom:-25px;color:var(--muted)}}
.legend{{display:flex;gap:18px;color:var(--muted);margin-top:8px}} .legend i{{display:inline-block;width:10px;height:10px;border-radius:2px;margin-right:5px}}
.health-line{{margin:16px 0}} .health-label,.health-counts{{display:flex;justify-content:space-between;gap:8px}} .health-label span,.health-counts{{color:var(--muted);font-size:12px}}
.stack{{display:flex;height:18px;border-radius:999px;overflow:hidden;background:#202c47;margin:6px 0}} .seg{{height:100%}} .seg.ok{{background:var(--ok)}} .seg.warning{{background:var(--warn)}} .seg.critical{{background:var(--crit)}}
.hotspot{{margin:12px 0}} .hotspot-title{{display:grid;grid-template-columns:auto minmax(0,1fr) auto;gap:8px;align-items:center}} .hotspot-title b{{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.hotspot-bar{{margin:6px 0}} .hotspot-bar span{{display:block;height:100%;border-radius:999px}} .hotspot-bar span.ok{{background:var(--ok)}} .hotspot-bar span.warning{{background:var(--warn)}} .hotspot-bar span.critical{{background:var(--crit)}}
.filters,.catalog-tools{{display:flex;gap:8px;flex-wrap:wrap;margin-bottom:12px}}
button,select,input{{background:var(--panel2);color:var(--text);border:1px solid var(--line);border-radius:999px;padding:8px 12px}} button{{cursor:pointer}} button.active{{border-color:var(--accent)}} input{{min-width:280px}}
table{{width:100%;border-collapse:collapse}} th,td{{padding:10px 8px;text-align:left;border-bottom:1px solid var(--line);vertical-align:top}} th{{color:#a8caff;font-size:12px;position:sticky;top:76px;background:var(--panel);z-index:2}}
.table-wrap{{max-height:560px;overflow:auto;border:1px solid var(--line);border-radius:12px}}
.pill{{display:inline-block;padding:3px 8px;border-radius:999px;font-size:11px;white-space:nowrap}} .pill.ok{{background:#123823;color:#84f0ad}} .pill.warning{{background:#493313;color:#ffd17c}} .pill.critical{{background:#4a1d22;color:#ff9aa3}} .pill.env{{background:#193455;color:#9fd0ff}} .pill.service{{background:#242e50;color:#c8d5ff}}
.event{{padding:10px 0;border-bottom:1px solid var(--line);display:grid;grid-template-columns:auto auto 1fr;gap:8px;align-items:start}} .event small{{grid-column:2/4}}
.catalog-bar-row{{margin:12px 0}} .catalog-bar-label{{display:flex;justify-content:space-between;gap:8px;margin-bottom:5px}}
.rec-grid{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}} .rec-card{{background:var(--panel3);border:1px solid var(--line);border-radius:12px;padding:14px}} .rec-card p{{margin:8px 0}} .rec-head{{display:flex;justify-content:space-between;gap:8px;align-items:center}}
pre{{white-space:pre-wrap;word-break:break-word;background:#080d19;border:1px solid var(--line);padding:10px;border-radius:9px;color:#dbe7ff;max-height:220px;overflow:auto}} details summary{{cursor:pointer;color:#a8caff}} .code-label{{color:var(--muted);font-size:11px;margin-top:10px;text-transform:uppercase}} .detail-note{{padding:8px 0;color:#dbe7ff}}
.source-note{{display:flex;justify-content:space-between;gap:12px;align-items:center;padding:12px;border:1px dashed var(--line);border-radius:12px;background:var(--panel3);margin-bottom:14px}}
footer{{padding:22px;color:var(--muted);text-align:center}}
@media(max-width:1100px){{.grid,.row2,.row3,.rec-grid{{grid-template-columns:1fr}} .summary-strip{{grid-template-columns:repeat(3,1fr)}} nav{{display:none}}}}
@media(max-width:650px){{main{{padding:12px}} header{{padding:12px}} .summary-strip{{grid-template-columns:repeat(2,1fr)}} input{{min-width:100%;width:100%}}}}
</style>
</head>
<body>
<header>
  <div class="header-row">
    <div><h1>Observabilidad {esc(SYSTEM_NAME)} – DEV / QA / STAGING</h1><p>Shift-Left: salud, reinicios, capacidad, FinOps y catálogo de métricas. Generado: {generated}</p></div>
    <nav><a href="#resumen">Resumen</a><a href="#pods">Pods</a><a href="#shiftleft">Shift-Left</a><a href="#eventos">Eventos</a></nav>
  </div>
</header>
<main>
  <section id="resumen" class="summary-strip">
    <div><span>Pods analizados</span><b>{total_pods}</b></div>
    <div><span>Críticos</span><b>{total_critical}</b></div>
    <div><span>Alertas</span><b>{total_warning}</b></div>
    <div><span>Restarts acumulados</span><b>{total_restarts}</b></div>
    <div><span>Controles Shift-Left</span><b>{len(catalog)}</b></div>
    <div><span>Categorías observabilidad</span><b>{category_count}</b></div>
  </section>

  <div class="grid">
    {env_card('dev', analyses['dev'])}
    {env_card('qa', analyses['qa'])}
    {env_card('stag', analyses['stag'])}
  </div>

  <div class="row2">
    <section class="panel"><h3>Salud por ambiente</h3><p class="explain">Distribución de pods OK, alerta y críticos en la muestra actual.</p>{health_rows(analyses)}</section>
    <section class="panel"><h3>Hotspots de reinicios / fallas</h3><p class="explain">Prioriza los pods con estado crítico y mayor acumulación de reinicios.</p>{build_hotspots(analyses)}</section>
  </div>

  <div class="row2">
    <section class="panel"><h3>CPU solicitada vs uso observado</h3><p class="explain">Una brecha grande puede indicar requests sobredimensionados. Confirma con datos de varios días antes de ajustar.</p><div id="cpuChart" class="chart"></div><div class="legend"><span><i class="c1"></i>Requests CPU</span><span><i class="c2"></i>Uso CPU</span></div></section>
    <section class="panel"><h3>Memoria solicitada vs uso observado</h3><p class="explain">Compara uso real contra requests para identificar riesgo de OOM o capacidad reservada sin uso.</p><div id="memChart" class="chart"></div><div class="legend"><span><i class="c1"></i>Requests Memoria</span><span><i class="c2"></i>Uso Memoria</span></div></section>
  </div>

  <section id="pods" class="panel" style="margin-top:18px">
    <h3>Pods – detalle operativo</h3>
    <div class="filters"><button class="active" onclick="filterPods('all',this)">Todos</button><button onclick="filterPods('critical',this)">Críticos</button><button onclick="filterPods('warning',this)">Alertas</button><button onclick="filterPods('ok',this)">OK</button><button onclick="filterPods('dev',this)">DEV</button><button onclick="filterPods('qa',this)">QA</button><button onclick="filterPods('stag',this)">STAGING</button></div>
    <div class="table-wrap"><table><thead><tr><th>Ambiente</th><th>Pod</th><th>Estado / razón</th><th>Restarts</th><th>CPU uso/request</th><th>Mem uso/request</th></tr></thead><tbody id="podRows">{''.join(pod_rows)}</tbody></table></div>
  </section>

  <section id="shiftleft" class="panel" style="margin-top:18px">
    <h2>Shift-Left Observability – métricas incorporadas desde Excel</h2>
    <div class="source-note"><div><b>Catálogo integrado:</b> <code>observability_catalog.json</code><br><small>Las consultas se muestran como guía. Ajusta proyecto, región, nombres de recursos y permisos antes de ejecutarlas.</small></div></div>
    <div class="row3">
      <div><h3>Controles por dominio</h3><p class="explain">El catálogo contiene {len(catalog)} controles distribuidos en {category_count} dominios.</p>{catalog_category_bars(catalog)}</div>
      <div><h3>Cómo usar esta matriz</h3><div class="explain"><p><b>1.</b> Detecta la señal en el dashboard.</p><p><b>2.</b> Abre el control recomendado.</p><p><b>3.</b> Ejecuta la query/CLI en solo lectura.</p><p><b>4.</b> Valida la condición indicada.</p><p><b>5.</b> Aplica corrección únicamente por el flujo autorizado.</p><p><b>Namespace actual:</b> <code>{esc(namespace)}</code>.</p></div></div>
    </div>

    <h3 style="margin-top:22px">Controles recomendados para la muestra actual</h3>
    <div class="rec-grid">{recommendation_cards(recommendations)}</div>

    <h3 style="margin-top:22px">Catálogo completo de observabilidad</h3>
    <div class="catalog-tools"><input id="catalogSearch" type="search" placeholder="Buscar servicio, validación o corrección..." oninput="filterCatalog()"><select id="catalogCategory" onchange="filterCatalog()"><option value="all">Todas las categorías</option>{category_options}</select><span id="catalogCount" class="pill service">{len(catalog)} controles</span></div>
    <div class="table-wrap"><table><thead><tr><th>Servicio</th><th>Categoría</th><th>Qué extraer</th><th>Qué validar</th><th>Cómo corregir</th><th>Query / CLI</th></tr></thead><tbody id="catalogRows">{catalog_rows(catalog)}</tbody></table></div>
  </section>

  <section id="eventos" class="panel" style="margin-top:18px"><h3>Eventos de advertencia recientes</h3>{''.join(events) if events else '<p class="explain">No se encontraron eventos Warning en la muestra recolectada.</p>'}</section>
</main>
<footer>Dashboard de solo lectura. No modifica recursos de GCP, GKE ni Azure DevOps.</footer>
<script>
const D = {env_json};
function makeChart(id, reqKey, useKey) {{
  const root = document.getElementById(id); const envs=['dev','qa','stag'];
  const max = Math.max(1, ...envs.flatMap(e => [D[e][reqKey]||0, D[e][useKey]||0]));
  root.innerHTML = envs.map(e => {{
    const rq=D[e][reqKey]||0, us=D[e][useKey]||0; const h1=Math.max(2,rq/max*100), h2=Math.max(2,us/max*100);
    return `<div class="group"><div title="Request ${{rq}}" class="col c1" style="height:${{h1}}%"></div><div title="Uso ${{us}}" class="col c2" style="height:${{h2}}%"></div><label>${{e==='stag'?'STAGING':e.toUpperCase()}}</label></div>`;
  }}).join('');
}}
makeChart('cpuChart','req_cpu_m','use_cpu_m'); makeChart('memChart','req_mem_mib','use_mem_mib');
function filterPods(filter,btn) {{
  document.querySelectorAll('.filters button').forEach(b=>b.classList.remove('active')); btn.classList.add('active');
  document.querySelectorAll('#podRows tr').forEach(tr=>{{tr.style.display=(filter==='all'||tr.dataset.sev===filter||tr.dataset.env===filter)?'':'none';}});
}}
function filterCatalog() {{
  const q=document.getElementById('catalogSearch').value.trim().toLowerCase(); const cat=document.getElementById('catalogCategory').value; let shown=0;
  document.querySelectorAll('#catalogRows tr').forEach(tr=>{{const okText=!q||tr.dataset.search.includes(q); const okCat=cat==='all'||tr.dataset.category===cat; const show=okText&&okCat; tr.style.display=show?'':'none'; if(show) shown++;}});
  document.getElementById('catalogCount').textContent=`${{shown}} controles`;
}}
</script>
</body>
</html>"""


def main():
    global PROJECTS, SYSTEM_NAME
    parser = argparse.ArgumentParser(description="Genera dashboard HTML de observabilidad TMS con catálogo Shift-Left")
    parser.add_argument("--data-dir", default="data", help="Directorio con datos recolectados")
    parser.add_argument("--catalog", default="observability_catalog.json", help="JSON generado desde el Excel de métricas")
    parser.add_argument("--namespace", default="tms", help="Namespace Kubernetes")
    parser.add_argument("--output", default="index.html", help="Archivo HTML de salida")
    parser.add_argument("--system-name", default="TMS", help="Nombre mostrado en el dashboard")
    parser.add_argument("--project-dev", required=True, help="Proyecto GCP de DEV")
    parser.add_argument("--project-qa", required=True, help="Proyecto GCP de QA")
    parser.add_argument("--project-stag", required=True, help="Proyecto GCP de STAGING")
    args = parser.parse_args()

    SYSTEM_NAME = args.system_name.upper()
    PROJECTS = {"dev": args.project_dev, "qa": args.project_qa, "stag": args.project_stag}

    analyses = {env: analyze_env(args.data_dir, env) for env in ("dev", "qa", "stag")}
    catalog = load_catalog(args.catalog, args.namespace)
    Path(args.output).write_text(build_html(analyses, catalog, args.namespace), encoding="utf-8")
    print(f"Dashboard generado: {Path(args.output).resolve()}")
    print(f"Controles Shift-Left integrados: {len(catalog)}")


if __name__ == "__main__":
    main()
