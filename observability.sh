#!/usr/bin/env bash
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/.env"

# Permite elegir otro archivo sin ejecutarlo todavía.
previous=""
for argument in "$@"; do
  if [[ "$previous" == "--config" ]]; then CONFIG_FILE="$argument"; break; fi
  previous="$argument"
done

if [[ -f "$CONFIG_FILE" ]]; then
  # El archivo es local y está excluido de Git. Solo debe contener variables
  # administradas por el propio usuario.
  set -a
  # shellcheck disable=SC1090
  source "$CONFIG_FILE"
  set +a
fi

umask 077

usage() {
  cat <<'EOF'
Uso:
  ./observability.sh --config .env
  ./observability.sh --system MI_SISTEMA \
    --project-dev mi-proyecto-dev \
    --project-qa mi-proyecto-qa \
    --project-stag mi-proyecto-stag

Opcional:
  NAMESPACE=otro ./observability.sh --config .env

Los proyectos no tienen valores predeterminados. Cada usuario debe indicar
sus propios PROJECT_DEV, PROJECT_QA y PROJECT_STAG mediante .env, variables de
entorno o argumentos.
EOF
}

SYSTEM="${SYSTEM:-}"
PROJECT_DEV="${PROJECT_DEV:-}"
PROJECT_QA="${PROJECT_QA:-}"
PROJECT_STAG="${PROJECT_STAG:-}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --system) SYSTEM="${2:-}"; shift 2 ;;
    --project-dev) PROJECT_DEV="${2:-}"; shift 2 ;;
    --project-qa) PROJECT_QA="${2:-}"; shift 2 ;;
    --project-stag) PROJECT_STAG="${2:-}"; shift 2 ;;
    --config) CONFIG_FILE="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "ERROR: opción desconocida: $1" >&2; usage; exit 2 ;;
  esac
done

choose_system() {
  echo "Seleccione el sistema que desea revisar:"
  echo "  1) WMS"
  echo "  2) OMS"
  echo "  3) CSC"
  echo "  4) TMS"
  read -r -p "Opción [1-4]: " option
  case "$option" in
    1) SYSTEM="WMS" ;;
    2) SYSTEM="OMS" ;;
    3) SYSTEM="CSC" ;;
    4) SYSTEM="TMS" ;;
    *) echo "ERROR: opción inválida." >&2; exit 2 ;;
  esac
}

[[ -n "$SYSTEM" ]] || choose_system
SYSTEM="$(tr '[:lower:]' '[:upper:]' <<<"$SYSTEM")"

case "$SYSTEM" in
  WMS)
    DEFAULT_NAMESPACE="wms"
    ;;
  OMS)
    DEFAULT_NAMESPACE="oms"
    ;;
  CSC)
    DEFAULT_NAMESPACE="csc"
    ;;
  TMS)
    DEFAULT_NAMESPACE="tms"
    ;;
  *) echo "ERROR: sistema '$SYSTEM' no soportado. Use WMS, OMS, CSC o TMS." >&2; exit 2 ;;
esac

request_project() {
  local variable_name="$1" label="$2" current_value="${!1:-}"
  if [[ -z "$current_value" && -t 0 ]]; then
    read -r -p "Proyecto GCP de $label: " current_value
    printf -v "$variable_name" '%s' "$current_value"
  fi
  [[ "$current_value" =~ ^[a-z][a-z0-9-]{4,28}[a-z0-9]$ ]] || {
    echo "ERROR: falta un ID válido para $variable_name ($label)." >&2
    echo "Use --config, --project-${label,,} o una variable de entorno." >&2
    exit 2
  }
}

request_project PROJECT_DEV DEV
request_project PROJECT_QA QA
request_project PROJECT_STAG STAG

NAMESPACE="${NAMESPACE:-$DEFAULT_NAMESPACE}"
RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)"
REPORT_DIR="${REPORT_DIR:-$SCRIPT_DIR/reports/${SYSTEM,,}_$RUN_ID}"
DATA_DIR="$REPORT_DIR/data"
mkdir -p "$DATA_DIR" "$REPORT_DIR/projects"

for command_name in gcloud kubectl jq python3; do
  command -v "$command_name" >/dev/null 2>&1 || {
    echo "ERROR: falta el comando '$command_name'." >&2
    exit 1
  }
done

if ! gcloud auth list --filter=status:ACTIVE --format='value(account)' | grep -q .; then
  echo "ERROR: no hay una cuenta activa en gcloud. Ejecute: gcloud auth login --no-launch-browser" >&2
  exit 1
fi

select_cluster() {
  local env_name="$1" project="$2" upper prefix cluster_var location_var cluster location rows count selection
  upper="$(tr '[:lower:]' '[:upper:]' <<<"$env_name")"
  prefix="${SYSTEM}_${upper}"
  cluster_var="${prefix}_CLUSTER"
  location_var="${prefix}_LOCATION"
  cluster="${!cluster_var:-}"
  location="${!location_var:-}"

  if [[ -z "$cluster" ]]; then
    mapfile -t rows < <(gcloud container clusters list --project "$project" --format='value(name,location)' 2>/dev/null)
    count="${#rows[@]}"
    (( count > 0 )) || { echo "ERROR: no se encontraron clústeres GKE en $project." >&2; return 1; }
    if (( count == 1 )); then
      read -r cluster location <<<"${rows[0]}"
    elif [[ -t 0 ]]; then
      echo "Se encontraron varios clústeres en $project:" >&2
      local i=1
      for row in "${rows[@]}"; do echo "  $i) $row" >&2; ((i++)); done
      read -r -p "Seleccione clúster [1-$count]: " selection
      [[ "$selection" =~ ^[0-9]+$ ]] && (( selection >= 1 && selection <= count )) || {
        echo "ERROR: selección inválida." >&2; return 1;
      }
      read -r cluster location <<<"${rows[selection-1]}"
    else
      echo "ERROR: hay varios clústeres en $project. Defina ${cluster_var} y ${location_var}." >&2
      return 1
    fi
  fi

  [[ -n "$location" ]] || {
    location="$(gcloud container clusters list --project "$project" --filter="name=$cluster" --format='value(location)' --limit=1)"
  }
  [[ -n "$location" ]] || { echo "ERROR: no se encontró la ubicación de $cluster." >&2; return 1; }

  echo "Clúster seleccionado: $cluster ($location)"
  if [[ "$location" =~ -[a-z]$ ]]; then
    gcloud container clusters get-credentials "$cluster" --zone "$location" --project "$project" >/dev/null
  else
    gcloud container clusters get-credentials "$cluster" --region "$location" --project "$project" >/dev/null
  fi
}

collect_environment() {
  local env_name="$1"
  local project="$2"
  local project_dir="$REPORT_DIR/projects/${env_name}_${project}"
  mkdir -p "$project_dir"
  echo
  echo "============================================================"
  echo "Recolectando $SYSTEM / ${env_name^^} / $project"
  echo "Namespace: $NAMESPACE"
  echo "============================================================"
  select_cluster "$env_name" "$project"

  kubectl get pods -n "$NAMESPACE" -o json > "$DATA_DIR/${env_name}_pods.json"
  kubectl get deployments -n "$NAMESPACE" -o json > "$DATA_DIR/${env_name}_deployments.json"
  kubectl get events -n "$NAMESPACE" --sort-by=.lastTimestamp -o json > "$DATA_DIR/${env_name}_events.json" || echo '{"items":[]}' > "$DATA_DIR/${env_name}_events.json"
  kubectl get nodes -o json > "$DATA_DIR/${env_name}_nodes.json"

  if kubectl top pods -n "$NAMESPACE" --no-headers >/dev/null 2>&1; then
    kubectl top pods -n "$NAMESPACE" --containers --no-headers > "$DATA_DIR/${env_name}_top.txt" || true
  else
    : > "$DATA_DIR/${env_name}_top.txt"
  fi

  gcloud logging read \
    'resource.type="k8s_container" AND resource.labels.namespace_name="'"$NAMESPACE"'" AND severity>=ERROR' \
    --project "$project" --freshness=6h --limit=100 --format=json \
    > "$DATA_DIR/${env_name}_errors.json" 2>/dev/null || echo '[]' > "$DATA_DIR/${env_name}_errors.json"

  cp "$DATA_DIR/${env_name}_pods.json" "$project_dir/pods.json"
  cp "$DATA_DIR/${env_name}_deployments.json" "$project_dir/deployments.json"
  cp "$DATA_DIR/${env_name}_events.json" "$project_dir/events.json"
  cp "$DATA_DIR/${env_name}_nodes.json" "$project_dir/nodes.json"
  cp "$DATA_DIR/${env_name}_top.txt" "$project_dir/top.txt"
  cp "$DATA_DIR/${env_name}_errors.json" "$project_dir/errors.json"

  jq -r --arg system "$SYSTEM" --arg env "${env_name^^}" --arg project "$project" --arg namespace "$NAMESPACE" '
    ["Sistema: " + $system,
     "Ambiente: " + $env,
     "Proyecto: " + $project,
     "Namespace: " + $namespace,
     "Pods: " + ((.items|length)|tostring),
     "Pods no Running/Succeeded: " + ([.items[] | select(.status.phase != "Running" and .status.phase != "Succeeded")] | length | tostring),
     "Reinicios acumulados: " + ([.items[].status.containerStatuses[]?.restartCount // 0] | add // 0 | tostring)] | .[]
  ' "$project_dir/pods.json" > "$project_dir/resumen.txt"
}

collect_environment dev "$PROJECT_DEV"
collect_environment qa "$PROJECT_QA"
collect_environment stag "$PROJECT_STAG"

python3 "$SCRIPT_DIR/build_dashboard.py" \
  --data-dir "$DATA_DIR" \
  --catalog "$SCRIPT_DIR/observability_catalog.json" \
  --namespace "$NAMESPACE" \
  --system-name "$SYSTEM" \
  --project-dev "$PROJECT_DEV" \
  --project-qa "$PROJECT_QA" \
  --project-stag "$PROJECT_STAG" \
  --output "$REPORT_DIR/dashboard_${SYSTEM,,}.html"

cat > "$REPORT_DIR/LEEME.txt" <<EOF
Sistema: $SYSTEM
Namespace: $NAMESPACE
Generado UTC: $RUN_ID

Dashboard consolidado: dashboard_${SYSTEM,,}.html
Reportes separados: projects/
  dev_${PROJECT_DEV}/
  qa_${PROJECT_QA}/
  stag_${PROJECT_STAG}/
EOF

echo
echo "Proceso terminado correctamente."
echo "Dashboard: $REPORT_DIR/dashboard_${SYSTEM,,}.html"
echo "Reportes por proyecto: $REPORT_DIR/projects"

