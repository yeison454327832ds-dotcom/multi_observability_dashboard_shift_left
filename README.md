# Dashboard multi-sistema Shift-Left

Permite seleccionar un sistema y recolectar información de GKE/Cloud Logging para DEV, QA y STAGING. El repositorio no incluye IDs de proyectos reales: cada usuario proporciona los suyos localmente.

## Uso fácil

```bash
cp config.example.env .env
# Edite .env con sus proyectos y namespace.
chmod +x observability.sh
./observability.sh --config .env
```

También puede ejecutarse directamente:

```bash
./observability.sh --system WMS \
  --project-dev mi-proyecto-dev \
  --project-qa mi-proyecto-qa \
  --project-stag mi-proyecto-stag
```

El namespace predeterminado es `wms`, `oms`, `csc` o `tms`. Se puede cambiar así:

```bash
NAMESPACE=otro ./observability.sh --system OMS
```

## Salida

Cada ejecución crea una carpeta en `reports/` con:

- Un dashboard HTML consolidado.
- Una carpeta independiente para cada proyecto DEV, QA y STAGING.
- JSON de pods, deployments, eventos, nodos y errores.
- Métricas de `kubectl top`, cuando Metrics Server está disponible.
- Un `resumen.txt` por proyecto.

## Requisitos

- `gcloud`, `kubectl`, `jq` y `python3`.
- Sesión activa de Google Cloud.
- Permisos de lectura sobre los proyectos y clústeres.

El script solamente consulta información. `get-credentials` actualiza el contexto local de `kubectl`, pero no modifica recursos de GCP/GKE.

## Seguridad antes de publicar

Los reportes contienen información operativa sensible (pods, nodos, IPs, eventos y errores). Por eso `reports/`, `data/` y `.env` están excluidos mediante `.gitignore`.

Antes de hacer commit o publicar, ejecute:

```bash
chmod +x check_publication.sh
./check_publication.sh
```

No use `git add -f` para incorporar archivos ignorados. Si un reporte fue agregado previamente, retírelo del índice y del historial antes de publicar.
