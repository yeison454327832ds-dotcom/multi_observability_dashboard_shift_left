#!/usr/bin/env bash
set -Eeuo pipefail

# Verificación local previa a publicar. No imprime valores encontrados.

if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo "ERROR: ejecute este script dentro del repositorio Git." >&2
  exit 2
fi

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(git rev-parse --show-toplevel)"
SCOPE="$(realpath --relative-to="$REPO_ROOT" "$SCRIPT_DIR")"

list_scoped_files() {
  git -C "$REPO_ROOT" ls-files -- "$SCOPE"
}

failures=0

check_tracked_path() {
  local pattern="$1" description="$2"
  if list_scoped_files | grep -Eq "$pattern"; then
    echo "ERROR: Git contiene $description." >&2
    failures=$((failures + 1))
  fi
}

check_tracked_path '(^|/)reports/' 'reportes operativos en reports/'
check_tracked_path '(^|/)data/' 'datos recolectados en data/'
check_tracked_path '(^|/)\.env($|\.)' 'un archivo .env local'
check_tracked_path '(credentials.*\.json|service-account.*\.json|\.pem$|\.key$|\.p12$|\.pfx$)' 'posibles credenciales o llaves'

tracked_files=()
while IFS= read -r file; do
  [[ -n "$file" ]] && tracked_files+=("$REPO_ROOT/$file")
done < <(list_scoped_files)

if ((${#tracked_files[@]})); then
  patterns=(
    '-----BEGIN ([A-Z ]+)?PRIVATE KEY-----'
    'AIza[0-9A-Za-z_-]{35}'
    'AKIA[0-9A-Z]{16}'
    'gh[pousr]_[A-Za-z0-9_]{30,}'
    'Authorization:[[:space:]]*(Bearer|Basic)[[:space:]]+[A-Za-z0-9+/_.=-]{12,}'
    '"type"[[:space:]]*:[[:space:]]*"service_account"'
    '(^|[^A-Za-z0-9])cpl-[a-z0-9-]{5,}([^A-Za-z0-9]|$)'
    '[A-Za-z0-9.-]+\.coppel\.(com|io)'
  )
  for pattern in "${patterns[@]}"; do
    if rg -l -i -- "$pattern" "${tracked_files[@]}" >/dev/null 2>&1; then
      echo "ERROR: se detectó un patrón sensible/corporativo en archivos versionados." >&2
      failures=$((failures + 1))
    fi
  done
fi

if ((failures)); then
  echo "Publicación bloqueada: $failures control(es) fallaron." >&2
  exit 1
fi

echo "OK: no se detectaron reportes, archivos sensibles ni identificadores corporativos en Git."
