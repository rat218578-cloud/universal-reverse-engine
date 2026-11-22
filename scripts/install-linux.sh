#!/usr/bin/env bash
# Instala o Universal Reverse Engine num ambiente virtual do usuário, sem root e sem rede.
# Uso: scripts/install-linux.sh caminho/para/universal_reverse_engine-1.0.0-py3-none-any.whl
set -euo pipefail

WHEEL="${1:-}"
if [ -z "$WHEEL" ] || [ ! -f "$WHEEL" ]; then
  echo "Uso: $0 caminho/para/universal_reverse_engine-*.whl" >&2
  exit 2
fi
PY="${PYTHON:-python3}"
if ! "$PY" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 11) else 1)'; then
  echo "É necessário Python 3.11 ou superior (encontrado: $("$PY" -V 2>&1))." >&2
  exit 1
fi
BASE="${URE_HOME:-$HOME/.local/share/universal-reverse-engine}"
BIN_DIR="${BIN_DIR:-$HOME/.local/bin}"
mkdir -p "$BASE" "$BIN_DIR"
"$PY" -m venv "$BASE/venv"
"$BASE/venv/bin/pip" install --quiet --no-index --force-reinstall "$WHEEL"
ln -sf "$BASE/venv/bin/ure-server" "$BIN_DIR/ure-server"
echo "Instalado em $BASE"
echo "Comando: $BIN_DIR/ure-server (se não for encontrado, adicione $BIN_DIR ao PATH)"
echo "Versão: $("$BASE/venv/bin/python" -c 'import ure; print(ure.__version__)')"
