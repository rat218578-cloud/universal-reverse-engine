#!/usr/bin/env bash
# Diagnóstico do ambiente de engenharia reversa do URE: sistema, recursos, Docker e cada ferramenta
# testada de verdade (mesmo código do servidor). Não altera nada. Código de saída: 0 se as
# ferramentas obrigatórias (java, apktool, lief) estiverem prontas; 1 caso contrário.
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS_HOME="${URE_TOOLS_HOME:-/opt/ure-tools}"
if [ -d "$ROOT/apps/backend" ]; then BACKEND="$ROOT/apps/backend"; else BACKEND="$ROOT/backend"; fi
TOOLS_ENV="${URE_TOOLS_ENV:-$TOOLS_HOME/tools.env}"

section() { printf '\n== %s\n' "$1"; }

section "Sistema"
uname -srm
if [ -r /etc/os-release ]; then . /etc/os-release; echo "${PRETTY_NAME:-desconhecido}"; fi
echo "CPUs: $(nproc 2>/dev/null || echo ?)"
echo "Usuário: $(id -un) (uid $(id -u))"

section "Recursos"
free -m 2>/dev/null | awk 'NR==1 || /Mem:/ {print}' || true
df -h "$TOOLS_HOME" 2>/dev/null | tail -n1 || df -h / | tail -n1

section "Docker"
if command -v docker >/dev/null 2>&1; then
  if docker info >/dev/null 2>&1; then echo "daemon: ativo"; else echo "daemon: INATIVO (o Docker não é usado por esta instalação)"; fi
else
  echo "docker: não instalado (a instalação usa o host, não a imagem)"
fi

section "Ambiente de ferramentas"
echo "arquivo: $TOOLS_ENV $( [ -f "$TOOLS_ENV" ] && echo '(presente)' || echo '(AUSENTE: rode scripts/install-tools.sh)')"
[ -f "$TOOLS_HOME/manifest.json" ] && echo "manifesto: $TOOLS_HOME/manifest.json (gerado em $(grep -o '"generated_at": "[^"]*"' "$TOOLS_HOME/manifest.json" | cut -d'"' -f4))"

section "Ferramentas (teste de execução real)"
URE_TOOLS_ENV="$TOOLS_ENV" PYTHONPATH="$BACKEND" python3 -m ure.toolcheck
status=$?

section "Resultado"
if [ "$status" -eq 0 ]; then echo "Ambiente pronto para análise (obrigatórias OK)."; else echo "Ambiente INCOMPLETO: veja as linhas AUSENTE/FALHOU acima."; fi
exit "$status"
