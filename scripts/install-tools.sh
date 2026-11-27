#!/usr/bin/env bash
# Instala e configura as ferramentas de engenharia reversa do URE neste servidor (Ubuntu/Debian).
#
# O que faz, de forma idempotente:
#   1. Pacotes do sistema via apt: Java 17 (requisito), Apktool, aapt (usado pelo Apktool) e,
#      se não for URE_SKIP_DOTNET=1, o SDK .NET 8 (requisito do ilspycmd).
#   2. LIEF 1.0.0 num ambiente virtual próprio ($URE_TOOLS_HOME/venv).
#   3. JADX, Ghidra, apkanalyzer e ilspycmd: só são instalados se a fonte oficial for informada com
#      URL e SHA-256 (ver abaixo). Sem isso, o script registra o bloqueio; nada é suposto instalado.
#   4. Grava $URE_TOOLS_HOME/tools.env (lido pelo servidor na inicialização) com os caminhos reais.
#   5. Roda o diagnóstico (python3 -m ure.toolcheck) e grava $URE_TOOLS_HOME/manifest.json.
#
# Fontes externas (opcionais), cada uma com URL e SHA-256 obrigatórios:
#   URE_JADX_URL, URE_JADX_SHA256            zip oficial do JADX (release do GitHub)
#   URE_GHIDRA_URL, URE_GHIDRA_SHA256        zip oficial do Ghidra (release do GitHub)
#   URE_APKANALYZER_URL, URE_APKANALYZER_SHA256   zip do Android Command-line Tools (dl.google.com)
#   URE_ILSPYCMD_NUPKG_URL, URE_ILSPYCMD_NUPKG_SHA256, URE_ILSPYCMD_VERSION   pacote .nupkg do ilspycmd
#
# Uso (como root):  sudo scripts/install-tools.sh
# Variáveis: URE_TOOLS_HOME (padrão /opt/ure-tools), URE_SKIP_DOTNET=1, URE_SKIP_APT=1, URE_LIEF_VERSION.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TOOLS_HOME="${URE_TOOLS_HOME:-/opt/ure-tools}"
LIEF_VERSION="${URE_LIEF_VERSION:-1.0.0}"
ANDROGUARD_VERSION="${URE_ANDROGUARD_VERSION:-4.1.4}"
TOOLS_ENV="$TOOLS_HOME/tools.env"
MANIFEST="$TOOLS_HOME/manifest.json"

if [ "$(id -u)" -ne 0 ]; then
  echo "Execute como root (sudo): a instalação grava em $TOOLS_HOME e usa apt." >&2
  exit 1
fi
if ! command -v apt-get >/dev/null 2>&1; then
  echo "apt-get não encontrado. Este script é para Ubuntu/Debian; instale as ferramentas manualmente" >&2
  echo "e informe os caminhos em $TOOLS_ENV (ver docs/FERRAMENTAS.md)." >&2
  exit 1
fi
if [ -d "$ROOT/apps/backend" ]; then BACKEND="$ROOT/apps/backend"; else BACKEND="$ROOT/backend"; fi
mkdir -p "$TOOLS_HOME" "$TOOLS_HOME/bin"

log() { printf '[install-tools] %s\n' "$*"; }

# ---- 1. pacotes do sistema -------------------------------------------------------------------
if [ "${URE_SKIP_APT:-0}" != "1" ]; then
  log "apt: Java 17, Apktool e aapt"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq openjdk-17-jre-headless apktool android-sdk radare2 apksigner mono-utils
  if [ "${URE_SKIP_DOTNET:-0}" != "1" ]; then
    log "apt: SDK .NET 8"
    apt-get install -y -qq dotnet-sdk-8.0
  fi
fi

# Java 17 é o runtime verificado do Apktool 2.7.0. Outras JVMs instaladas como dependência
# (ex.: OpenJDK 25 no Ubuntu 26.04) passam a não ser o padrão.
JAVA17_HOME=/usr/lib/jvm/java-17-openjdk-amd64
if [ -x "$JAVA17_HOME/bin/java" ]; then
  for tool in java javac; do
    [ -x "$JAVA17_HOME/bin/$tool" ] && update-alternatives --set "$tool" "$JAVA17_HOME/bin/$tool" >/dev/null 2>&1 || true
  done
  export JAVA_HOME="$JAVA17_HOME"
  log "java padrão: $JAVA17_HOME/bin/java"
fi

# ---- 2. LIEF em ambiente próprio -------------------------------------------------------------
VENV="$TOOLS_HOME/venv"
if [ ! -x "$VENV/bin/python" ]; then
  log "criando ambiente virtual do LIEF em $VENV"
  python3 -m venv "$VENV"
fi
log "LIEF $LIEF_VERSION"
log "Androguard $ANDROGUARD_VERSION"
"$VENV/bin/pip" install -q --disable-pip-version-check "lief==$LIEF_VERSION" "androguard==$ANDROGUARD_VERSION"

# ---- 3. fontes externas com verificação de SHA-256 ------------------------------------------
fetch_verified() { # url sha256 destino
  local url="$1" sha="$2" dest="$3"
  curl -fsSL --retry 3 -o "$dest.part" "$url"
  if ! echo "$sha  $dest.part" | sha256sum -c --status -; then
    rm -f "$dest.part"
    echo "SHA-256 não confere para $url. Arquivo descartado." >&2
    return 1
  fi
  mv "$dest.part" "$dest"
}

declare -A EXTRA=()
install_zip_tool() { # chave url_var sha_var binario_relativo
  local key="$1" url="${!2:-}" sha="${!3:-}" rel="$4"
  if [ -z "$url" ] || [ -z "$sha" ]; then
    log "$key: não instalado. Defina $2 e $3 (fonte oficial) para instalar."
    return 0
  fi
  local dir="$TOOLS_HOME/$key" tmp
  tmp="$(mktemp -d)"
  fetch_verified "$url" "$sha" "$tmp/pkg.zip"
  rm -rf "$dir" && mkdir -p "$dir"
  unzip -q "$tmp/pkg.zip" -d "$dir"
  rm -rf "$tmp"
  local bin
  bin="$(find "$dir" -path "*$rel" -type f 2>/dev/null | head -n1 || true)"
  if [ -z "$bin" ]; then
    log "$key: binário '$rel' não encontrado no pacote."
    return 0
  fi
  chmod +x "$bin"
  EXTRA["$key"]="$bin"
  log "$key instalado em $bin"
}

install_zip_tool jadx URE_JADX_URL URE_JADX_SHA256 "bin/jadx"
install_zip_tool ghidra URE_GHIDRA_URL URE_GHIDRA_SHA256 "support/analyzeHeadless"
install_zip_tool apkanalyzer URE_APKANALYZER_URL URE_APKANALYZER_SHA256 "cmdline-tools/bin/apkanalyzer"

if [ -n "${URE_ILSPYCMD_NUPKG_URL:-}" ] && [ -n "${URE_ILSPYCMD_NUPKG_SHA256:-}" ] && [ -n "${URE_ILSPYCMD_VERSION:-}" ]; then
  if command -v dotnet >/dev/null 2>&1; then
    tmp="$(mktemp -d)"
    fetch_verified "$URE_ILSPYCMD_NUPKG_URL" "$URE_ILSPYCMD_NUPKG_SHA256" "$tmp/ilspycmd.$URE_ILSPYCMD_VERSION.nupkg"
    dotnet tool install --tool-path "$TOOLS_HOME/ilspy" --add-source "$tmp" ilspycmd --version "$URE_ILSPYCMD_VERSION"
    rm -rf "$tmp"
    EXTRA[ilspycmd]="$TOOLS_HOME/ilspy/ilspycmd"
    log "ilspycmd instalado em ${EXTRA[ilspycmd]}"
  else
    log "ilspycmd: .NET ausente; instale o SDK .NET 8 primeiro."
  fi
else
  log "ilspycmd: não instalado. Defina URE_ILSPYCMD_NUPKG_URL, URE_ILSPYCMD_NUPKG_SHA256 e URE_ILSPYCMD_VERSION."
fi

# ---- 4. arquivo de ambiente lido pelo servidor ------------------------------------------------
{
  echo "# Gerado por scripts/install-tools.sh em $(date -u +%Y-%m-%dT%H:%M:%SZ). Não editar à mão."
  echo "URE_LIEF_PYTHON=$VENV/bin/python"
  java_bin="$(command -v java || true)"
  [ -x "$JAVA17_HOME/bin/java" ] && java_bin="$JAVA17_HOME/bin/java"
  for pair in "URE_JAVA:$java_bin" "URE_DOTNET:$(command -v dotnet || true)" \
              "URE_APKTOOL:$(command -v apktool || true)" "URE_RADARE2:$(command -v r2 || true)" \
              "URE_APKSIGNER:$(command -v apksigner || true)" "URE_MONODIS:$(command -v monodis || true)"; do
    value="${pair#*:}"; [ -n "$value" ] && echo "${pair%%:*}=$value"
  done
  for key in jadx ghidra apkanalyzer ilspycmd; do
    [ -n "${EXTRA[$key]:-}" ] && echo "URE_$(echo "$key" | tr '[:lower:]' '[:upper:]')=${EXTRA[$key]}"
  done
} > "$TOOLS_ENV"
chmod 0644 "$TOOLS_ENV"
log "ambiente gravado em $TOOLS_ENV"

# ---- 5. diagnóstico com o mesmo código do servidor --------------------------------------------
log "diagnóstico"
set +e
URE_TOOLS_ENV="$TOOLS_ENV" PYTHONPATH="$BACKEND" python3 -m ure.toolcheck --manifest "$MANIFEST"
status=$?
set -e
log "manifesto gravado em $MANIFEST"
exit "$status"
