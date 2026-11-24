# Imagem com o ambiente de engenharia reversa instalado na própria imagem (não em sessão temporária).
# O build falha se as ferramentas obrigatórias (java, apktool, lief) não ficarem prontas.
# JADX, Ghidra, apkanalyzer e ilspycmd só entram com fonte oficial e SHA-256 (build-args
# URE_JADX_URL/URE_JADX_SHA256 etc., ver scripts/install-tools.sh e docs/FERRAMENTAS.md).
#
# Construir:  docker build -t ure .
# Executar:   docker run -e URE_HOST=0.0.0.0 -e URE_TOKEN=... -p 8765:8765 -v ure-data:/data ure
#
# Estado: NÃO construída no ambiente de desenvolvimento desta versão (o daemon do Docker estava
# inativo e o Docker Hub não era alcançável). O script de instalação foi executado no host real.
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 URE_HOST=0.0.0.0 URE_PORT=8765 URE_DATA_DIR=/data \
    URE_TOOLS_HOME=/opt/ure-tools URE_TOOLS_ENV=/opt/ure-tools/tools.env URE_SKIP_DOTNET=1
WORKDIR /app
COPY scripts /app/scripts
COPY apps/backend /app/backend
COPY apps/web /app/web
RUN apt-get update -qq && apt-get install -y -qq --no-install-recommends curl unzip ca-certificates \
    && rm -rf /var/lib/apt/lists/*
RUN bash /app/scripts/install-tools.sh
WORKDIR /app/backend
VOLUME ["/data"]
EXPOSE 8765
CMD ["python3", "-m", "ure.server"]
