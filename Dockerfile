# NÃO TESTADO: Docker não está disponível no ambiente de desenvolvimento desta versão.
# Construa com: docker build -t ure . ; execute com: docker run -e URE_HOST=0.0.0.0 -e URE_TOKEN=... -p 8765:8765 ure
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 URE_HOST=0.0.0.0 URE_PORT=8765 URE_DATA_DIR=/data
WORKDIR /app
COPY apps/backend /app/backend
COPY apps/web /app/web
WORKDIR /app/backend
VOLUME ["/data"]
EXPOSE 8765
CMD ["python3", "-m", "ure.server"]
