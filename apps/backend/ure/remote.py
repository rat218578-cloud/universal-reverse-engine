"""Cliente do aparelho para um servidor do URE.

Usa somente a biblioteca padrão e não importa nenhum outro módulo do ``ure``: pode rodar
dentro do backend Chaquopy do aparelho sem dependências extras. As ferramentas de análise
continuam no servidor; este módulo apenas envia o APK, acompanha o job e baixa os resultados.

Fluxo (todas as rotas já existem no servidor):
  1. POST /api/v1/projects                                   cria o projeto
  2. POST /api/v1/projects/{pid}/artifacts                    envia o arquivo (corpo bruto)
  3. POST /api/v1/projects/{pid}/artifacts/{aid}/analyze      inicia a análise (job)
  4. GET  /api/v1/jobs/{jid}                                  acompanha até estado final
  5. GET  /api/v1/projects/{pid}/artifacts/{aid}/report       relatório JSON
  6. GET  /api/v1/projects/{pid}/artifacts/{aid}/export       ZIP com os resultados
"""
from __future__ import annotations

import hashlib
import http.client
import json
import ssl
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

TERMINAL_STATES = ("done", "failed", "interrupted", "cancelled")
LOOPBACK_HOSTS = ("127.0.0.1", "localhost", "::1")
CHUNK = 64 * 1024


class RemoteError(Exception):
    """Falha de comunicação ou resposta de erro do servidor (mensagem em português, sem o token)."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.status = status


def validate_base_url(url: str) -> str:
    """Aceita https em qualquer host, e http somente para o próprio aparelho (loopback).

    Token em texto puro sobre rede local seria exposto; por isso http fora do loopback é recusado.
    """
    raw = (url or "").strip().rstrip("/")
    parts = urllib.parse.urlsplit(raw)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise RemoteError("endereço do servidor inválido: use http://… ou https://…")
    if parts.username or parts.password:
        raise RemoteError("não coloque usuário e senha no endereço do servidor")
    if parts.scheme == "http" and parts.hostname not in LOOPBACK_HOSTS:
        raise RemoteError("conexão sem TLS só é aceita para 127.0.0.1; use https para outros servidores")
    return raw


@dataclass(frozen=True)
class RemoteConfig:
    base_url: str
    token: str = field(repr=False)

    def __post_init__(self) -> None:
        if len((self.token or "").strip()) < 32:
            raise RemoteError("token do servidor deve ter pelo menos 32 caracteres")
        object.__setattr__(self, "base_url", validate_base_url(self.base_url))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for block in iter(lambda: fh.read(CHUNK), b""):
            digest.update(block)
    return digest.hexdigest()


class RemoteClient:
    def __init__(self, config: RemoteConfig, timeout_s: float = 30.0,
                 ssl_context: ssl.SSLContext | None = None) -> None:
        self.config = config
        self.timeout_s = timeout_s
        if ssl_context is not None and (
            ssl_context.verify_mode != ssl.CERT_REQUIRED or not ssl_context.check_hostname
        ):
            raise RemoteError("validação de certificado TLS não pode ser desligada")
        self._ssl = ssl_context
        parts = urllib.parse.urlsplit(config.base_url)
        self._https = parts.scheme == "https"
        self._host = parts.hostname or ""
        self._port = parts.port or (443 if self._https else 80)
        self._prefix = parts.path.rstrip("/")

    def _connection(self) -> http.client.HTTPConnection:
        if self._https:
            return http.client.HTTPSConnection(self._host, self._port, timeout=self.timeout_s,
                                               context=self._ssl or ssl.create_default_context())
        return http.client.HTTPConnection(self._host, self._port, timeout=self.timeout_s)

    def _request(self, method: str, path: str, *, json_body: Any = None, body_file: Path | None = None,
                 headers: dict[str, str] | None = None, dest: Path | None = None) -> Any:
        hdrs = {"Authorization": f"Bearer {self.config.token}", "Accept": "application/json"}
        hdrs.update(headers or {})
        body: Any = None
        conn = self._connection()
        try:
            if json_body is not None:
                body = json.dumps(json_body).encode("utf-8")
                hdrs["Content-Type"] = "application/json"
                hdrs["Content-Length"] = str(len(body))
            elif body_file is not None:
                hdrs["Content-Type"] = "application/octet-stream"
                hdrs["Content-Length"] = str(body_file.stat().st_size)
                body = body_file.open("rb")
            conn.request(method, self._prefix + path, body=body, headers=hdrs)
            resp = conn.getresponse()
            status = resp.status
            if status >= 400:
                raw = resp.read(64 * 1024)
                raise RemoteError(_server_message(raw, status), status)
            if dest is not None:
                dest.parent.mkdir(parents=True, exist_ok=True)
                with dest.open("wb") as out:
                    for block in iter(lambda: resp.read(CHUNK), b""):
                        out.write(block)
                return dest
            raw = resp.read()
            return json.loads(raw.decode("utf-8")) if raw else None
        except RemoteError:
            raise
        except (OSError, http.client.HTTPException, ssl.SSLError) as exc:
            raise RemoteError(f"não foi possível falar com o servidor: {exc.__class__.__name__}") from exc
        except json.JSONDecodeError as exc:
            raise RemoteError("o servidor respondeu algo que não é JSON") from exc
        finally:
            if body is not None and hasattr(body, "close"):
                body.close()
            conn.close()

    # --- operações -------------------------------------------------------------

    def health(self) -> dict:
        return self._request("GET", "/api/v1/health")

    def create_project(self, name: str) -> dict:
        return self._request("POST", "/api/v1/projects", json_body={"name": name})

    def upload(self, project_id: str, apk: Path) -> dict:
        """Envia o arquivo e confere o SHA-256 devolvido pelo servidor com o calculado aqui."""
        local_hash = sha256_file(apk)
        filename = urllib.parse.quote(apk.name, safe="")
        row = self._request("POST", f"/api/v1/projects/{project_id}/artifacts", body_file=apk,
                            headers={"X-Filename": filename})
        if row.get("sha256") != local_hash:
            raise RemoteError("o servidor recebeu um arquivo diferente do enviado (SHA-256 não confere)")
        return row

    def start_analysis(self, project_id: str, artifact_id: str, params: dict | None = None) -> dict:
        return self._request("POST", f"/api/v1/projects/{project_id}/artifacts/{artifact_id}/analyze",
                             json_body=params or {})

    def job(self, job_id: str) -> dict:
        return self._request("GET", f"/api/v1/jobs/{job_id}")

    def wait_job(self, job_id: str, on_progress: Callable[[dict], None] | None = None,
                 poll_s: float = 1.0, timeout_s: float = 900.0) -> dict:
        deadline = time.monotonic() + timeout_s
        last: tuple | None = None
        while True:
            job = self.job(job_id)
            key = (job.get("status"), job.get("progress"), job.get("message"))
            if on_progress and key != last:
                on_progress(job)
                last = key
            if job.get("status") in TERMINAL_STATES:
                return job
            if time.monotonic() >= deadline:
                raise RemoteError("tempo de espera da análise esgotado no aparelho; o job continua no servidor")
            time.sleep(poll_s)

    def report(self, project_id: str, artifact_id: str) -> dict:
        return self._request("GET", f"/api/v1/projects/{project_id}/artifacts/{artifact_id}/report")

    def download_export(self, project_id: str, artifact_id: str, dest: Path) -> Path:
        return self._request("GET", f"/api/v1/projects/{project_id}/artifacts/{artifact_id}/export", dest=dest)


def _server_message(raw: bytes, status: int) -> str:
    try:
        data = json.loads(raw.decode("utf-8"))
        if isinstance(data, dict) and data.get("error"):
            return f"servidor recusou a operação ({status}): {data['error']}"
    except (ValueError, UnicodeDecodeError):
        pass
    return f"servidor recusou a operação ({status})"


def send_apk(config: RemoteConfig, apk: Path, out_dir: Path, *, project_name: str | None = None,
             on_progress: Callable[[dict], None] | None = None, poll_s: float = 1.0,
             timeout_s: float = 900.0, client: RemoteClient | None = None) -> dict:
    """Fluxo completo. Devolve um resumo com caminhos locais dos resultados.

    Se o job falhar, o relatório e o ZIP ainda são baixados quando existirem, e o estado
    final do job é devolvido em ``job`` para que a tela mostre o motivo real.
    """
    if not apk.is_file():
        raise RemoteError("arquivo não encontrado no aparelho")
    cli = client or RemoteClient(config)
    cli.health()
    project = cli.create_project(project_name or f"Aparelho: {apk.name}"[:120])
    pid = project["id"]
    artifact = cli.upload(pid, apk)
    aid = artifact["id"]
    job = cli.start_analysis(pid, aid)
    final = cli.wait_job(job["id"], on_progress=on_progress, poll_s=poll_s, timeout_s=timeout_s)
    out_dir.mkdir(parents=True, exist_ok=True)
    summary: dict[str, Any] = {
        "project_id": pid, "artifact_id": aid, "sha256": artifact["sha256"],
        "job": {"id": final.get("id"), "status": final.get("status"), "message": final.get("message"),
                "error": final.get("error")},
        "report_path": None, "export_path": None, "report": None,
    }
    try:
        report = cli.report(pid, aid)
    except RemoteError as exc:
        summary["report_error"] = exc.message
    else:
        path = out_dir / "analysis.json"
        path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        summary["report"] = report
        summary["report_path"] = str(path)
    try:
        summary["export_path"] = str(cli.download_export(pid, aid, out_dir / "export.zip"))
    except RemoteError as exc:
        summary["export_error"] = exc.message
    return summary
