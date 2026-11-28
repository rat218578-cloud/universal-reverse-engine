"""Sessão do servidor remoto no aparelho.

O token NUNCA passa por HTTP: quem o entrega é o aplicativo Android (ure_android.set_remote),
que o lê do Android Keystore. Aqui ele fica somente em memória, do processo, e não entra em
respostas, jobs, relatórios nem mensagens de erro.

Rotas (registradas só no aparelho, por install_routes):
  GET  /api/v1/remote                                       estado: configurado ou não, endereço
  POST /api/v1/projects/{pid}/artifacts/{aid}/remote-send   envia o original ao servidor (202, job)
  GET  /api/v1/remote/jobs/{jid}                            andamento e resultado do envio

Os resultados ficam no próprio artefato local, em <artefato>/remote/. A análise local continua
funcionando mesmo que o servidor esteja fora do ar.
"""
from __future__ import annotations

import json
import logging
import re
import threading
import uuid
from pathlib import Path
from typing import Any

from . import app as ure_app
from .remote import RemoteConfig, RemoteError, send_apk

log = logging.getLogger("ure.remote")

_lock = threading.Lock()
_config: RemoteConfig | None = None
_jobs: dict[str, dict[str, Any]] = {}
_MAX_JOBS = 50
_FALLBACK_ERROR = "falha inesperada no envio; detalhes omitidos por segurança"


def configure(base_url: str, token: str) -> dict[str, Any]:
    """Guarda a configuração em memória. Valida endereço e tamanho do token."""
    global _config
    cfg = RemoteConfig(base_url, token)  # RemoteError se inválido; a mensagem não contém o token
    with _lock:
        _config = cfg
    return status()


def clear() -> dict[str, Any]:
    global _config
    with _lock:
        _config = None
    return status()


def status() -> dict[str, Any]:
    with _lock:
        cfg = _config
    return {"configured": cfg is not None, "server": cfg.base_url if cfg else None}


def _job_public(job: dict[str, Any]) -> dict[str, Any]:
    return {k: job[k] for k in ("id", "project_id", "artifact_id", "status", "progress", "message", "error")}


def _update(jid: str, **fields: Any) -> None:
    with _lock:
        if jid in _jobs:
            _jobs[jid].update(fields)


def start_send(app: Any, pid: str, aid: str, filename: str) -> dict[str, Any]:
    with _lock:
        cfg = _config
        if cfg is None:
            raise ure_app.ApiError(409, "servidor remoto não configurado no aparelho")
        jid = uuid.uuid4().hex
        job = {"id": jid, "project_id": pid, "artifact_id": aid, "status": "queued",
               "progress": 0.0, "message": "na fila", "error": None}
        _jobs[jid] = job
        while len(_jobs) > _MAX_JOBS:
            _jobs.pop(next(iter(_jobs)))
    thread = threading.Thread(target=_run_send, args=(app, cfg, pid, aid, filename, jid),
                              name=f"ure-remote-{jid[:8]}", daemon=True)
    thread.start()
    return _job_public(job)


def _run_send(app: Any, cfg: RemoteConfig, pid: str, aid: str, filename: str, jid: str) -> None:
    _update(jid, status="running", message="enviando ao servidor")
    try:
        root = app.root_of(pid, aid)
        apk = root / "original" / filename
        out_dir = root / "remote"
        # Resultados de um envio anterior não podem sobreviver a um envio que falhou.
        for stale in ("analysis.json", "export.zip"):
            (out_dir / stale).unlink(missing_ok=True)

        def on_progress(server_job: dict[str, Any]) -> None:
            _update(jid, message=f"servidor: {server_job.get('message') or server_job.get('status')}",
                    progress=float(server_job.get("progress") or 0.0))

        summary = send_apk(cfg, apk, out_dir, on_progress=on_progress, poll_s=1.0, timeout_s=900.0)
        server_job = summary["job"]
        if server_job["status"] != "done":
            reason = server_job.get("error") or server_job.get("message") or server_job["status"]
            _update(jid, status="failed", message="análise no servidor não concluiu",
                    error=f"servidor: {reason}")
            return
        extra = []
        if summary.get("report_error"):
            extra.append(summary["report_error"])
        if summary.get("export_error"):
            extra.append(summary["export_error"])
        _update(jid, status="done", progress=1.0, message="concluído",
                error="; ".join(extra) or None)
    except RemoteError as exc:
        _update(jid, status="failed", message="envio não concluído", error=exc.message)
    except Exception as exc:  # noqa: BLE001 - nunca propagar nem registrar detalhes que possam conter segredos
        log.error("falha no envio remoto: %s", exc.__class__.__name__)
        _update(jid, status="failed", message="envio não concluído", error=_FALLBACK_ERROR)


def job(jid: str) -> dict[str, Any] | None:
    with _lock:
        row = _jobs.get(jid)
        return _job_public(row) if row else None


# --- rotas -----------------------------------------------------------------------

def _status_route(a: Any, h: Any, m: Any, q: dict[str, str]) -> tuple[int, Any]:
    return 200, status()


def _send_route(a: Any, h: Any, m: Any, q: dict[str, str]) -> tuple[int, Any]:
    pid, aid = m.group(1), m.group(2)
    art = a.artifact_or_404(pid, aid)
    return 202, start_send(a, pid, aid, art["filename"])


def _job_route(a: Any, h: Any, m: Any, q: dict[str, str]) -> tuple[int, Any]:
    found = job(m.group(1))
    if found is None:
        raise ure_app.ApiError(404, "envio não encontrado")
    return 200, found


def _remote_dir(a: Any, pid: str, aid: str) -> Path:
    art = a.artifact_or_404(pid, aid)
    return a.root_of(art["project_id"], art["id"]) / "remote"


def _remote_report_route(a: Any, h: Any, m: Any, q: dict[str, str]) -> tuple[int, Any]:
    path = _remote_dir(a, m.group(1), m.group(2)) / "analysis.json"
    if not path.is_file():
        raise ure_app.ApiError(404, "relatório do servidor ainda não disponível")
    return 200, json.loads(path.read_text(encoding="utf-8"))


def _remote_export_route(a: Any, h: Any, m: Any, q: dict[str, str]) -> tuple[int, Any]:
    art = a.artifact_or_404(m.group(1), m.group(2))
    path = _remote_dir(a, m.group(1), m.group(2)) / "export.zip"
    if not path.is_file():
        raise ure_app.ApiError(404, "exportação do servidor ainda não disponível")
    return 200, ure_app.FileResponse(path, "application/zip", f"{Path(art['filename']).stem}-servidor.zip")


ROUTES = [
    ("GET", re.compile(rf"/api/v1/projects/{ure_app.ID}/artifacts/{ure_app.ID}/remote-report"), _remote_report_route),
    ("GET", re.compile(rf"/api/v1/projects/{ure_app.ID}/artifacts/{ure_app.ID}/remote-export"), _remote_export_route),
    ("GET", re.compile(r"/api/v1/remote"), _status_route),
    ("POST", re.compile(rf"/api/v1/projects/{ure_app.ID}/artifacts/{ure_app.ID}/remote-send"), _send_route),
    ("GET", re.compile(r"/api/v1/remote/jobs/" + ure_app.ID), _job_route),
]


def install_routes() -> None:
    """Registra as rotas do servidor remoto (idempotente). Chamado só no backend do aparelho."""
    existing = {id(fn) for _, _, fn in ure_app.ROUTES}
    for method, pattern, fn in ROUTES:
        if id(fn) not in existing:
            ure_app.ROUTES.append((method, pattern, fn))
