"""Executor de jobs persistidos: progresso no SQLite, falhas tratadas na fronteira, nova tentativa."""
from __future__ import annotations

import sys
import traceback
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from .db import Store
from .storage import new_id

Progress = Callable[[float, str], None]
Handler = Callable[[str, str, dict[str, Any], Progress], dict[str, Any]]
RETRYABLE = ("failed", "interrupted")


class JobRunner:
    def __init__(self, store: Store, workers: int) -> None:
        self.store = store
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="ure-job")
        self._handlers: dict[str, Handler] = {}

    def register(self, kind: str, handler: Handler) -> None:
        self._handlers[kind] = handler

    def submit(self, kind: str, pid: str, aid: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if kind not in self._handlers:
            raise KeyError(kind)
        jid = new_id()
        job = self.store.create_job(
            {
                "id": jid,
                "project_id": pid,
                "artifact_id": aid,
                "kind": kind,
                "status": "queued",
                "progress": 0.0,
                "message": "na fila",
                "params": params or {},
            }
        )
        self._pool.submit(self._run, jid, kind, pid, aid, params or {})
        return job

    def retry(self, jid: str) -> dict[str, Any]:
        old = self.store.get_job(jid)
        if old is None:
            raise KeyError(jid)
        if old["status"] not in RETRYABLE:
            raise ValueError(f"somente jobs {', '.join(RETRYABLE)} podem ser repetidos")
        return self.submit(old["kind"], old["project_id"], old["artifact_id"], old["params"])

    def _run(self, jid: str, kind: str, pid: str, aid: str, params: dict[str, Any]) -> None:
        self.store.update_job(jid, status="running", message="iniciando")

        def progress(fraction: float, message: str) -> None:
            self.store.update_job(jid, progress=max(0.0, min(1.0, fraction)), message=message[:300])

        try:
            result = self._handlers[kind](pid, aid, params, progress)
            self.store.update_job(jid, status="done", progress=1.0, message="concluído", result=result)
        except Exception as exc:  # fronteira do job: o worker nunca morre por erro de análise
            traceback.print_exc(file=sys.stderr)
            self.store.update_job(
                jid,
                status="failed",
                message="falhou",
                error=f"{type(exc).__name__}: {str(exc)[:500]}",
            )

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)
