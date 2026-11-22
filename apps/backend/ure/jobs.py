"""Executor de jobs: progresso, cancelamento cooperativo, limite de tempo e erros sanitizados.

Erros de exceções não previstas nunca chegam ao cliente: a mensagem pública é genérica e o
traceback vai para o log do servidor. Apenas exceções em `safe_exceptions` têm mensagem exibida.
"""
from __future__ import annotations

import sys
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable

from .db import Store
from .limits import Cancelled, Guard, TimeLimitExceeded
from .storage import new_id

Handler = Callable[[str, str, dict[str, Any], Guard], dict[str, Any]]
RETRYABLE = ("failed", "interrupted", "cancelled")
TERMINAL = ("done", "failed", "interrupted", "cancelled")
GENERIC_ERROR = "falha interna no processamento; detalhes foram registrados no log do servidor"


class BusyError(RuntimeError):
    """Artefato em uso por outro processamento."""


class JobRunner:
    def __init__(self, store: Store, workers: int, timeout_s: float,
                 safe_exceptions: tuple[type[BaseException], ...] = ()) -> None:
        self.store = store
        self.timeout_s = timeout_s
        self.safe_exceptions = safe_exceptions + (Cancelled, TimeLimitExceeded, BusyError)
        self._pool = ThreadPoolExecutor(max_workers=workers, thread_name_prefix="ure-job")
        self._handlers: dict[str, Handler] = {}
        self._events: dict[str, threading.Event] = {}
        self._lock = threading.Lock()

    def register(self, kind: str, handler: Handler) -> None:
        self._handlers[kind] = handler

    def submit(self, kind: str, pid: str, aid: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        if kind not in self._handlers:
            raise KeyError(kind)
        jid = new_id()
        job = self.store.create_job({
            "id": jid, "project_id": pid, "artifact_id": aid, "kind": kind,
            "status": "queued", "progress": 0.0, "message": "na fila", "params": params or {},
        })
        event = threading.Event()
        with self._lock:
            self._events[jid] = event
        self._pool.submit(self._run, jid, kind, pid, aid, params or {}, event)
        return job

    def retry(self, jid: str) -> dict[str, Any]:
        old = self.store.get_job(jid)
        if old is None:
            raise KeyError(jid)
        if old["status"] not in RETRYABLE:
            raise ValueError(f"somente jobs {', '.join(RETRYABLE)} podem ser repetidos")
        return self.submit(old["kind"], old["project_id"], old["artifact_id"], old["params"])

    def cancel(self, jid: str) -> dict[str, Any]:
        job = self.store.get_job(jid)
        if job is None:
            raise KeyError(jid)
        if job["status"] in TERMINAL:
            raise ValueError("o job já terminou")
        with self._lock:
            event = self._events.get(jid)
            if event is None:
                raise ValueError("job não está ativo nesta execução")
            event.set()
        if job["status"] == "queued":
            self.store.update_job(jid, status="cancelled", message="cancelado antes de iniciar")
        return self.store.get_job(jid)  # type: ignore[return-value]

    def _run(self, jid: str, kind: str, pid: str, aid: str, params: dict[str, Any],
             event: threading.Event) -> None:
        try:
            if event.is_set():
                self.store.update_job(jid, status="cancelled", message="cancelado antes de iniciar")
                return
            self.store.update_job(jid, status="running", message="iniciando")

            def progress(fraction: float, message: str) -> None:
                self.store.update_job(jid, progress=max(0.0, min(1.0, fraction)), message=message[:300])

            guard = Guard(self.timeout_s, event, progress)
            try:
                result = self._handlers[kind](pid, aid, params, guard)
                self.store.update_job(jid, status="done", progress=1.0, message="concluído", result=result)
            except Cancelled:
                self.store.update_job(jid, status="cancelled", message="cancelado", error=None)
            except TimeLimitExceeded:
                self.store.update_job(jid, status="failed", message="tempo limite excedido",
                                      error="tempo limite do processamento excedido")
            except Exception as exc:  # fronteira do job: o worker nunca morre por erro de análise
                traceback.print_exc(file=sys.stderr)
                public = str(exc)[:500] if isinstance(exc, self.safe_exceptions) else GENERIC_ERROR
                self.store.update_job(jid, status="failed", message="falhou", error=public)
        finally:
            with self._lock:
                self._events.pop(jid, None)

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)
