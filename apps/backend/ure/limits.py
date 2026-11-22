"""Limites de tempo e cancelamento para etapas executadas no próprio processo.

O Guard é verificado em laços de extração, varredura e análise. Não limita CPU: não há
cota de CPU por thread no Python sem recursos do SO; o limite aplicado é o de tempo de parede.
"""
from __future__ import annotations

import threading
import time
from collections.abc import Callable


class Cancelled(RuntimeError):
    """Processamento cancelado pelo usuário."""


class TimeLimitExceeded(RuntimeError):
    """Tempo limite do processamento excedido."""


class Guard:
    def __init__(
        self,
        timeout_s: float,
        cancel: threading.Event | None = None,
        progress: Callable[[float, str], None] | None = None,
    ) -> None:
        self.deadline = time.monotonic() + timeout_s
        self.cancel = cancel
        self._progress = progress

    def check(self) -> None:
        if self.cancel is not None and self.cancel.is_set():
            raise Cancelled("processamento cancelado")
        if time.monotonic() > self.deadline:
            raise TimeLimitExceeded("tempo limite do processamento excedido")

    def remaining(self) -> float:
        return max(0.0, self.deadline - time.monotonic())

    def step(self, fraction: float, message: str) -> None:
        self.check()
        if self._progress is not None:
            self._progress(fraction, message)
