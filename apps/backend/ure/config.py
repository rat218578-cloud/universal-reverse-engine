"""Configuração por variáveis de ambiente (prefixo URE_). Nenhum segredo fica no código."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

MB = 1024 * 1024
LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1"})


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    host: str = "127.0.0.1"
    port: int = 8765
    max_upload_bytes: int = 512 * MB
    max_extract_bytes: int = 2048 * MB
    max_entries: int = 100_000
    max_ratio: float = 200.0
    token: str | None = None
    tool_timeout_s: int = 900
    tool_memory_mb: int = 3072
    ai_enabled: bool = False
    ollama_url: str = "http://127.0.0.1:11434"
    ai_daily_budget: int = 50
    job_workers: int = 1

    @classmethod
    def from_env(cls) -> Settings:
        env = os.environ

        def num(key: str, default: int) -> int:
            raw = env.get(key)
            return int(raw) if raw else default

        return cls(
            data_dir=Path(env.get("URE_DATA_DIR") or "data").expanduser().resolve(),
            host=env.get("URE_HOST", "127.0.0.1"),
            port=num("URE_PORT", 8765),
            max_upload_bytes=num("URE_MAX_UPLOAD_MB", 512) * MB,
            max_extract_bytes=num("URE_MAX_EXTRACT_MB", 2048) * MB,
            token=env.get("URE_TOKEN") or None,
            tool_timeout_s=num("URE_TOOL_TIMEOUT_S", 900),
            tool_memory_mb=num("URE_TOOL_MEMORY_MB", 3072),
            ai_enabled=env.get("URE_AI_ENABLED", "0") == "1",
            ollama_url=env.get("URE_OLLAMA_URL", "http://127.0.0.1:11434"),
            ai_daily_budget=num("URE_AI_DAILY_BUDGET", 50),
            job_workers=num("URE_JOB_WORKERS", 1),
        )

    def check_bind(self) -> None:
        """Recusa expor a API fora do loopback sem token de acesso."""
        if self.host not in LOOPBACK and not self.token:
            raise RuntimeError("Bind fora de loopback exige URE_TOKEN definido.")
