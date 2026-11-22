"""Configuração por variáveis de ambiente (prefixo URE_). Nenhum segredo fica no código."""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

MB = 1024 * 1024
LOOPBACK = frozenset({"127.0.0.1", "localhost", "::1"})


def load_env_file(path: Path) -> int:
    """Carrega linhas KEY=VALUE de um arquivo de configuração. Só aceita chaves URE_*.
    Variáveis já definidas no ambiente têm precedência. Retorna quantas foram carregadas."""
    if not path.is_file():
        return 0
    loaded = 0
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip(chr(34)).strip(chr(39))
        if key.startswith("URE_") and key not in os.environ:
            os.environ[key] = value
            loaded += 1
    return loaded


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
    socket_timeout_s: int = 30
    extra_hosts: tuple[str, ...] = ()
    job_timeout_s: int = 900
    ollama_model: str = "llama3.2"
    external_ai_url: str | None = None
    external_ai_model: str = "default"
    external_ai_key: str | None = field(default=None, repr=False)

    @classmethod
    def from_env(cls) -> Settings:
        load_env_file(Path(os.environ.get("URE_CONFIG", "ure.env")).expanduser())
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
            socket_timeout_s=num("URE_SOCKET_TIMEOUT_S", 30),
            extra_hosts=tuple(h.strip() for h in env.get("URE_ALLOWED_HOSTS", "").split(",") if h.strip()),
            job_timeout_s=num("URE_JOB_TIMEOUT_S", 900),
            ollama_model=env.get("URE_OLLAMA_MODEL", "llama3.2"),
            external_ai_url=env.get("URE_EXTERNAL_AI_URL") or None,
            external_ai_model=env.get("URE_EXTERNAL_AI_MODEL", "default"),
            external_ai_key=env.get("URE_EXTERNAL_AI_KEY") or None,
        )

    def check_bind(self) -> None:
        """Recusa expor a API fora do loopback sem token de acesso."""
        if self.host not in LOOPBACK and not self.token:
            raise RuntimeError("Bind fora de loopback exige URE_TOKEN definido.")


def load_or_create_token(data_dir: Path) -> str:
    """Token de sessão aleatório (32 bytes), gravado com permissão 0600. Reutilizado entre execuções."""
    path = data_dir / "session.token"
    if path.is_file():
        return path.read_text(encoding="utf-8").strip()
    data_dir.mkdir(parents=True, exist_ok=True)
    token = secrets.token_urlsafe(32)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(token)
    return token
