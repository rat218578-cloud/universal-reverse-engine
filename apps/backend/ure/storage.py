"""Layout de armazenamento e resolução segura de caminhos dentro de um artefato."""
from __future__ import annotations

import os
import re
import uuid
from pathlib import Path

ID_RE = re.compile(r"^[0-9a-f]{32}$")
SUBDIRS = ("original", "extracted", "decompiled", "reports", "exports")
READ_ROOTS = ("original", "extracted", "decompiled", "reports")


class PathRejectedError(ValueError):
    """Caminho fora da área permitida, com traversal ou link simbólico."""


def new_id() -> str:
    return uuid.uuid4().hex


def valid_id(value: str | None) -> bool:
    return bool(value and ID_RE.fullmatch(value))


def artifact_root(data_dir: Path, project_id: str, artifact_id: str) -> Path:
    if not (valid_id(project_id) and valid_id(artifact_id)):
        raise PathRejectedError("identificador inválido")
    return data_dir / "projects" / project_id / "artifacts" / artifact_id


def ensure_layout(root: Path) -> None:
    for sub in SUBDIRS:
        (root / sub).mkdir(parents=True, exist_ok=True)


def safe_join(base: Path, rel: str) -> Path:
    """Resolve `rel` sob `base` recusando traversal, byte nulo, caminho absoluto e symlinks."""
    if "\x00" in rel or "\\" in rel or rel.startswith("/"):
        raise PathRejectedError("caminho inválido")
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise PathRejectedError("traversal bloqueado")
    cur = base
    for part in parts:
        cur = cur / part
        if cur.is_symlink():
            raise PathRejectedError("link simbólico bloqueado")
    if cur.exists() and base.resolve() not in cur.resolve().parents and cur.resolve() != base.resolve():
        raise PathRejectedError("caminho escapa da área")
    return cur


def make_readonly(path: Path) -> None:
    os.chmod(path, 0o444)
