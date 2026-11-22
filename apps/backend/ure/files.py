"""Árvore de arquivos, prévia segura e exportação ZIP de artefatos."""
from __future__ import annotations

import hashlib
import json
import os
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .storage import PathRejectedError

MAX_TREE_ENTRIES = 20_000
TEXT_PREVIEW_BYTES = 512 * 1024
HEX_PREVIEW_BYTES = 4096
EXPORT_SUBDIRS = ("extracted", "decompiled", "reports")


def build_tree(directory: Path) -> dict[str, Any]:
    if not directory.exists():
        return {"entries": [], "truncated": False}
    if not directory.is_dir():
        raise PathRejectedError("o caminho não é um diretório")
    entries: list[dict[str, Any]] = []
    truncated = False
    with os.scandir(directory) as it:
        ordered = sorted(it, key=lambda e: (not e.is_dir(follow_symlinks=False), e.name.casefold()))
        for entry in ordered:
            if len(entries) >= MAX_TREE_ENTRIES:
                truncated = True
                break
            if entry.is_symlink():
                kind, size = "link", 0
            elif entry.is_dir(follow_symlinks=False):
                kind, size = "dir", 0
            else:
                kind, size = "file", entry.stat(follow_symlinks=False).st_size
            entries.append({"name": entry.name, "type": kind, "size": size})
    return {"entries": entries, "truncated": truncated}


def read_preview(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise PathRejectedError("não é um arquivo regular")
    size = path.stat().st_size
    with path.open("rb") as f:
        head = f.read(TEXT_PREVIEW_BYTES)
    if b"\x00" not in head[:8192]:
        try:
            text = head.decode("utf-8")
            return {"size": size, "mode": "text", "truncated": size > TEXT_PREVIEW_BYTES, "content": text}
        except UnicodeDecodeError:
            pass
    with path.open("rb") as f:
        raw = f.read(HEX_PREVIEW_BYTES)
    lines = [f"{off:08x}  {raw[off:off + 16].hex(' ')}" for off in range(0, len(raw), 16)]
    return {"size": size, "mode": "hex", "truncated": size > HEX_PREVIEW_BYTES, "content": "\n".join(lines)}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def export_project_zip(root: Path, dest: Path, include_original: bool) -> dict[str, Any]:
    """Gera ZIP com MANIFEST.json (SHA-256 por arquivo). Links simbólicos nunca são incluídos."""
    subdirs = list(EXPORT_SUBDIRS) + (["original"] if include_original else [])
    found: list[tuple[Path, str]] = []
    for sub in subdirs:
        base = root / sub
        if not base.is_dir():
            continue
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            dirnames[:] = [d for d in dirnames if not (Path(dirpath) / d).is_symlink()]
            for name in filenames:
                p = Path(dirpath) / name
                if p.is_symlink() or not p.is_file():
                    continue
                found.append((p, p.relative_to(root).as_posix()))
    manifest = {
        "generator": "universal-reverse-engine",
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "include_original": include_original,
        "files": [
            {"path": arc, "size": p.stat().st_size, "sha256": sha256_file(p)} for p, arc in found
        ],
    }
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(".part")
    with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6, allowZip64=True) as zf:
        zf.writestr("MANIFEST.json", json.dumps(manifest, indent=2, ensure_ascii=False))
        for p, arc in found:
            zf.write(p, arc)
    os.replace(tmp, dest)
    return {"files": len(found), "size": dest.stat().st_size}
