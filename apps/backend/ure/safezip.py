"""Extração segura de ZIP/APK/JAR.

Regras: rejeita traversal, caminhos absolutos, byte nulo, barra invertida e nomes duplicados
(sem diferença de caixa); ignora links simbólicos e entradas especiais; limita entradas,
bytes totais e razão de compressão (declarada e medida durante a escrita); grava com O_EXCL
e O_NOFOLLOW para nunca seguir um link já existente no destino.
"""
from __future__ import annotations

import os
import re
import stat
import zipfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

CHUNK = 1024 * 1024
BOMB_MIN_SIZE = 1024 * 1024
_DRIVE = re.compile(r"^[A-Za-z]:")


class UnsafeArchiveError(ValueError):
    """Entrada insegura (traversal, link, nome inválido, duplicata)."""


class ArchiveLimitError(ValueError):
    """Limite de entradas, tamanho ou razão de compressão excedido (possível ZIP bomb)."""


@dataclass
class ExtractionReport:
    files: int = 0
    directories: int = 0
    total_bytes: int = 0
    skipped: list[str] = field(default_factory=list)


def clean_entry_name(name: str) -> PurePosixPath:
    if not name or "\x00" in name or "\\" in name or name.startswith("/") or _DRIVE.match(name):
        raise UnsafeArchiveError(f"nome inseguro: {name!r}")
    parts = [p for p in PurePosixPath(name).parts if p != "."]
    if not parts or any(p == ".." for p in parts):
        raise UnsafeArchiveError(f"traversal ou nome vazio: {name!r}")
    return PurePosixPath(*parts)


def safe_extract_zip(
    archive: Path,
    dest: Path,
    *,
    max_entries: int,
    max_total_bytes: int,
    max_ratio: float,
) -> ExtractionReport:
    report = ExtractionReport()
    dest.mkdir(parents=True, exist_ok=True)
    base = dest.resolve()
    with zipfile.ZipFile(archive) as zf:
        infos = zf.infolist()
        if len(infos) > max_entries:
            raise ArchiveLimitError(f"{len(infos)} entradas excedem o limite de {max_entries}")
        if sum(i.file_size for i in infos) > max_total_bytes:
            raise ArchiveLimitError("tamanho total declarado excede o limite")
        seen: set[str] = set()
        for info in infos:
            name = clean_entry_name(info.filename)
            key = name.as_posix().casefold()
            if key in seen:
                raise UnsafeArchiveError(f"entrada duplicada: {info.filename!r}")
            seen.add(key)
            mode = (info.external_attr >> 16) & 0xFFFF
            if stat.S_ISLNK(mode):
                report.skipped.append(f"link simbólico ignorado: {info.filename}")
                continue
            target = base.joinpath(*name.parts)
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                report.directories += 1
                continue
            # Tipo Unix nos bits altos de external_attr. 0 = sem tipo informado (arquivo comum).
            file_type = stat.S_IFMT(mode)
            if file_type not in (0, stat.S_IFREG):
                report.skipped.append(f"entrada especial ignorada: {info.filename}")
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            if target.resolve().parent != base and base not in target.resolve().parents:
                raise UnsafeArchiveError("destino escapa da área de extração")
            report.total_bytes += _write_entry(zf, info, target, max_ratio, max_total_bytes - report.total_bytes)
            report.files += 1
    return report


def _write_entry(zf: zipfile.ZipFile, info: zipfile.ZipInfo, target: Path, max_ratio: float, budget: int) -> int:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    declared_ratio = info.file_size / max(info.compress_size, 1)
    if info.file_size > BOMB_MIN_SIZE and declared_ratio > max_ratio:
        raise ArchiveLimitError(f"razão de compressão declarada {declared_ratio:.0f}:1 excede {max_ratio:.0f}:1")
    written = 0
    fd = os.open(target, flags, 0o644)
    try:
        with zf.open(info) as src, os.fdopen(fd, "wb") as out:
            fd = -1
            while True:
                chunk = src.read(CHUNK)
                if not chunk:
                    break
                written += len(chunk)
                if written > budget:
                    raise ArchiveLimitError("bytes extraídos excedem o limite total")
                if written > BOMB_MIN_SIZE and written / max(info.compress_size, 1) > max_ratio:
                    raise ArchiveLimitError("razão de compressão medida excede o limite (ZIP bomb)")
                out.write(chunk)
    finally:
        if fd != -1:
            os.close(fd)
    return written
