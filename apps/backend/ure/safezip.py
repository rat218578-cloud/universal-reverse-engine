"""Extração segura de ZIP/APK/JAR com MEDIÇÃO REAL de bytes.

A razão de compressão não usa os tamanhos declarados no cabeçalho do ZIP, porque eles são
controlados pelo arquivo. O URE lê os dados comprimidos diretamente do arquivo, descompacta com
zlib e mede bytes reais: comprimidos lidos e descompactados produzidos. Limites aplicados:
número de entradas, bytes totais medidos, razão por entrada (a partir de 1 MiB de saída),
razão agregada do arquivo (a partir de 8 MiB de saída), profundidade de caminho, CRC e tempo/
cancelamento via Guard. Entradas criptografadas e métodos diferentes de STORED/DEFLATE são recusados.
Em qualquer falha o diretório de destino é removido.
"""
from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import struct
import zipfile
import zlib
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from .limits import Guard

CHUNK = 256 * 1024
OUT_CHUNK = 256 * 1024
ENTRY_MIN_OUTPUT = 1024 * 1024
AGG_MIN_OUTPUT = 8 * 1024 * 1024
MAX_DEPTH = 32
MAX_ITERATIONS = 10_000_000
MAX_NAME_LEN = 255
_DRIVE = re.compile(r"^[A-Za-z]:")


class UnsafeArchiveError(ValueError):
    """Entrada insegura: traversal, nome inválido, duplicata, criptografia, método não suportado, corrupção."""


class ArchiveLimitError(ValueError):
    """Limite de entradas, bytes, razão de compressão, profundidade ou tempo excedido."""


@dataclass
class ExtractionReport:
    files: int = 0
    directories: int = 0
    total_bytes: int = 0
    compressed_bytes: int = 0
    skipped: list[str] = field(default_factory=list)
    # Nomes repetidos no diretório central. "identica": o conteúdo é igual (SHA-256) e só um
    # arquivo foi mantido. "conflitante": o conteúdo difere; nenhuma versão foi escolhida e todas
    # ficaram em quarentena, fora da árvore extraída.
    duplicates: list[dict] = field(default_factory=list)


@dataclass
class _Totals:
    out: int = 0
    comp: int = 0


def clean_entry_name(name: str) -> PurePosixPath:
    if not name or "\x00" in name or "\\" in name or name.startswith("/") or _DRIVE.match(name):
        raise UnsafeArchiveError(f"nome inseguro: {name!r}")
    if len(name) > 1024:
        raise UnsafeArchiveError("nome excessivamente longo")
    parts = [p for p in PurePosixPath(name).parts if p != "."]
    if not parts or any(p == ".." for p in parts):
        raise UnsafeArchiveError(f"traversal ou nome vazio: {name!r}")
    if len(parts) > MAX_DEPTH:
        raise ArchiveLimitError(f"profundidade {len(parts)} excede o limite de {MAX_DEPTH}")
    if any(len(p) > MAX_NAME_LEN for p in parts):
        raise UnsafeArchiveError("componente de nome longo demais")
    return PurePosixPath(*parts)


@dataclass(frozen=True)
class _Planned:
    index: int
    info: zipfile.ZipInfo
    name: PurePosixPath
    kind: str  # "dir", "file" ou "skip"
    key: str


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _ensure_inside(base: Path, target: Path) -> None:
    parent = target.parent.resolve()
    if parent != base and base not in parent.parents:
        raise UnsafeArchiveError("destino escapa da área de extração")


def _check_encryption(info: zipfile.ZipInfo) -> None:
    if info.flag_bits & 0x1:
        raise UnsafeArchiveError(f"entrada criptografada não suportada: {info.filename!r}")


def _plan(infos: list[zipfile.ZipInfo], report: ExtractionReport, guard: Guard | None) -> list[_Planned]:
    """Valida todos os nomes antes de gravar qualquer coisa. Nome inseguro aborta a extração."""
    planned: list[_Planned] = []
    for index, info in enumerate(infos):
        if guard is not None:
            guard.check()
        name = clean_entry_name(info.filename)
        mode = (info.external_attr >> 16) & 0xFFFF
        if stat.S_ISLNK(mode):
            report.skipped.append(f"link simbólico ignorado: {info.filename}")
            kind = "skip"
        elif info.is_dir():
            kind = "dir"
        elif stat.S_IFMT(mode) not in (0, stat.S_IFREG):
            report.skipped.append(f"entrada especial ignorada: {info.filename}")
            kind = "skip"
        else:
            kind = "file"
        planned.append(_Planned(index, info, name, kind, name.as_posix().casefold()))
    return planned


def _write_single(archive: Path, base: Path, p: _Planned, report: ExtractionReport,
                  max_ratio: float, max_total: int, totals: _Totals, guard: Guard | None) -> None:
    target = base.joinpath(*p.name.parts)
    target.parent.mkdir(parents=True, exist_ok=True)
    _ensure_inside(base, target)
    _check_encryption(p.info)
    _extract_entry(archive, p.info, target, max_ratio, max_total, totals, guard)
    report.files += 1


def _resolve_group(archive: Path, base: Path, q_root: Path, gi: int, members: list[_Planned],
                   report: ExtractionReport, max_ratio: float, max_total: int,
                   totals: _Totals, guard: Guard | None) -> None:
    """Trata entradas de mesmo nome (ou de nome que só diferem em caixa) sem escolher conteúdo."""
    stage = q_root / ".staging" / f"{gi:04d}"
    staged: list[tuple[_Planned, Path, str]] = []
    try:
        for mi, p in enumerate(members):
            _check_encryption(p.info)
            tmp = stage / str(mi)
            tmp.parent.mkdir(parents=True, exist_ok=True)
            _extract_entry(archive, p.info, tmp, max_ratio, max_total, totals, guard)
            staged.append((p, tmp, _sha256(tmp)))
        indexes = [p.index for p in members]
        name = members[0].name.as_posix()
        digests = [d for _, _, d in staged]
        if len(set(digests)) == 1:
            first, tmp, digest = staged[0]
            target = base.joinpath(*first.name.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            _ensure_inside(base, target)
            shutil.move(str(tmp), str(target))
            report.files += 1
            report.duplicates.append({
                "name": name, "status": "identica", "occurrences": len(members), "indexes": indexes,
                "sha256": digest, "kept": first.name.as_posix(), "quarantined": [],
            })
        else:
            conflict_dir = q_root / "conflitantes" / f"{gi:04d}"
            conflict_dir.mkdir(parents=True, exist_ok=True)
            quarantined: list[str] = []
            for mi, (p, tmp, _digest) in enumerate(staged):
                dst = conflict_dir / f"{mi}-entrada{p.index}-{p.name.name}"
                shutil.move(str(tmp), str(dst))
                quarantined.append(dst.relative_to(q_root).as_posix())
            report.duplicates.append({
                "name": name, "status": "conflitante", "occurrences": len(members), "indexes": indexes,
                "sha256": digests, "kept": None, "quarantined": quarantined,
            })
    finally:
        shutil.rmtree(stage, ignore_errors=True)


def safe_extract_zip(
    archive: Path,
    dest: Path,
    *,
    max_entries: int,
    max_total_bytes: int,
    max_ratio: float,
    guard: Guard | None = None,
    quarantine: Path | None = None,
) -> ExtractionReport:
    """Extrai em `dest` (que deve não existir ou estar vazio).

    Nomes repetidos são comparados por SHA-256: conteúdo igual mantém um arquivo e registra a
    duplicata; conteúdo diferente não escolhe versão e vai para `quarantine` (padrão:
    `dest.parent/quarantine`), registrado no relatório. O arquivo original nunca é alterado.
    Em falha de segurança ou corrupção, `dest` é removido inteiro e a exceção é relançada.
    """
    report = ExtractionReport()
    q_root = quarantine if quarantine is not None else dest.parent / "quarantine"
    try:
        dest.mkdir(parents=True, exist_ok=True)
        base = dest.resolve()
        totals = _Totals()
        with zipfile.ZipFile(archive) as zf:
            infos = zf.infolist()
            if len(infos) > max_entries:
                raise ArchiveLimitError(f"{len(infos)} entradas excedem o limite de {max_entries}")
            plan = _plan(infos, report, guard)
            counts: dict[str, int] = {}
            for p in plan:
                if p.kind == "file":
                    counts[p.key] = counts.get(p.key, 0) + 1
            groups: dict[str, list[_Planned]] = {}
            for p in plan:
                if guard is not None:
                    guard.check()
                if p.kind == "dir":
                    base.joinpath(*p.name.parts).mkdir(parents=True, exist_ok=True)
                    report.directories += 1
                elif p.kind == "file" and counts[p.key] > 1:
                    groups.setdefault(p.key, []).append(p)
                elif p.kind == "file":
                    _write_single(archive, base, p, report, max_ratio, max_total_bytes, totals, guard)
            for gi, members in enumerate(groups.values()):
                _resolve_group(archive, base, q_root, gi, members, report,
                               max_ratio, max_total_bytes, totals, guard)
        report.total_bytes = totals.out
        report.compressed_bytes = totals.comp
    except BaseException:
        shutil.rmtree(dest, ignore_errors=True)
        raise
    return report


def inventory_zip(archive: Path, *, max_entries: int) -> dict:
    """Inventário do diretório central, sem extrair nem gravar nada.

    Serve de análise segura mesmo quando a extração falha: lista nomes, tamanhos, duplicatas
    (por CRC e tamanho declarados) e entradas com nome inseguro.
    """
    with zipfile.ZipFile(archive) as zf:
        infos = zf.infolist()
        if len(infos) > max_entries:
            raise ArchiveLimitError(f"{len(infos)} entradas excedem o limite de {max_entries}")
        by_name: dict[str, list[tuple[int, zipfile.ZipInfo]]] = {}
        unsafe: list[dict] = []
        for index, info in enumerate(infos):
            try:
                name = clean_entry_name(info.filename).as_posix()
            except UnsafeArchiveError as exc:
                unsafe.append({"index": index, "name": info.filename, "reason": str(exc)})
                continue
            by_name.setdefault(name, []).append((index, info))
    duplicates = []
    for name, items in by_name.items():
        if len(items) > 1:
            same = len({(i.CRC, i.file_size) for _, i in items}) == 1
            duplicates.append({
                "name": name, "occurrences": len(items), "indexes": [idx for idx, _ in items],
                "crc_and_size": "iguais" if same else "diferentes",
            })
    return {
        "entries": len(infos),
        "unique_names": len(by_name),
        "names": sorted(by_name),
        "declared_bytes": sum(i.file_size for i in infos),
        "duplicates": duplicates,
        "unsafe_entries": unsafe,
    }


def _check_ratio(entry_out: int, entry_comp: int, totals: _Totals, max_ratio: float, max_total: int) -> None:
    if totals.out > max_total:
        raise ArchiveLimitError("bytes extraídos excedem o limite total")
    if entry_out > ENTRY_MIN_OUTPUT and entry_out > max_ratio * max(entry_comp, 1):
        raise ArchiveLimitError(f"razão de compressão da entrada excede {max_ratio:.0f}:1 (medida)")
    if totals.out > AGG_MIN_OUTPUT and totals.out > max_ratio * max(totals.comp, 1):
        raise ArchiveLimitError(f"razão de compressão agregada excede {max_ratio:.0f}:1 (medida)")


def _extract_entry(
    archive: Path,
    info: zipfile.ZipInfo,
    target: Path,
    max_ratio: float,
    max_total: int,
    totals: _Totals,
    guard: Guard | None,
) -> None:
    if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
        raise UnsafeArchiveError(f"método de compressão {info.compress_type} não suportado")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    crc = 0
    entry_out = 0
    entry_comp = 0
    with archive.open("rb") as f:
        f.seek(info.header_offset)
        hdr = f.read(30)
        if len(hdr) < 30 or hdr[:4] != b"PK\x03\x04":
            raise UnsafeArchiveError("cabeçalho local inválido")
        name_len, extra_len = struct.unpack("<HH", hdr[26:30])
        f.seek(info.header_offset + 30 + name_len + extra_len)
        fd = os.open(target, flags, 0o644)
        with os.fdopen(fd, "wb") as out:

            def emit(data: bytes) -> None:
                nonlocal crc, entry_out
                if not data:
                    return
                crc = zlib.crc32(data, crc)
                entry_out += len(data)
                totals.out += len(data)
                _check_ratio(entry_out, entry_comp, totals, max_ratio, max_total)
                out.write(data)

            if info.compress_type == zipfile.ZIP_STORED:
                remaining = info.compress_size
                while remaining > 0:
                    if guard is not None:
                        guard.check()
                    chunk = f.read(min(CHUNK, remaining))
                    if not chunk:
                        raise UnsafeArchiveError("dados armazenados truncados")
                    remaining -= len(chunk)
                    entry_comp += len(chunk)
                    totals.comp += len(chunk)
                    emit(chunk)
            else:
                dec = zlib.decompressobj(-zlib.MAX_WBITS)
                iterations = 0
                while True:
                    iterations += 1
                    if iterations > MAX_ITERATIONS:
                        raise UnsafeArchiveError("fluxo comprimido não converge")
                    if guard is not None:
                        guard.check()
                    # fim do fluxo tem precedência: bytes sobrando após o fim são ignorados
                    if dec.eof:
                        break
                    if dec.unconsumed_tail:
                        pending = dec.unconsumed_tail
                    else:
                        pending = f.read(CHUNK)
                        if not pending:
                            raise UnsafeArchiveError("fluxo comprimido truncado")
                    try:
                        data = dec.decompress(pending, OUT_CHUNK)
                    except zlib.error as exc:
                        raise UnsafeArchiveError(f"fluxo comprimido corrompido: {exc}") from None
                    # conta só os bytes que o zlib consumiu desta entrada (não o bloco lido à frente)
                    unused = len(dec.unused_data) if dec.eof else 0
                    consumed = len(pending) - len(dec.unconsumed_tail) - unused
                    entry_comp += consumed
                    totals.comp += consumed
                    emit(data)
                if not dec.eof:
                    raise UnsafeArchiveError("fluxo comprimido incompleto")
                try:
                    tail = dec.flush()
                except zlib.error as exc:
                    raise UnsafeArchiveError(f"fluxo comprimido corrompido: {exc}") from None
                emit(tail)
    if (crc & 0xFFFFFFFF) != info.CRC:
        raise UnsafeArchiveError(f"CRC inválido em {info.filename!r}")
