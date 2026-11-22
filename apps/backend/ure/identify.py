"""Identificação real de formato por assinatura binária (nunca pela extensão)."""
from __future__ import annotations

import re
import struct
import zipfile
from pathlib import Path
from typing import Any

from .pe import PEError, parse_pe

KIND_APK = "apk"
KIND_PE = "pe"
KIND_ELF = "elf"
KIND_MACHO = "macho"
KIND_DEX = "dex"
KIND_JAR = "jar"
KIND_ZIP = "zip"
KIND_CORRUPT = "corrupt"
KIND_EMPTY = "empty"
KIND_UNKNOWN = "unknown"

UPLOADABLE_KINDS = frozenset({KIND_APK, KIND_PE})
MACHO_MAGICS = frozenset({b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"})
MAX_IDENTIFY_ENTRIES = 200_000
ZIP_MAGICS = frozenset({b"PK\x03\x04", b"PK\x05\x06", b"PK\x07\x08"})
_DEX_TOP = re.compile(r"classes\d*\.dex$")
ELF_TYPES = {1: "REL", 2: "EXEC", 3: "DYN", 4: "CORE"}
ELF_MACHINES = {3: "x86", 8: "mips", 40: "arm", 62: "x64", 183: "arm64"}


def identify(path: Path) -> dict[str, Any]:
    with path.open("rb") as f:
        head = f.read(8)
    if not head:
        return {"kind": KIND_EMPTY, "reason": "arquivo vazio"}
    if head[:2] == b"MZ":
        try:
            return {"kind": KIND_PE, "details": parse_pe(path)}
        except PEError as exc:
            return {"kind": KIND_CORRUPT, "reason": f"cabeçalho MZ sem PE válido: {exc}"}
    if head[:4] == b"\x7fELF":
        return {"kind": KIND_ELF, "details": _elf_header(path)}
    if head[:4] in MACHO_MAGICS:
        return {"kind": KIND_MACHO, "details": {}}
    if head[:4] == b"dex\n":
        return {"kind": KIND_DEX, "details": {}}
    if head[:4] in ZIP_MAGICS:
        return _identify_zip(path)
    return {"kind": KIND_UNKNOWN, "reason": "assinatura não reconhecida"}


def _identify_zip(path: Path) -> dict[str, Any]:
    try:
        with zipfile.ZipFile(path) as zf:
            infos = zf.infolist()
            if len(infos) > MAX_IDENTIFY_ENTRIES:
                return {"kind": KIND_CORRUPT, "reason": "contêiner com número de entradas acima do limite"}
            names = {i.filename for i in infos}
    except (zipfile.BadZipFile, OSError, ValueError, RuntimeError):
        return {"kind": KIND_CORRUPT, "reason": "contêiner ZIP corrompido ou ilegível"}
    has_dex = any(_DEX_TOP.fullmatch(n) for n in names)
    if "AndroidManifest.xml" in names and has_dex:
        return {"kind": KIND_APK, "details": {"entries": len(names)}}
    if "META-INF/MANIFEST.MF" in names:
        return {"kind": KIND_JAR, "details": {"entries": len(names)}}
    return {"kind": KIND_ZIP, "details": {"entries": len(names)}}


def _elf_header(path: Path) -> dict[str, Any]:
    with path.open("rb") as f:
        h = f.read(64)
    if len(h) < 20:
        return {"error": "cabeçalho ELF truncado"}
    bits = {1: 32, 2: 64}.get(h[4], 0)
    endian = "<" if h[5] == 1 else ">"
    e_type, e_machine = struct.unpack_from(endian + "HH", h, 16)
    return {
        "bits": bits,
        "type": ELF_TYPES.get(e_type, f"0x{e_type:x}"),
        "machine": ELF_MACHINES.get(e_machine, f"0x{e_machine:x}"),
    }
