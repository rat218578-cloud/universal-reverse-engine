"""Analisador PE (EXE/DLL) em biblioteca padrão: cabeçalhos, seções, importações e assinatura.

Implementação própria, sem LIEF. Cobre o necessário para triagem; recursos avançados
(relocações, certificados, exportações completas) ficam fora do escopo deste módulo.
"""
from __future__ import annotations

import datetime as dt
import math
import mmap
import struct
from pathlib import Path
from typing import Any

MACHINES = {0x014C: "x86", 0x8664: "x64", 0xAA64: "arm64", 0x01C0: "arm", 0x01C4: "armnt", 0x0200: "ia64"}
SUBSYSTEMS = {1: "native", 2: "windows-gui", 3: "windows-cui", 9: "windows-ce", 10: "efi-app", 14: "xbox"}
IMAGE_FILE_DLL = 0x2000
MAX_IMPORTS = 20_000
MAX_THUNKS_PER_DLL = 8_192
MAX_SECTIONS = 256
ENTROPY_SAMPLE = 1024 * 1024


class PEError(ValueError):
    """Cabeçalho PE ausente, truncado ou inválido."""


def _cstr(m: mmap.mmap, off: int, limit: int = 512) -> str | None:
    end = m.find(b"\x00", off, min(off + limit, len(m)))
    if end < 0:
        return None
    return m[off:end].decode("utf-8", "replace")


def _entropy(data: bytes) -> float:
    if not data:
        return 0.0
    total = len(data)
    ent = 0.0
    for b in range(256):
        c = data.count(bytes((b,)))
        if c:
            p = c / total
            ent -= p * math.log2(p)
    return round(ent, 3)


def parse_pe(path: Path) -> dict[str, Any]:
    size = path.stat().st_size
    if size < 64:
        raise PEError("arquivo menor que o cabeçalho DOS")
    warnings: list[str] = []
    with path.open("rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as m:
        if m[:2] != b"MZ":
            raise PEError("assinatura MZ ausente")
        lfanew = struct.unpack_from("<I", m, 0x3C)[0]
        if lfanew < 0x40 or lfanew + 24 > size or m[lfanew : lfanew + 4] != b"PE\x00\x00":
            raise PEError("cabeçalho PE ausente ou fora do arquivo")
        machine, nsec, ts, _, _, opt_size, chars = struct.unpack_from("<HHIIIHH", m, lfanew + 4)
        opt = lfanew + 24
        if opt_size < 2 or opt + opt_size > size:
            raise PEError("optional header truncado")
        magic = struct.unpack_from("<H", m, opt)[0]
        if magic == 0x10B:
            fmt, plus, dd_base, ib_off = "PE32", False, opt + 96, opt + 28
        elif magic == 0x20B:
            fmt, plus, dd_base, ib_off = "PE32+", True, opt + 112, opt + 24
        else:
            raise PEError("magic do optional header desconhecido")
        if opt_size < (112 if plus else 96):
            raise PEError("optional header menor que o esperado")
        if nsec == 0 or nsec > MAX_SECTIONS:
            raise PEError("número de seções implausível")
        entry = struct.unpack_from("<I", m, opt + 16)[0]
        image_base = struct.unpack_from("<Q" if plus else "<I", m, ib_off)[0]
        subsystem = struct.unpack_from("<H", m, opt + 68)[0]
        ndirs = min(struct.unpack_from("<I", m, dd_base - 4)[0], 16)
        dirs = [struct.unpack_from("<II", m, dd_base + 8 * i) for i in range(ndirs) if dd_base + 8 * i + 8 <= size]

        sec_off = opt + opt_size
        if sec_off + 40 * nsec > size:
            raise PEError("tabela de seções truncada")
        sections: list[dict[str, Any]] = []
        for i in range(nsec):
            o = sec_off + 40 * i
            name = m[o : o + 8].split(b"\x00", 1)[0].decode("ascii", "replace")
            vsize, vaddr, rsize, rptr = struct.unpack_from("<IIII", m, o + 8)
            schars = struct.unpack_from("<I", m, o + 36)[0]
            entropy: float | None = None
            if rptr < size and rsize > 0:
                entropy = _entropy(m[rptr : min(rptr + rsize, rptr + ENTROPY_SAMPLE, size)])
            if rptr + rsize > size:
                warnings.append(f"seção {name!r} aponta além do fim do arquivo")
            sections.append(
                {
                    "name": name,
                    "virtual_address": vaddr,
                    "virtual_size": vsize,
                    "raw_ptr": rptr,
                    "raw_size": rsize,
                    "characteristics": schars,
                    "entropy": entropy,
                }
            )

        def rva_to_off(rva: int) -> int | None:
            for s in sections:
                va = s["virtual_address"]
                span = max(s["virtual_size"], s["raw_size"])
                if va <= rva < va + span and rva - va < s["raw_size"]:
                    off = s["raw_ptr"] + (rva - va)
                    return off if off < size else None
            return None

        imports: dict[str, list[str]] = {}
        total = 0
        imp_rva = dirs[1][0] if len(dirs) > 1 else 0
        if imp_rva:
            off = rva_to_off(imp_rva)
            if off is None:
                warnings.append("tabela de importações fora das seções")
            else:
                step = 8 if plus else 4
                ordinal_flag = (1 << 63) if plus else (1 << 31)
                while off + 20 <= size and total < MAX_IMPORTS:
                    oft, _, _, name_rva, ft = struct.unpack_from("<IIIII", m, off)
                    if not (oft or name_rva or ft):
                        break
                    dll_off = rva_to_off(name_rva) if name_rva else None
                    dll = (_cstr(m, dll_off) if dll_off is not None else None) or "?"
                    names: list[str] = []
                    toff = rva_to_off(oft or ft)
                    if toff is not None:
                        for k in range(MAX_THUNKS_PER_DLL):
                            if toff + step * (k + 1) > size or total >= MAX_IMPORTS:
                                break
                            val = struct.unpack_from("<Q" if plus else "<I", m, toff + step * k)[0]
                            if val == 0:
                                break
                            if val & ordinal_flag:
                                names.append(f"ordinal#{val & 0xFFFF}")
                            else:
                                ho = rva_to_off(val & 0x7FFFFFFF)
                                names.append((_cstr(m, ho + 2) if ho is not None else None) or "?")
                            total += 1
                    imports.setdefault(dll, []).extend(names)
                    off += 20
                if total >= MAX_IMPORTS:
                    warnings.append("limite de importações atingido; lista truncada")

        sec_dir = dirs[4] if len(dirs) > 4 else (0, 0)
        end_of_data = max((s["raw_ptr"] + s["raw_size"] for s in sections), default=0)
        overlay = max(0, size - end_of_data)
        timestamp = None
        if 0 < ts < 2**32:
            timestamp = dt.datetime.fromtimestamp(ts, tz=dt.timezone.utc).isoformat()

    return {
        "format": fmt,
        "machine": MACHINES.get(machine, f"0x{machine:04x}"),
        "is_dll": bool(chars & IMAGE_FILE_DLL),
        "subsystem": SUBSYSTEMS.get(subsystem, f"0x{subsystem:04x}"),
        "entry_point_rva": f"0x{entry:08x}",
        "image_base": f"0x{image_base:x}",
        "compile_timestamp": timestamp,
        "compile_timestamp_note": "valor do cabeçalho; pode ser forjado ou zerado",
        "sections": sections,
        "imports": imports,
        "import_count": total,
        "signed": sec_dir[1] > 0,
        "overlay_bytes": overlay,
        "warnings": warnings,
    }
