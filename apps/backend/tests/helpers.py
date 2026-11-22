"""Auxiliares de teste. Arquivos sintéticos são construídos em bytes e nunca executados."""
from __future__ import annotations

import os
import struct
import threading
import zipfile
from pathlib import Path


def make_zip(path: Path, entries: list[tuple[str, bytes, int | None]]) -> Path:
    """entries: (nome, conteúdo, modo_unix ou None). Modo permite criar links simbólicos."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data, mode in entries:
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            if mode is not None:
                info.external_attr = (mode & 0xFFFF) << 16
            zf.writestr(info, data)
    return path


def synthetic_apk(path: Path, extra: list[tuple[str, bytes, int | None]] | None = None) -> Path:
    entries = [
        ("AndroidManifest.xml", b"\x03\x00\x08\x00 binary-manifest", None),
        ("classes.dex", b"dex\n035\x00" + b"\x00" * 96, None),
        ("assets/notes.txt", b"hello from ure\n", None),
    ]
    return make_zip(path, entries + (extra or []))


def synthetic_pe32(path: Path) -> Path:
    """PE32 x86 mínimo e válido: uma seção .idata que importa KERNEL32.dll!ExitProcess."""
    buf = bytearray(0x400)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, 0x40)
    buf[0x40:0x44] = b"PE\x00\x00"
    struct.pack_into("<HHIIIHH", buf, 0x44, 0x14C, 1, 0, 0, 0, 224, 0x0102)
    opt = 0x58
    struct.pack_into("<H", buf, opt, 0x10B)
    struct.pack_into("<I", buf, opt + 16, 0x1000)  # entry point
    struct.pack_into("<I", buf, opt + 28, 0x400000)  # image base
    struct.pack_into("<H", buf, opt + 68, 3)  # subsystem: CUI
    struct.pack_into("<I", buf, opt + 92, 16)  # NumberOfRvaAndSizes
    dd = opt + 96
    struct.pack_into("<II", buf, dd + 8, 0x1000, 0x28)  # import directory
    sec = opt + 224
    buf[sec : sec + 8] = b".idata\x00\x00"
    struct.pack_into("<IIIII", buf, sec + 8, 0x100, 0x1000, 0x200, 0x200, 0)
    struct.pack_into("<I", buf, sec + 36, 0xC0000040)

    def off(rva: int) -> int:
        return rva - 0x1000 + 0x200

    struct.pack_into("<IIIII", buf, off(0x1000), 0x1028, 0, 0, 0x1050, 0x1038)  # descriptor
    struct.pack_into("<II", buf, off(0x1028), 0x1060, 0)  # OFT
    struct.pack_into("<II", buf, off(0x1038), 0x1060, 0)  # IAT
    buf[off(0x1050) : off(0x1050) + 13] = b"KERNEL32.dll\x00"
    struct.pack_into("<H", buf, off(0x1060), 0)
    buf[off(0x1062) : off(0x1062) + 12] = b"ExitProcess\x00"
    path.write_bytes(bytes(buf))
    return path


def find_real_pe() -> Path | None:
    """PE real para os testes. Ordem: URE_TEST_PE (caminho explícito) e depois as pastas site/sys.path
    do interpretador em uso, procurando o launcher w32.exe que o pip distribui. Sem caminhos fixos no código."""
    import site
    import sys

    env = os.environ.get("URE_TEST_PE")
    if env and Path(env).is_file():
        return Path(env)
    roots = [Path(p) for p in sys.path if p] + [Path(p) for p in site.getsitepackages()]
    for root in roots:
        candidate = root / "pip" / "_vendor" / "distlib" / "w32.exe"
        if candidate.is_file():
            return candidate
    return None


# Chave de exemplo oficial da AWS, usada apenas para testar a regra de detecção. Montada em tempo de
# execução para que o literal completo não apareça no código-fonte (varreduras de segredo sinalizam o padrão).
AWS_EXAMPLE_KEY = "AKIA" + "IOSFODNN7EXAMPLE"


def run_server_in_thread(server: object) -> threading.Thread:
    t = threading.Thread(target=server.serve_forever, daemon=True)  # type: ignore[attr-defined]
    t.start()
    return t
