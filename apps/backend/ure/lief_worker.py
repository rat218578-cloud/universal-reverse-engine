"""Inspeção estrutural com LIEF (ELF, PE, Mach-O e DEX). Roda em processo separado.

Chamado como script pelo motor do URE, com o interpretador do ambiente do LIEF. Não importa o pacote
`ure`, porque o ambiente do LIEF pode não tê-lo. Imprime um JSON. Nunca executa o arquivo analisado.
Uso: python lief_worker.py ARQUIVO
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

MAX_NAMES = 200
DEX_MAGIC = b"dex\n"


def _names(items, attr: str = "name") -> list[str]:
    out: list[str] = []
    for item in items:
        if len(out) >= MAX_NAMES:
            break
        value = item if isinstance(item, str) else getattr(item, attr, None)
        if value:
            out.append(str(value))
    return out


def _inspect_dex(path: Path) -> dict:
    import lief

    dex = lief.DEX.parse(str(path))
    dexes = dex if isinstance(dex, list) else [dex]
    summary = []
    for d in dexes[:8]:
        summary.append({
            "version": str(getattr(d, "version", "")),
            "classes": len(list(d.classes)),
            "methods": len(list(d.methods)),
            "strings": len(list(d.strings)),
            "class_names": _names([c.fullname for c in d.classes]),
        })
    return {"format": "DEX", "dex_files": summary}


def _inspect_binary(path: Path) -> dict:
    import lief

    binary = lief.parse(str(path))
    if binary is None:
        return {"error": "formato_nao_reconhecido", "reason": "LIEF não reconheceu o arquivo"}
    fmt = str(binary.format).replace("FORMATS.", "")
    header = binary.header
    result: dict = {
        "format": fmt,
        "machine": str(getattr(header, "machine_type", None) or getattr(header, "machine", "")),
        "file_type": str(getattr(header, "file_type", "")),
        "sections": _names(binary.sections),
    }
    if fmt == "ELF":
        result["needed_libraries"] = _names(binary.libraries)
        result["exported_symbols"] = _names(binary.exported_symbols)
        result["imported_functions"] = len(list(binary.imported_functions))
        result["nx"] = bool(binary.has_nx)
        result["pie"] = bool(binary.is_pie)
    elif fmt == "PE":
        result["imported_dlls"] = _names(binary.imports)
        result["exported_symbols"] = _names(binary.exported_functions) if hasattr(binary, "exported_functions") else []
    return result


def inspect(path: Path) -> dict:
    head = path.read_bytes()[:4]
    if head == DEX_MAGIC:
        return _inspect_dex(path)
    return _inspect_binary(path)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(json.dumps({"error": "uso", "reason": "python lief_worker.py ARQUIVO"}))
        return 2
    try:
        result = inspect(Path(argv[1]))
    except Exception as exc:  # o erro vira resultado registrado, nunca falha silenciosa
        result = {"error": type(exc).__name__, "reason": str(exc)[:300]}
    result["lief_version"] = _lief_version()
    sys.stdout.write(json.dumps(result, ensure_ascii=False))
    return 0


def _lief_version() -> str:
    try:
        import lief
        return str(lief.__version__)
    except Exception:
        return "indisponível"


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
