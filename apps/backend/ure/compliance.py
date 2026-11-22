"""Verificações locais de conformidade: licenças declaradas nos arquivos e tamanho do conteúdo.

Detecção por texto de cabeçalho de arquivos LICENSE/COPYING/NOTICE. É indicativa, não é parecer
jurídico, e um arquivo não identificado é reportado como tal.
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

LICENSE_FILE = re.compile(r"(^|/)(LICEN[CS]E|COPYING|NOTICE)([._-][A-Za-z0-9.-]+)?$", re.IGNORECASE)
SIGNATURES: tuple[tuple[str, str], ...] = (
    ("Apache-2.0", "apache license"),
    ("MIT", "mit license"),
    ("MPL-2.0", "mozilla public license"),
    ("GPL", "gnu general public license"),
    ("LGPL", "gnu lesser general public license"),
    ("BSD", "redistribution and use in source and binary forms"),
    ("ISC", "isc license"),
    ("Unlicense", "this is free and unencumbered software"),
)
MAX_HEAD = 64 * 1024


def detect_license_text(text: str) -> list[str]:
    low = text.lower()
    found = [name for name, needle in SIGNATURES if needle in low]
    if "GPL" in found and "version 3" in low:
        found = ["GPL-3.0" if f == "GPL" else f for f in found]
    return found


def scan_licenses(base: Path) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    if not base.is_dir():
        return results
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
        for name in sorted(filenames):
            path = Path(dirpath, name)
            rel = path.relative_to(base).as_posix()
            if path.is_symlink() or not path.is_file() or not LICENSE_FILE.search(rel):
                continue
            head = path.read_bytes()[:MAX_HEAD].decode("utf-8", "replace")
            detected = detect_license_text(head)
            results.append({"file": rel, "detected": detected or ["não identificada"]})
    return results


def size_summary(base: Path) -> dict[str, int]:
    total = 0
    count = 0
    if base.is_dir():
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
            for name in filenames:
                path = Path(dirpath, name)
                if path.is_symlink() or not path.is_file():
                    continue
                total += path.stat().st_size
                count += 1
    return {"files": count, "bytes": total}
