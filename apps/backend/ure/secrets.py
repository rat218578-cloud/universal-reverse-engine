"""Varredura de segredos com regras conhecidas. Valores são sempre mascarados no resultado."""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_TOTAL_BYTES = 200 * 1024 * 1024
MAX_FINDINGS = 500

RULES: tuple[tuple[str, re.Pattern[bytes]], ...] = (
    ("aws-access-key-id", re.compile(rb"AKIA[0-9A-Z]{16}")),
    ("private-key-block", re.compile(rb"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----")),
    ("google-api-key", re.compile(rb"AIza[0-9A-Za-z_\-]{35}")),
    ("slack-token", re.compile(rb"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    (
        "credential-assignment",
        re.compile(rb"(?i)(?:api[_-]?key|secret|token|passwd|password)[\"']?\s*[:=]\s*[\"'][^\"'\s]{8,}[\"']"),
    ),
)


def _redact(raw: bytes) -> str:
    text = raw.decode("ascii", "replace")
    if len(text) <= 8:
        return "*" * len(text)
    return f"{text[:4]}...{text[-2:]}"


def scan_secrets(base: Path, guard: Any = None) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    scanned = 0
    total = 0
    truncated = False
    for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
        for name in sorted(filenames):
            path = Path(dirpath, name)
            if path.is_symlink() or not path.is_file():
                continue
            if guard is not None:
                guard.check()
            size = path.stat().st_size
            if size > MAX_FILE_BYTES or total + size > MAX_TOTAL_BYTES:
                truncated = True
                continue
            data = path.read_bytes()
            total += len(data)
            scanned += 1
            rel = path.relative_to(base).as_posix()
            for rule, pattern in RULES:
                for match in pattern.finditer(data):
                    if len(findings) >= MAX_FINDINGS:
                        return {"files_scanned": scanned, "bytes_scanned": total, "findings": findings, "truncated": True}
                    findings.append(
                        {"file": rel, "rule": rule, "offset": match.start(), "preview": _redact(match.group())}
                    )
    return {"files_scanned": scanned, "bytes_scanned": total, "findings": findings, "truncated": truncated}
