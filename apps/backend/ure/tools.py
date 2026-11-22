"""Registro de motores de engenharia reversa: detecção, versão e execução com limites.

Ferramenta ausente é registrada como 'missing' e nunca simulada. Os motores apenas leem o
arquivo recebido (parse ou decompilação); o arquivo analisado nunca é executado.
"""
from __future__ import annotations

import importlib.util
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import MB


@dataclass(frozen=True)
class ToolSpec:
    key: str
    name: str
    purpose: str
    binaries: tuple[str, ...]
    version_args: tuple[str, ...]
    env_var: str
    jvm: bool = False


SPECS: tuple[ToolSpec, ...] = (
    ToolSpec("java", "Java Runtime", "requisito de JADX, apktool e ILSpy", ("java",), ("-version",), "URE_JAVA"),
    ToolSpec("apktool", "Apktool", "decodificação de APK: Manifest, recursos, Smali",
             ("apktool",), ("--version",), "URE_APKTOOL", jvm=True),
    ToolSpec("jadx", "JADX", "descompilação de DEX para Java", ("jadx",), ("--version",), "URE_JADX", jvm=True),
    ToolSpec("apkanalyzer", "Android SDK apkanalyzer", "metadados do APK pelo SDK Android",
             ("apkanalyzer",), ("--version",), "URE_APKANALYZER", jvm=True),
    ToolSpec("ilspycmd", "ILSpy (ilspycmd)", "descompilação de assemblies .NET",
             ("ilspycmd",), ("--version",), "URE_ILSPYCMD"),
    ToolSpec("ghidra", "Ghidra analyzeHeadless", "análise nativa de PE/ELF (headless)",
             ("analyzeHeadless", "ghidra_analyzeHeadless"), (), "URE_GHIDRA", jvm=True),
    ToolSpec("lief", "LIEF (biblioteca Python)", "análise binária avançada (opcional)", (), (), ""),
)
SPECS_BY_KEY = {s.key: s for s in SPECS}

_LIMIT_STUB = (
    "import resource, os, sys\n"
    "mem = int(sys.argv[1])\n"
    "resource.setrlimit(resource.RLIMIT_AS, (mem, mem))\n"
    "os.execvp(sys.argv[2], sys.argv[2:])\n"
)


def resolve(spec: ToolSpec) -> str | None:
    override = os.environ.get(spec.env_var) if spec.env_var else None
    if override:
        return override if os.path.isfile(override) and os.access(override, os.X_OK) else None
    for binary in spec.binaries:
        found = shutil.which(binary)
        if found:
            return found
    return None


def _version(path: str, args: tuple[str, ...]) -> str | None:
    if not args:
        return None
    try:
        proc = subprocess.run(
            [path, *args], capture_output=True, timeout=20, stdin=subprocess.DEVNULL, text=True, errors="replace"
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    lines = (proc.stdout or proc.stderr or "").strip().splitlines()
    return lines[0][:120] if lines else None


def probe(spec: ToolSpec) -> dict[str, Any]:
    base = {"key": spec.key, "name": spec.name, "purpose": spec.purpose}
    if spec.key == "lief":
        found = importlib.util.find_spec("lief") is not None
        note = "" if found else "não instalado; a análise PE usa o analisador próprio do URE"
        return {**base, "status": "available" if found else "missing", "path": None, "version": None, "note": note}
    path = resolve(spec)
    if path is None:
        hint = f"defina {spec.env_var} ou instale no PATH" if spec.env_var else "instale no PATH"
        return {**base, "status": "missing", "path": None, "version": None, "note": f"não encontrado; {hint}"}
    return {
        **base,
        "status": "available",
        "path": path,
        "version": _version(path, spec.version_args) or "versão não determinada",
        "note": "",
    }


def probe_all() -> list[dict[str, Any]]:
    return [probe(spec) for spec in SPECS]


def run_tool(
    argv: list[str],
    *,
    cwd: Path,
    timeout_s: int,
    memory_mb: int,
    log: Path,
    stdout_file: Path | None = None,
) -> dict[str, Any]:
    """Executa um motor com tempo limite e limite de memória virtual (POSIX, via RLIMIT_AS)."""
    cmd = list(argv)
    limited = os.name == "posix"
    if limited:
        cmd = [sys.executable, "-c", _LIMIT_STUB, str(memory_mb * MB), *argv]
    env = {k: os.environ[k] for k in ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "JAVA_HOME") if k in os.environ}
    out_fh = stdout_file.open("wb") if stdout_file else None
    try:
        proc = subprocess.run(
            cmd,
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=out_fh if out_fh else subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout_s,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {"status": "timeout", "timeout_s": timeout_s, "memory_limit_applied": limited}
    except FileNotFoundError:
        return {"status": "missing", "memory_limit_applied": limited}
    finally:
        if out_fh:
            out_fh.close()
    captured = proc.stderr or b""
    if not out_fh:
        captured = (proc.stdout or b"") + captured
    log.parent.mkdir(parents=True, exist_ok=True)
    log.write_bytes(captured[-65536:])
    status = "ok" if proc.returncode == 0 else "failed"
    return {
        "status": status,
        "returncode": proc.returncode,
        "log": log.name,
        "memory_limit_applied": limited,
    }
