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
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Mapping
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
    # Chaves de outras ferramentas que precisam estar disponíveis para esta funcionar.
    requires: tuple[str, ...] = ()


SPECS: tuple[ToolSpec, ...] = (
    ToolSpec("java", "Java Runtime", "requisito de Apktool, JADX, apkanalyzer e Ghidra",
             ("java",), ("-version",), "URE_JAVA"),
    ToolSpec("dotnet", ".NET SDK/Runtime", "requisito do ilspycmd",
             ("dotnet",), ("--version",), "URE_DOTNET"),
    ToolSpec("apktool", "Apktool", "decodificação de APK: Manifest, recursos, Smali",
             ("apktool",), ("--version",), "URE_APKTOOL", jvm=True, requires=("java",)),
    ToolSpec("jadx", "JADX", "descompilação de DEX para Java", ("jadx",), ("--version",), "URE_JADX",
             jvm=True, requires=("java",)),
    ToolSpec("apkanalyzer", "Android SDK apkanalyzer", "metadados do APK pelo SDK Android",
             ("apkanalyzer",), ("--version",), "URE_APKANALYZER", jvm=True, requires=("java",)),
    ToolSpec("ilspycmd", "ILSpy (ilspycmd)", "descompilação de assemblies .NET",
             ("ilspycmd",), ("--version",), "URE_ILSPYCMD", requires=("dotnet",)),
    ToolSpec("ghidra", "Ghidra analyzeHeadless", "análise nativa de PE/ELF (headless)",
             ("analyzeHeadless", "ghidra_analyzeHeadless"), (), "URE_GHIDRA", jvm=True, requires=("java",)),
    ToolSpec("lief", "LIEF (biblioteca Python)", "análise de estruturas ELF, PE e Mach-O",
             (), (), "URE_LIEF_PYTHON"),
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
    text = f"{proc.stdout or ''}\n{proc.stderr or ''}"
    # a JVM imprime avisos como "Picked up JAVA_TOOL_OPTIONS" antes da versão real
    lines = [ln.strip() for ln in text.splitlines()
             if ln.strip() and not ln.lstrip().startswith(("Picked up", "NOTE:", "WARNING:"))]
    if not lines:
        return None
    preferred = next((ln for ln in lines if "version" in ln.lower()), lines[0])
    return preferred[:120]


_LIEF_PROBE = "import lief, sys; sys.stdout.write(lief.__version__)"
DEFAULT_TOOLS_ENV = Path("/opt/ure-tools/tools.env")


def _probe_lief() -> dict[str, Any]:
    """LIEF é testado no interpretador configurado (URE_LIEF_PYTHON), não no do servidor."""
    py = os.environ.get("URE_LIEF_PYTHON") or sys.executable
    if not (os.path.isfile(py) and os.access(py, os.X_OK)):
        return {"status": "missing", "path": None, "version": None,
                "note": f"interpretador não encontrado: {py}; instale com scripts/install-tools.sh"}
    try:
        proc = subprocess.run([py, "-c", _LIEF_PROBE], capture_output=True, text=True, timeout=30,
                              stdin=subprocess.DEVNULL, env=child_env())
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"status": "missing", "path": py, "version": None, "note": f"falha ao testar LIEF: {exc}"}
    if proc.returncode != 0:
        last = (proc.stderr or "").strip().splitlines()[-1:] or ["erro desconhecido"]
        return {"status": "missing", "path": py, "version": None, "note": f"lief não importa: {last[0][:160]}"}
    return {"status": "available", "path": py, "version": f"LIEF {proc.stdout.strip() or 'versão não determinada'}",
            "note": ""}


def probe(spec: ToolSpec) -> dict[str, Any]:
    base = {"key": spec.key, "name": spec.name, "purpose": spec.purpose, "requires": list(spec.requires)}
    if spec.key == "lief":
        return {**base, **_probe_lief()}
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
    """Estado real de cada ferramenta, com as dependências que faltam para ela funcionar."""
    rows = [probe(spec) for spec in SPECS]
    status = {r["key"]: r["status"] for r in rows}
    for row in rows:
        row["pending"] = [k for k in row["requires"] if status.get(k) != "available"]
        if row["pending"]:
            dep = "dependência ausente: " + ", ".join(row["pending"])
            # Ferramenta ausente com dependência ausente: o motivo da ausência é mantido e a dependência é acrescentada.
            row["note"] = f"{row['note']}; {dep}" if row["status"] != "available" and row["note"] else dep
    return rows


def self_test(spec: ToolSpec, timeout_s: float = 30) -> dict[str, Any]:
    """Executa a ferramenta de verdade (versão, ou importação para o LIEF) e reporta o resultado."""
    row = probe(spec)
    if row["status"] != "available":
        return {"key": spec.key, "ok": False, "status": "missing", "path": None, "exit_code": None,
                "detail": row["note"]}
    argv = [row["path"], "-c", _LIEF_PROBE] if spec.key == "lief" else [row["path"], *spec.version_args]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout_s,
                              stdin=subprocess.DEVNULL, env=child_env())
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"key": spec.key, "ok": False, "status": "failed", "path": row["path"], "exit_code": None,
                "detail": str(exc)}
    text = "\n".join(ln for ln in f"{proc.stdout or ''}\n{proc.stderr or ''}".splitlines()
                     if ln.strip() and not ln.lstrip().startswith(("Picked up", "NOTE:")))
    ok = proc.returncode == 0
    return {"key": spec.key, "ok": ok, "status": "ok" if ok else "failed", "path": row["path"],
            "exit_code": proc.returncode, "detail": text[-600:]}


def load_tools_env() -> Path | None:
    """Carrega o arquivo de ambiente das ferramentas (URE_TOOLS_ENV ou /opt/ure-tools/tools.env).
    Só chaves URE_* são aceitas e variáveis já definidas no ambiente têm precedência."""
    from .config import load_env_file  # import local: evita ciclo na inicialização
    raw = os.environ.get("URE_TOOLS_ENV")
    path = Path(raw).expanduser() if raw else DEFAULT_TOOLS_ENV
    if path.is_file():
        load_env_file(path)
        return path
    return None


def startup_lines(rows: list[dict[str, Any]]) -> list[str]:
    """Linhas de diagnóstico impressas na inicialização do servidor."""
    lines = []
    for r in rows:
        if r["status"] == "available":
            lines.append(f"[ferramentas] {r['key']}: {r['version']} em {r['path']}")
        else:
            lines.append(f"[ferramentas] {r['key']}: AUSENTE. {r['note']}")
    return lines


MAX_CAPTURE_BYTES = 4 * MB
_TRUNCATED = b"\n[saida truncada: limite de captura atingido]\n"


def _drain(stream: Any, path: Path, cap: int) -> None:
    """Lê o fluxo até o fim, gravando no máximo `cap` bytes. O restante é descartado,
    mas continua sendo lido: o processo nunca fica bloqueado numa escrita de pipe."""
    written = 0
    marked = False
    try:
        with path.open("wb") as fh:
            for chunk in iter(lambda: stream.read(65536), b""):
                if written < cap:
                    part = chunk[: cap - written]
                    fh.write(part)
                    written += len(part)
                    rest = chunk[len(part):]
                else:
                    rest = chunk
                if rest and not marked:
                    fh.write(_TRUNCATED)
                    marked = True
    finally:
        stream.close()


# Variáveis que o processo filho precisa para funcionar. Lista fixa: segredos do ambiente
# do usuário não são repassados às ferramentas analisadas. No Windows, SYSTEMROOT e
# companhia são indispensáveis: sem elas, quase nenhum programa inicia.
_BASE_ENV_KEYS = ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "JAVA_HOME")
_WINDOWS_ENV_KEYS = (
    "SYSTEMROOT", "WINDIR", "COMSPEC", "PATHEXT", "USERPROFILE", "TEMP", "TMP",
    "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "PROGRAMFILES", "PROGRAMFILES(X86)",
)


def child_env(environ: Mapping[str, str] | None = None, platform_name: str | None = None) -> dict[str, str]:
    """Ambiente mínimo para motores externos, conforme a plataforma."""
    source = os.environ if environ is None else environ
    keys = _BASE_ENV_KEYS + (_WINDOWS_ENV_KEYS if (platform_name or os.name) == "nt" else ())
    return {k: source[k] for k in keys if k in source}


def kill_tree(proc: subprocess.Popen) -> None:
    """Encerra o processo e os filhos. Em Windows, wrappers como apktool.bat iniciam um java
    filho que sobreviveria ao kill direto; taskkill /T derruba a árvore inteira."""
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
            capture_output=True, timeout=30, check=False,
        )
    proc.kill()
    proc.wait()


def run_tool(
    argv: list[str],
    *,
    cwd: Path,
    timeout_s: float,
    memory_mb: int,
    log: Path,
    stdout_file: Path | None = None,
    cancel: threading.Event | None = None,
) -> dict[str, Any]:
    """Executa um motor com tempo limite, cancelamento, limite de memória virtual (POSIX) e
    captura limitada: no máximo MAX_CAPTURE_BYTES por fluxo (stdout e stderr).
    Em tempo esgotado ou cancelamento, o processo é encerrado.
    """
    cmd = list(argv)
    limited = os.name == "posix"
    if limited:
        cmd = [sys.executable, "-c", _LIMIT_STUB, str(memory_mb * MB), *argv]
    env = child_env()
    if limited:
        # A JVM reserva heap e metaspace como memória virtual: sem um teto de heap menor que o
        # limite de endereçamento, ela falha com "insufficient memory" (visto no CI Ubuntu).
        env["JAVA_TOOL_OPTIONS"] = f"-Xmx{max(256, memory_mb // 2)}m"
    log.parent.mkdir(parents=True, exist_ok=True)
    kwargs: dict[str, Any] = {"stdin": subprocess.DEVNULL, "stdout": subprocess.PIPE}
    if stdout_file is not None:
        kwargs["stderr"] = subprocess.PIPE
    else:
        kwargs["stderr"] = subprocess.STDOUT
    try:
        proc = subprocess.Popen(cmd, cwd=cwd, env=env, **kwargs)
    except FileNotFoundError:
        log.write_bytes(b"")
        return {"status": "missing", "memory_limit_applied": limited}
    drains = [threading.Thread(target=_drain, args=(proc.stdout, stdout_file or log, MAX_CAPTURE_BYTES), daemon=True)]
    if stdout_file is not None:
        drains.append(threading.Thread(target=_drain, args=(proc.stderr, log, MAX_CAPTURE_BYTES), daemon=True))
    for t in drains:
        t.start()
    deadline = time.monotonic() + timeout_s
    status: str | None = None
    while status is None:
        try:
            rc = proc.wait(timeout=0.2)
            status = "ok" if rc == 0 else "failed"
        except subprocess.TimeoutExpired:
            if cancel is not None and cancel.is_set():
                kill_tree(proc)
                status = "cancelled"
            elif time.monotonic() > deadline:
                kill_tree(proc)
                status = "timeout"
    for t in drains:
        t.join(timeout=10)
    result: dict[str, Any] = {"status": status, "log": log.name, "memory_limit_applied": limited}
    if status in ("ok", "failed"):
        result["returncode"] = proc.returncode
    if status == "timeout":
        result["timeout_s"] = timeout_s
    return result
