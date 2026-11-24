"""Adaptadores dos motores externos. Cada um lê o arquivo; nunca o executa.

Ferramenta ausente retorna status 'missing' com motivo. Nenhum resultado é simulado.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

from .config import Settings
from .limits import Guard
from .tools import SPECS_BY_KEY, resolve, run_tool

LIEF_WORKER = Path(__file__).with_name("lief_worker.py")


def _invoke(key: str, args: list[str], settings: Settings, logs: Path, *,
            stdout_file: Path | None = None, workdir: Path | None = None,
            guard: Guard | None = None) -> dict[str, Any]:
    binary = resolve(SPECS_BY_KEY[key])
    if binary is None:
        return {"tool": key, "status": "missing", "reason": "ferramenta não instalada; etapa não executada"}
    cwd = workdir or logs
    cwd.mkdir(parents=True, exist_ok=True)
    timeout = settings.tool_timeout_s
    cancel = None
    if guard is not None:
        timeout = min(timeout, guard.remaining())
        cancel = guard.cancel
    result = run_tool(
        [binary, *args],
        cwd=cwd,
        timeout_s=timeout,
        memory_mb=settings.tool_memory_mb,
        log=logs / f"{key}.log",
        stdout_file=stdout_file,
        cancel=cancel,
    )
    return {"tool": key, **result}


def apktool_decode(apk: Path, out: Path, settings: Settings, logs: Path, guard: Guard | None = None) -> dict[str, Any]:
    res = _invoke("apktool", ["d", "-f", "-o", str(out), str(apk)], settings, logs, guard=guard)
    if res["status"] == "ok":
        res["produced"] = {
            "manifest_xml": (out / "AndroidManifest.xml").is_file(),
            "resources": (out / "res").is_dir(),
            "assets": (out / "assets").is_dir(),
            "smali_dirs": sum(1 for p in out.glob("smali*") if p.is_dir()),
        }
    return res


def jadx_decompile(apk: Path, out: Path, settings: Settings, logs: Path, guard: Guard | None = None) -> dict[str, Any]:
    res = _invoke("jadx", ["-d", str(out), "-j", "2", str(apk)], settings, logs, guard=guard)
    if res["status"] == "ok":
        res["produced"] = {"java_sources": sum(1 for _ in out.rglob("*.java"))}
    return res


def apkanalyzer_manifest(apk: Path, out_file: Path, settings: Settings, logs: Path,
                         guard: Guard | None = None) -> dict[str, Any]:
    out_file.parent.mkdir(parents=True, exist_ok=True)
    res = _invoke("apkanalyzer", ["manifest", "print", str(apk)], settings, logs,
                  stdout_file=out_file, guard=guard)
    if res["status"] == "ok":
        res["produced"] = {"manifest_file": out_file.name}
    return res


def ilspy_decompile(assembly: Path, out: Path, settings: Settings, logs: Path, guard: Guard | None = None) -> dict[str, Any]:
    out.mkdir(parents=True, exist_ok=True)
    res = _invoke("ilspycmd", ["-o", str(out), str(assembly)], settings, logs, guard=guard)
    if res["status"] == "ok":
        res["produced"] = {"csharp_files": sum(1 for _ in out.rglob("*.cs"))}
    return res


def ghidra_analyze(binary: Path, settings: Settings, logs: Path, guard: Guard | None = None) -> dict[str, Any]:
    project = logs / "ghidra-project"
    project.mkdir(parents=True, exist_ok=True)
    args = [str(project), "ure_import", "-import", str(binary), "-overwrite", "-deleteProject"]
    res = _invoke("ghidra", args, settings, logs, guard=guard)
    if res["status"] == "ok":
        res["produced"] = {"note": "importação e auto-análise executadas; saída detalhada apenas no log"}
    return res


def lief_inspect(target: Path, settings: Settings, logs: Path, label: str,
                 guard: Guard | None = None) -> dict[str, Any]:
    """Estrutura de ELF, PE, Mach-O ou DEX com LIEF. Roda em processo separado, com limite de
    memória e tempo; o resultado é o JSON produzido pelo worker, sem interpretação extra."""
    py = os.environ.get("URE_LIEF_PYTHON") or sys.executable
    if not (os.path.isfile(py) and os.access(py, os.X_OK)):
        return {"tool": "lief", "status": "missing", "reason": f"interpretador do LIEF não encontrado: {py}"}
    timeout = settings.tool_timeout_s
    cancel = None
    if guard is not None:
        timeout = min(timeout, guard.remaining())
        cancel = guard.cancel
    out = logs / f"lief-{label}.json"
    res = run_tool(
        [py, str(LIEF_WORKER), str(target)],
        cwd=logs, timeout_s=timeout, memory_mb=settings.tool_memory_mb,
        log=logs / f"lief-{label}.log", stdout_file=out, cancel=cancel,
    )
    result: dict[str, Any] = {"tool": "lief", **res}
    if res["status"] == "ok":
        try:
            data = json.loads(out.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            result["status"] = "failed"
            result["reason"] = f"saída do worker inválida: {exc}"
            return result
        if "error" in data:
            # O worker sai com código 0 e relata o erro no JSON; sem tratar isso, um LIEF ausente
            # apareceria como execução bem-sucedida. Módulo ausente = missing; o resto = failed.
            module_missing = data.get("error") == "ModuleNotFoundError" and "lief" in str(data.get("reason", ""))
            result["status"] = "missing" if module_missing else "failed"
            prefix = "LIEF não instalado neste interpretador" if module_missing else "LIEF falhou"
            result["reason"] = f"{prefix}: {data.get('reason', 'motivo não informado')} (interpretador {py})"
        else:
            result["result"] = data
    return result
