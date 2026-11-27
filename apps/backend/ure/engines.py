"""Adaptadores dos motores externos. Cada um lê o arquivo; nunca o executa.

Ferramenta ausente retorna status 'missing' com motivo. Nenhum resultado é simulado.
"""
from __future__ import annotations

import json
import os
import re
import shutil
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


ANDROGUARD_WORKER = Path(__file__).with_name("androguard_worker.py")


def _python_interpreter(key: str) -> str | None:
    """Interpretador de uma biblioteca Python: variável própria, depois a do LIEF, depois o do servidor."""
    spec = SPECS_BY_KEY[key]
    py = os.environ.get(spec.env_var) or os.environ.get("URE_LIEF_PYTHON") or sys.executable
    return py if os.path.isfile(py) and os.access(py, os.X_OK) else None


def _run_for_json(tool: str, argv: list[str], settings: Settings, logs: Path, label: str,
                  guard: Guard | None) -> dict[str, Any]:
    out = logs / f"{tool}-{label}.json"
    timeout = settings.tool_timeout_s
    cancel = None
    if guard is not None:
        timeout = min(timeout, guard.remaining())
        cancel = guard.cancel
    res = run_tool(argv, cwd=logs, timeout_s=timeout, memory_mb=settings.tool_memory_mb,
                   log=logs / f"{tool}-{label}.log", stdout_file=out, cancel=cancel)
    return {"tool": tool, **res}


def androguard_summary(apk: Path, settings: Settings, logs: Path, label: str,
                       guard: Guard | None = None) -> dict[str, Any]:
    """Manifesto, componentes, permissões e classes do APK, lidos pelo Androguard."""
    py = _python_interpreter("androguard")
    if py is None:
        return {"tool": "androguard", "status": "missing", "reason": "interpretador do Androguard não encontrado"}
    result = _run_for_json("androguard", [py, "-I", str(ANDROGUARD_WORKER), "summary", str(apk)],
                           settings, logs, label, guard)
    if result["status"] != "ok":
        return result
    try:
        data = json.loads((logs / f"androguard-{label}.json").read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        return {**result, "status": "failed", "reason": f"saída do Androguard inválida: {exc}"}
    if "error" in data:
        module_missing = data["error"] == "ModuleNotFoundError"
        return {**result, "status": "missing" if module_missing else "failed",
                "reason": f"{data['error']}: {data.get('reason', '')}"}
    return {**result, "result": data}


def androguard_decompile(apk: Path, out: Path, settings: Settings, logs: Path,
                         guard: Guard | None = None) -> dict[str, Any]:
    """Reconstrói código Java a partir dos DEX com a CLI oficial do Androguard (papel do JADX)."""
    py = _python_interpreter("androguard")
    if py is None:
        return {"tool": "androguard", "status": "missing", "reason": "interpretador do Androguard não encontrado"}
    cli = Path(py).with_name("androguard")
    if not cli.is_file():
        return {"tool": "androguard", "status": "missing", "reason": f"CLI 'androguard' ausente em {cli.parent}"}
    shutil.rmtree(out, ignore_errors=True)
    timeout = settings.tool_timeout_s
    cancel = None
    if guard is not None:
        timeout = min(timeout, guard.remaining())
        cancel = guard.cancel
    res = run_tool([str(cli), "decompile", "-o", str(out), str(apk)], cwd=logs, timeout_s=timeout,
                   memory_mb=settings.tool_memory_mb, log=logs / "androguard-decompile.log", cancel=cancel)
    result: dict[str, Any] = {"tool": "androguard", **res}
    if res["status"] == "ok":
        result["produced"] = {"java_sources": sum(1 for _ in out.rglob("*.java"))}
    return result


_SIGNER_RE = re.compile(r"^Signer #(\d+) certificate (DN|SHA-256 digest): (.+)$")


def apksigner_verify(apk: Path, settings: Settings, logs: Path, label: str,
                     guard: Guard | None = None) -> dict[str, Any]:
    """Assinatura e certificados do APK com o apksigner do Android SDK. Só lê o arquivo."""
    binary = resolve(SPECS_BY_KEY["apksigner"])
    if binary is None:
        return {"tool": "apksigner", "status": "missing", "reason": "apksigner não instalado; etapa não executada"}
    out = logs / f"apksigner-{label}.txt"
    timeout = settings.tool_timeout_s
    cancel = None
    if guard is not None:
        timeout = min(timeout, guard.remaining())
        cancel = guard.cancel
    res = run_tool([binary, "verify", "--print-certs", str(apk)], cwd=logs, timeout_s=timeout,
                   memory_mb=settings.tool_memory_mb, log=logs / f"apksigner-{label}.log",
                   stdout_file=out, cancel=cancel)
    text = out.read_text(encoding="utf-8", errors="replace") if out.exists() else ""
    log_text = (logs / f"apksigner-{label}.log").read_text(encoding="utf-8", errors="replace") \
        if (logs / f"apksigner-{label}.log").exists() else ""
    combined = text + "\n" + log_text
    if res["status"] == "timeout" or res["status"] == "cancelled":
        return {"tool": "apksigner", **res}
    signers: dict[int, dict[str, str]] = {}
    for line in text.splitlines():
        m = _SIGNER_RE.match(line.strip())
        if m:
            entry = signers.setdefault(int(m.group(1)), {})
            entry["dn" if m.group(2) == "DN" else "sha256"] = m.group(3)
    # Sucesso do 'apksigner verify' não imprime "Verifies": sai com código 0 e lista os certificados.
    if res["status"] == "ok" and signers:
        return {"tool": "apksigner", "status": "ok", "verified": True,
                "signers": [signers[k] for k in sorted(signers)]}
    if "DOES NOT VERIFY" in combined:
        reasons = [ln.strip() for ln in combined.splitlines() if ln.strip().startswith(("ERROR", "DOES NOT"))]
        return {"tool": "apksigner", "status": "ok", "verified": False, "signers": [],
                "reasons": reasons[:5] or ["APK sem assinatura válida"]}
    return {"tool": "apksigner", **res, "status": "failed",
            "reason": "saída do apksigner não reconhecida; ver o log"}


def radare2_functions(path: Path, settings: Settings, logs: Path, label: str,
                      guard: Guard | None = None) -> dict[str, Any]:
    """Funções e símbolos de uma biblioteca nativa com o radare2 (análise automática, somente leitura)."""
    binary = resolve(SPECS_BY_KEY["radare2"])
    if binary is None:
        return {"tool": "radare2", "status": "missing", "reason": "radare2 não instalado; etapa não executada"}
    result = _run_for_json("radare2", [binary, "-q", "-c", "aaa; aflj", str(path)], settings, logs, label, guard)
    if result["status"] != "ok":
        return result
    try:
        funcs = json.loads((logs / f"radare2-{label}.json").read_text(encoding="utf-8") or "[]")
    except ValueError as exc:
        return {**result, "status": "failed", "reason": f"saída do radare2 inválida: {exc}"}
    names = [f.get("name", "") for f in funcs if isinstance(f, dict)]
    return {**result, "result": {
        "functions": len(names),
        "names": names[:200],
        "exported": [n for n in names if n.startswith("sym.") and not n.startswith("sym.imp.")][:100],
    }}


def monodis_disassemble(assembly: Path, out_dir: Path, settings: Settings, logs: Path,
                        guard: Guard | None = None) -> dict[str, Any]:
    """Desmontagem IL de um assembly .NET com o monodis. A saída é IL, não C#."""
    binary = resolve(SPECS_BY_KEY["monodis"])
    if binary is None:
        return {"tool": "monodis", "status": "missing", "reason": "monodis não instalado; etapa não executada"}
    out_dir.mkdir(parents=True, exist_ok=True)
    il = out_dir / "assembly.il"
    timeout = settings.tool_timeout_s
    cancel = None
    if guard is not None:
        timeout = min(timeout, guard.remaining())
        cancel = guard.cancel
    res = run_tool([binary, str(assembly)], cwd=logs, timeout_s=timeout, memory_mb=settings.tool_memory_mb,
                   log=logs / "monodis.log", stdout_file=il, cancel=cancel)
    result: dict[str, Any] = {"tool": "monodis", **res}
    log_text = (logs / "monodis.log").read_text(encoding="utf-8", errors="replace") \
        if (logs / "monodis.log").exists() else ""
    # O monodis reporta arquivo que não é .NET no stderr ('Error while trying to process ...'),
    # às vezes com código 0 e às vezes com código 1. Esse texto vale mais que o código de saída.
    not_dotnet = "Error while trying to process" in log_text
    if not_dotnet:
        return {**result, "status": "failed", "reason": "arquivo não é um assembly .NET reconhecido pelo monodis"}
    if res["status"] != "ok":
        last = next((ln for ln in reversed(log_text.splitlines()) if ln.strip()), "")
        result["reason"] = f"monodis terminou com status {res['status']}: {last[:200]}".rstrip(": ")
        return result
    text = il.read_text(encoding="utf-8", errors="replace") if il.exists() else ""
    if "Error while trying to process" in text:
        return {**result, "status": "failed", "reason": "arquivo não é um assembly .NET reconhecido pelo monodis"}
    result["produced"] = {"il_lines": text.count("\n"), "methods": text.count(".method ")}
    return result
