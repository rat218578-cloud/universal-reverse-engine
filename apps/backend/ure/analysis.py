"""Pipeline de análise. Verifica integridade, faz triagem, extrai com segurança, chama motores
disponíveis, varre segredos e grava reports/analysis.json. O arquivo analisado nunca é executado."""
from __future__ import annotations

import dataclasses
import json
import re
import shutil
from pathlib import Path
from typing import Any

from .engines import apkanalyzer_manifest, apktool_decode, ghidra_analyze, ilspy_decompile, jadx_decompile
from .files import sha256_file
from .identify import KIND_APK, KIND_JAR, KIND_PE, KIND_ZIP
from .pe import parse_pe
from .safezip import safe_extract_zip
from .secrets import scan_secrets
from .tools import probe_all

SUSPICIOUS_IMPORTS = frozenset({
    "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory", "OpenProcess",
    "URLDownloadToFileA", "URLDownloadToFileW", "WinExec", "ShellExecuteA", "ShellExecuteW",
    "SetWindowsHookExA", "SetWindowsHookExW", "IsDebuggerPresent", "NtQueryInformationProcess",
})
DEX_TOP = re.compile(r"classes\d*\.dex")
CONTAINER_KINDS = frozenset({KIND_APK, KIND_JAR, KIND_ZIP})
INDICATOR_NOTE = "indicador estático: não comprova comportamento malicioso"


class IntegrityError(RuntimeError):
    pass


def _skipped(reason: str) -> dict[str, Any]:
    return {"status": "skipped", "reason": reason}


def run_analysis(app: Any, pid: str, aid: str, params: dict[str, Any], progress: Any) -> dict[str, Any]:
    art = app.artifact_or_404(pid, aid)
    s = app.settings
    root = app.root_of(pid, aid)
    original = root / "original" / art["filename"]
    if not original.is_file():
        raise FileNotFoundError("arquivo original ausente")
    progress(0.02, "verificando integridade (SHA-256)")
    if sha256_file(original) != art["sha256"]:
        raise IntegrityError("hash do original não confere com o registrado")
    logs = root / "reports" / "logs"
    logs.mkdir(parents=True, exist_ok=True)
    deep = bool(params.get("deep"))
    report: dict[str, Any] = {
        "artifact_id": aid,
        "kind": art["kind"],
        "filename": art["filename"],
        "sha256": art["sha256"],
        "integrity": "ok",
        "deep_analysis": deep,
        "tools": [{"key": t["key"], "status": t["status"], "version": t["version"]} for t in probe_all()],
        "engines": {},
        "dependencies": {},
        "indicators": [],
    }
    if art["kind"] == KIND_PE:
        _analyze_pe(root, original, s, logs, report, progress, deep)
    elif art["kind"] in CONTAINER_KINDS:
        _analyze_container(root, original, art, s, logs, report, progress)
    progress(0.92, "varredura de segredos")
    extracted = root / "extracted"
    report["secrets"] = (
        scan_secrets(extracted) if extracted.is_dir() else {"files_scanned": 0, "findings": [], "truncated": False}
    )
    out = root / "reports" / "analysis.json"
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    progress(1.0, "relatório gerado")
    return {
        "report": "reports/analysis.json",
        "engines": {k: v.get("status") for k, v in report["engines"].items()},
        "secret_findings": len(report["secrets"]["findings"]),
        "indicators": len(report["indicators"]),
    }


def _analyze_pe(root: Path, original: Path, s: Any, logs: Path, report: dict[str, Any], progress: Any, deep: bool) -> None:
    progress(0.1, "análise PE: cabeçalhos, seções e importações")
    pe = parse_pe(original)
    (root / "reports" / "pe.json").write_text(json.dumps(pe, ensure_ascii=False, indent=2), encoding="utf-8")
    imports = pe["imports"]
    report["dependencies"] = {
        "format": pe["format"],
        "imported_dlls": {dll: len(names) for dll, names in imports.items()},
        "signed": pe["signed"],
        "clr_runtime": pe["clr_runtime"],
        "overlay_bytes": pe["overlay_bytes"],
    }
    for fn in sorted({n for names in imports.values() for n in names if n in SUSPICIOUS_IMPORTS}):
        report["indicators"].append({"type": "import", "value": fn, "note": INDICATOR_NOTE})
    if pe["clr_runtime"]:
        progress(0.4, "descompilação .NET (ILSpy)")
        report["engines"]["ilspycmd"] = ilspy_decompile(original, root / "decompiled" / "ilspy", s, logs)
    elif deep:
        progress(0.4, "análise nativa (Ghidra headless)")
        report["engines"]["ghidra"] = ghidra_analyze(original, s, logs)
    else:
        report["engines"]["ghidra"] = _skipped("análise profunda não solicitada (deep=true)")


def _analyze_container(root: Path, original: Path, art: dict[str, Any], s: Any, logs: Path,
                       report: dict[str, Any], progress: Any) -> None:
    progress(0.08, "extração segura")
    extracted = root / "extracted"
    if not extracted.is_dir() or not any(extracted.iterdir()):
        shutil.rmtree(extracted, ignore_errors=True)
        extracted.mkdir(parents=True)
        rep = safe_extract_zip(
            original, extracted,
            max_entries=s.max_entries, max_total_bytes=s.max_extract_bytes, max_ratio=s.max_ratio,
        )
        report["extraction"] = dataclasses.asdict(rep)
    names = sorted(p.relative_to(extracted).as_posix() for p in extracted.rglob("*") if p.is_file())
    natives = [n for n in names if n.startswith("lib/") and n.endswith(".so")]
    report["dependencies"] = {
        "dex_files": [n for n in names if DEX_TOP.fullmatch(n)],
        "native_libraries": len(natives),
        "abis": sorted({n.split("/")[1] for n in natives}),
        "signature_files": [n for n in names if n.startswith("META-INF/") and n.rsplit(".", 1)[-1] in ("RSA", "DSA", "EC", "SF")],
        "embedded_jars": [n for n in names if n.endswith(".jar")],
        "has_android_manifest": "AndroidManifest.xml" in names,
    }
    is_apk = art["kind"] == KIND_APK
    progress(0.25, "apktool (decodificação)")
    report["engines"]["apktool"] = (
        apktool_decode(original, root / "decompiled" / "apktool", s, logs) if is_apk else _skipped("não é APK")
    )
    progress(0.5, "JADX (descompilação DEX)")
    report["engines"]["jadx"] = (
        jadx_decompile(original, root / "decompiled" / "jadx", s, logs)
        if is_apk and report["dependencies"]["dex_files"] else _skipped("sem DEX ou não é APK")
    )
    progress(0.75, "apkanalyzer (manifesto)")
    report["engines"]["apkanalyzer"] = (
        apkanalyzer_manifest(original, root / "reports" / "apkanalyzer-manifest.xml", s, logs)
        if is_apk else _skipped("não é APK")
    )
    if is_apk and not report["dependencies"]["has_android_manifest"]:
        report["indicators"].append({"type": "structure", "value": "AndroidManifest.xml ausente", "note": INDICATOR_NOTE})
