"""Pipeline de análise. Verifica integridade, faz triagem, extrai com segurança, chama motores
disponíveis, varre segredos e grava reports/analysis.json. O arquivo analisado nunca é executado.

Concorrência: o artefato é protegido por lock durante a análise. A extração é refeita do zero a cada
análise (nunca reaproveita diretório parcial). Tempo limite e cancelamento são verificados via Guard.
"""
from __future__ import annotations

import dataclasses
import json
import re
import shutil
import zipfile
from pathlib import Path
from typing import Any

from .compliance import scan_licenses, size_summary
from .engines import (androguard_decompile, androguard_summary, apkanalyzer_manifest, apksigner_verify,
                      apktool_decode, ghidra_analyze, ilspy_decompile, jadx_decompile, lief_inspect,
                      monodis_disassemble, radare2_functions)
from .files import sha256_file
from .identify import KIND_APK, KIND_JAR, KIND_PE, KIND_ZIP
from .jobs import BusyError
from .limits import Guard
from .pe import parse_pe
from .safezip import ArchiveLimitError, UnsafeArchiveError, inventory_zip, safe_extract_zip
from .secrets import scan_secrets
from .tools import probe_all

SUSPICIOUS_IMPORTS = frozenset({
    "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory", "OpenProcess",
    "URLDownloadToFileA", "URLDownloadToFileW", "WinExec", "ShellExecuteA", "ShellExecuteW",
    "SetWindowsHookExA", "SetWindowsHookExW", "IsDebuggerPresent", "NtQueryInformationProcess",
})
DEX_TOP = re.compile(r"classes\d*\.dex")
MAX_LIEF_FILES = 16
CONTAINER_KINDS = frozenset({KIND_APK, KIND_JAR, KIND_ZIP})
INDICATOR_NOTE = "indicador estático: não comprova comportamento malicioso"
LOCK_WAIT_S = 60.0


class IntegrityError(RuntimeError):
    """Hash do original não confere com o registrado."""


def _skipped(reason: str) -> dict[str, Any]:
    return {"status": "skipped", "reason": reason}


def run_analysis(app: Any, pid: str, aid: str, params: dict[str, Any], guard: Guard) -> dict[str, Any]:
    lock = app.artifact_lock(aid)
    wait = min(LOCK_WAIT_S, guard.remaining())
    if not lock.acquire(timeout=wait):
        raise BusyError("artefato em uso por outro processamento")
    try:
        return _run(app, pid, aid, params, guard)
    finally:
        lock.release()


def _run(app: Any, pid: str, aid: str, params: dict[str, Any], guard: Guard) -> dict[str, Any]:
    progress = guard.step
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
        "artifact_id": aid, "kind": art["kind"], "filename": art["filename"], "sha256": art["sha256"],
        "integrity": "ok", "deep_analysis": deep,
        "tools": [{"key": t["key"], "status": t["status"], "version": t["version"]} for t in probe_all()],
        "engines": {}, "dependencies": {}, "indicators": [],
    }
    if art["kind"] == KIND_PE:
        _analyze_pe(root, original, s, logs, report, progress, deep, guard)
    elif art["kind"] in CONTAINER_KINDS:
        _analyze_container(root, original, art, s, logs, report, progress, guard)
    progress(0.92, "varredura de segredos")
    extracted = root / "extracted"
    report["secrets"] = (
        scan_secrets(extracted, guard) if extracted.is_dir()
        else {"files_scanned": 0, "findings": [], "truncated": False}
    )
    if extracted.is_dir():
        report["compliance"] = {
            "licenses": scan_licenses(extracted),
            "size": size_summary(extracted),
            "limit_bytes": s.max_extract_bytes,
        }
    guard.check()
    out = root / "reports" / "analysis.json"
    out.write_text(json.dumps(report, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    progress(1.0, "relatório gerado")
    return {
        "report": "reports/analysis.json",
        "engines": {k: v.get("status") for k, v in report["engines"].items()},
        "secret_findings": len(report["secrets"]["findings"]),
        "indicators": len(report["indicators"]),
    }


def _analyze_pe(root: Path, original: Path, s: Any, logs: Path, report: dict[str, Any],
                progress: Any, deep: bool, guard: Guard) -> None:
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
    report["engines"]["lief"] = lief_inspect(original, s, logs, "pe", guard)
    if not pe["clr_runtime"]:
        progress(0.3, "funções nativas (radare2)")
        report["engines"]["radare2"] = radare2_functions(original, s, logs, "pe", guard)
    if pe["clr_runtime"]:
        progress(0.4, "descompilação .NET (ILSpy)")
        report["engines"]["ilspycmd"] = ilspy_decompile(original, root / "decompiled" / "ilspy", s, logs, guard)
        report["engines"]["monodis"] = monodis_disassemble(original, root / "decompiled" / "monodis", s, logs, guard)
    elif deep:
        progress(0.4, "análise nativa (Ghidra headless)")
        report["engines"]["ghidra"] = ghidra_analyze(original, s, logs, guard)
    else:
        report["engines"]["ghidra"] = _skipped("análise profunda não solicitada (deep=true)")


def _analyze_container(root: Path, original: Path, art: dict[str, Any], s: Any, logs: Path,
                       report: dict[str, Any], progress: Any, guard: Guard) -> None:
    # Inventário do diretório central: não grava nada e continua disponível mesmo se a
    # extração falhar. Duplicatas e nomes inseguros aparecem aqui antes de qualquer extração.
    progress(0.05, "inventário do diretório central")
    try:
        report["inventory"] = inventory_zip(original, max_entries=s.max_entries)
    except (zipfile.BadZipFile, ArchiveLimitError) as exc:
        report["inventory"] = {"status": "failed", "error": type(exc).__name__, "reason": str(exc)}
    inventory_ok = report.get("inventory", {}).get("status") != "failed"
    for dup in (report.get("inventory") or {}).get("duplicates", []):
        report["indicators"].append({"type": "archive", "value": f"nome repetido: {dup['name']}",
                                     "note": f"ocorrências: {dup['occurrences']}; conteúdo: {dup['crc_and_size']}"})

    progress(0.08, "extração segura")
    extracted = root / "extracted"
    shutil.rmtree(extracted, ignore_errors=True)
    failure: Exception | None = None
    try:
        rep = safe_extract_zip(
            original, extracted,
            max_entries=s.max_entries, max_total_bytes=s.max_extract_bytes, max_ratio=s.max_ratio,
            guard=guard, quarantine=root / "quarantine",
        )
        report["extraction"] = {"status": "ok", **dataclasses.asdict(rep)}
        for dup in rep.duplicates:
            if dup["status"] == "conflitante":
                report["indicators"].append({"type": "archive", "value": f"conflito de conteúdo: {dup['name']}",
                                             "note": "nenhuma versão foi usada; cópias em quarentena"})
    except (UnsafeArchiveError, ArchiveLimitError, zipfile.BadZipFile) as exc:
        failure = exc
        report["extraction"] = {"status": "failed", "error": type(exc).__name__, "reason": str(exc)}

    if failure is None:
        names = sorted(p.relative_to(extracted).as_posix() for p in extracted.rglob("*") if p.is_file())
    else:
        names = (report.get("inventory") or {}).get("names", []) if inventory_ok else []
    natives = [n for n in names if n.startswith("lib/") and n.endswith(".so")]
    report["dependencies"] = {
        "dex_files": [n for n in names if DEX_TOP.fullmatch(n)],
        "native_libraries": len(natives),
        "abis": sorted({n.split("/")[1] for n in natives}),
        "signature_files": [n for n in names if n.startswith("META-INF/")
                            and n.rsplit(".", 1)[-1] in ("RSA", "DSA", "EC", "SF")],
        "embedded_jars": [n for n in names if n.endswith(".jar")],
        "has_android_manifest": "AndroidManifest.xml" in names,
        "source": "extraido" if failure is None else ("inventario" if inventory_ok else "indisponivel"),
    }
    is_apk = art["kind"] == KIND_APK
    # LIEF lê as bibliotecas e o DEX já extraídos; sem extração aceita, não é executado.
    if failure is None:
        natives = [n for n in names if n.startswith("lib/") and n.endswith(".so")][:MAX_LIEF_FILES]
        dexes = report["dependencies"]["dex_files"][:MAX_LIEF_FILES]
        items = []
        for i, name in enumerate([*natives, *dexes]):
            res = lief_inspect(extracted / name, s, logs, f"item-{i}", guard)
            items.append({"path": name, **res})
        report["structures"] = items
        statuses = {it["status"] for it in items}
        report["engines"]["lief"] = {
            "tool": "lief",
            "status": ("missing" if "missing" in statuses else "failed" if "failed" in statuses
                       else "ok" if items else "skipped"),
            "items": len(items),
        }
    else:
        report["engines"]["lief"] = _skipped(f"extração recusada ({type(failure).__name__}): LIEF não executado")
    # radare2 nas bibliotecas nativas extraídas (somente leitura), com o mesmo limite do LIEF.
    if failure is None and natives:
        progress(0.3, "funções nativas (radare2)")
        r2_items = []
        for i, name in enumerate(natives[:MAX_LIEF_FILES]):
            r2_items.append({"path": name, **radare2_functions(extracted / name, s, logs, f"native-{i}", guard)})
        report["native_functions"] = r2_items
        r2_statuses = {it["status"] for it in r2_items}
        report["engines"]["radare2"] = {
            "tool": "radare2",
            "status": ("missing" if "missing" in r2_statuses else "failed" if "failed" in r2_statuses
                       else "ok" if r2_items else "skipped"),
            "items": len(r2_items),
        }
    elif failure is None:
        report["engines"]["radare2"] = _skipped("sem bibliotecas nativas no APK")
    else:
        report["engines"]["radare2"] = _skipped(f"extração recusada ({type(failure).__name__}): radare2 não executado")
    if is_apk:
        progress(0.32, "assinatura e certificados (apksigner)")
        report["engines"]["apksigner"] = apksigner_verify(original, s, logs, "apk", guard)
    # Decompiladores escrevem a partir do conteúdo do arquivo. Se a extração recusou entradas
    # inseguras ou excedeu limites, eles não são executados; o motivo fica registrado.
    blocked = (f"extração recusada ({type(failure).__name__}): decompilador não executado"
               if failure is not None else None)
    progress(0.25, "apktool (decodificação)")
    if blocked is not None:
        report["engines"]["apktool"] = _skipped(blocked)
    else:
        report["engines"]["apktool"] = (
            apktool_decode(original, root / "decompiled" / "apktool", s, logs, guard) if is_apk
            else _skipped("não é APK")
        )
    progress(0.5, "JADX (descompilação DEX)")
    if blocked is not None:
        report["engines"]["jadx"] = _skipped(blocked)
    else:
        report["engines"]["jadx"] = (
            jadx_decompile(original, root / "decompiled" / "jadx", s, logs, guard)
            if is_apk and report["dependencies"]["dex_files"] else _skipped("sem DEX ou não é APK")
        )
    progress(0.6, "Androguard (manifesto e classes)")
    if blocked is not None:
        report["engines"]["androguard"] = _skipped(blocked)
        report["engines"]["androguard_decompile"] = _skipped(blocked)
    elif is_apk:
        report["engines"]["androguard"] = androguard_summary(original, s, logs, "apk", guard)
        if report["dependencies"]["dex_files"]:
            report["engines"]["androguard_decompile"] = androguard_decompile(
                original, root / "decompiled" / "androguard", s, logs, guard)
        else:
            report["engines"]["androguard_decompile"] = _skipped("sem DEX")
    else:
        report["engines"]["androguard"] = _skipped("não é APK")
        report["engines"]["androguard_decompile"] = _skipped("não é APK")
    progress(0.75, "apkanalyzer (manifesto)")
    report["engines"]["apkanalyzer"] = (
        apkanalyzer_manifest(original, root / "reports" / "apkanalyzer-manifest.xml", s, logs, guard)
        if is_apk else _skipped("não é APK")
    )
    if is_apk and not report["dependencies"]["has_android_manifest"]:
        report["indicators"].append({"type": "structure", "value": "AndroidManifest.xml ausente", "note": INDICATOR_NOTE})
