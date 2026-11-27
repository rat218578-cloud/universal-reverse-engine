"""Fluxo completo com ferramentas reais: upload, extração, Apktool, LIEF, relatório.

Os casos usam o APK real de tests/fixtures/real. Quando uma ferramenta não está instalada no
servidor, o teste exige que o relatório registre o motivo (status 'missing'); nenhum resultado é
simulado. O LIEF é procurado em URE_LIEF_PYTHON, depois no interpretador do teste.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import time
import unittest
from pathlib import Path
from unittest import mock

import warnings

from tests.helpers import make_zip, native_fixture_bytes, real_apk_entries
from tests.test_api import ApiCase
from ure.tools import SPECS_BY_KEY, load_tools_env, probe_all, resolve

load_tools_env()  # respeita URE_TOOLS_ENV / tools.env instalado pelo script
# zipfile avisa ao gravar nomes repetidos: as duplicatas destes testes são intencionais.
warnings.filterwarnings("ignore", message="Duplicate name", category=UserWarning)
LIEF_PY_CANDIDATES = (os.environ.get("URE_LIEF_PYTHON"), "/opt/ure-tools/venv/bin/python", sys.executable)


def _lief_python() -> str | None:
    for py in LIEF_PY_CANDIDATES:
        if py and os.path.isfile(py) and os.access(py, os.X_OK):
            import subprocess
            ok = subprocess.run([py, "-c", "import lief"], capture_output=True, timeout=60).returncode == 0
            if ok:
                return py
    return None


LIEF_PY = _lief_python()
HAS_APKTOOL = resolve(SPECS_BY_KEY["apktool"]) is not None
HAS_JADX = resolve(SPECS_BY_KEY["jadx"]) is not None
_STATE = {r["key"]: r["status"] for r in probe_all()}
HAS_ANDROGUARD = _STATE.get("androguard") == "available"
HAS_APKSIGNER = _STATE.get("apksigner") == "available"
HAS_R2 = _STATE.get("radare2") == "available"
FIXTURES_DOTNET = Path(__file__).parent / "fixtures" / "dotnet"


class RealApkFlowTests(ApiCase):
    def setUp(self) -> None:
        self._env = mock.patch.dict(os.environ, {"URE_LIEF_PYTHON": LIEF_PY} if LIEF_PY else {})
        self._env.start()
        super().setUp()

    def tearDown(self) -> None:
        super().tearDown()
        self._env.stop()

    def wait_job(self, jid: str, timeout: float = 240.0) -> dict:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            _, job = self.js("GET", f"/api/v1/jobs/{jid}")
            if job["status"] not in ("queued", "running"):
                return job
            time.sleep(0.3)
        self.fail("job não terminou no tempo esperado")

    def upload_and_analyze(self, data: bytes, filename: str = "app.apk") -> tuple[str, str, dict]:
        pid = self.new_project()
        status, art = self._upload_raw(pid, filename, data)
        self.assertEqual(status, 201, art)
        status, job = self.js("POST", f"/api/v1/projects/{pid}/artifacts/{art['id']}/analyze", {})
        self.assertEqual(status, 202)
        job = self.wait_job(job["id"])
        self.assertEqual(job["status"], "done", job.get("error"))
        _, report = self.js("GET", f"/api/v1/projects/{pid}/artifacts/{art['id']}/report")
        return pid, art["id"], report

    @unittest.skipUnless(HAS_APKTOOL, "apktool não instalado neste servidor")
    def test_apktool_decodes_manifest_resources_and_smali(self) -> None:
        apk = make_zip(self.tmp / "real.apk", real_apk_entries())
        _, _, report = self.upload_and_analyze(apk.read_bytes())
        engine = report["engines"]["apktool"]
        if engine["status"] != "ok":
            # Mostra a saída real do Apktool, sem a qual a falha no CI não é diagnosticável.
            logs = [p for p in Path(self.settings.data_dir).rglob("apktool.log")]
            tail = logs[0].read_text(encoding="utf-8", errors="replace")[-2000:] if logs else "(log ausente)"
            self.fail(f"apktool não decodificou o APK: {engine}\n--- apktool.log (fim) ---\n{tail}")
        self.assertTrue(engine["produced"]["manifest_xml"])
        self.assertTrue(engine["produced"]["resources"])
        self.assertGreaterEqual(engine["produced"]["smali_dirs"], 1)
        manifest = (Path(self.tmp) / "data").rglob("AndroidManifest.xml")
        texts = [p.read_text(encoding="utf-8", errors="replace") for p in manifest]
        self.assertTrue(any("com.ure.fixture" in t for t in texts), "manifesto decodificado deve conter o pacote")

    @unittest.skipIf(HAS_JADX, "JADX presente: caso de ausência não se aplica")
    def test_missing_jadx_is_registered_with_reason_not_simulated(self) -> None:
        apk = make_zip(self.tmp / "real.apk", real_apk_entries())
        _, _, report = self.upload_and_analyze(apk.read_bytes())
        engine = report["engines"]["jadx"]
        self.assertEqual(engine["status"], "missing")
        self.assertIn("não instalada", engine["reason"])
        self.assertNotIn("produced", engine)

    @unittest.skipUnless(LIEF_PY, "LIEF não importa em nenhum interpretador configurado")
    def test_lief_reads_native_library_and_dex_from_extracted_apk(self) -> None:
        entries = real_apk_entries() + [("lib/x86_64/libfixture.so", native_fixture_bytes(), None)]
        apk = make_zip(self.tmp / "native.apk", entries)
        _, _, report = self.upload_and_analyze(apk.read_bytes())
        self.assertEqual(report["engines"]["lief"]["status"], "ok", report["engines"]["lief"])
        items = {i["path"]: i for i in report["structures"]}
        native = items["lib/x86_64/libfixture.so"]
        self.assertEqual(native["status"], "ok")
        self.assertEqual(native["result"]["format"], "ELF")
        self.assertIn("ure_fixture_add", native["result"]["exported_symbols"])
        dex = items["classes.dex"]
        self.assertEqual(dex["status"], "ok")
        names = dex["result"]["dex_files"][0]["class_names"]
        self.assertIn("Lcom/ure/fixture/Main;", names)
        self.assertEqual(report["dependencies"]["native_libraries"], 1)
        self.assertEqual(report["dependencies"]["abis"], ["x86_64"])

    def test_conflicting_duplicates_are_reported_and_analysis_continues(self) -> None:
        entries = real_apk_entries() + [("res/yHu.xml", b"<a/>", None), ("res/yHu.xml", b"<b/>", None)]
        apk = make_zip(self.tmp / "dup.apk", entries)
        _, _, report = self.upload_and_analyze(apk.read_bytes())
        self.assertEqual(report["extraction"]["status"], "ok")
        dup = [d for d in report["extraction"]["duplicates"] if d["name"] == "res/yHu.xml"][0]
        self.assertEqual(dup["status"], "conflitante")
        self.assertIsNone(dup["kept"])
        self.assertEqual(len(dup["quarantined"]), 2)
        self.assertTrue(any(i["type"] == "archive" and "res/yHu.xml" in i["value"] for i in report["indicators"]))
        # a análise prosseguiu: o Apktool foi executado (não marcado como recusado)
        self.assertNotIn("extração recusada", report["engines"]["apktool"].get("reason", ""))
        self.assertIn("inventory", report)
        self.assertEqual(report["inventory"]["duplicates"][0]["crc_and_size"], "diferentes")

    def test_androguard_apksigner_and_radare2_are_in_the_report(self) -> None:
        entries = real_apk_entries() + [("lib/x86_64/libfixture.so", native_fixture_bytes(), None)]
        apk = make_zip(self.tmp / "engines.apk", entries)
        _, _, report = self.upload_and_analyze(apk.read_bytes())
        eng = report["engines"]
        if LIEF_PY is None and not HAS_APKSIGNER:
            self.skipTest("nenhum dos motores novos disponível")
        self.assertEqual(eng["apksigner"]["status"], "ok", eng["apksigner"])
        self.assertFalse(eng["apksigner"]["verified"])  # fixture não assinado: resultado real
        if HAS_ANDROGUARD:
            self.assertEqual(eng["androguard"]["status"], "ok", eng["androguard"])
            self.assertEqual(eng["androguard"]["result"]["package"], "com.ure.fixture")
            self.assertEqual(eng["androguard_decompile"]["status"], "ok", eng["androguard_decompile"])
            self.assertGreaterEqual(eng["androguard_decompile"]["produced"]["java_sources"], 1)
        if HAS_R2:
            self.assertEqual(eng["radare2"]["status"], "ok", eng["radare2"])
            native = [i for i in report["native_functions"] if i["path"] == "lib/x86_64/libfixture.so"][0]
            self.assertIn("sym.ure_fixture_add", native["result"]["names"])

    def test_dotnet_assembly_upload_runs_monodis_and_reports_ilspy_missing(self) -> None:
        data = (FIXTURES_DOTNET / "UreSample.dll").read_bytes()
        _, _, report = self.upload_and_analyze(data, filename="UreSample.dll")
        self.assertTrue(report["dependencies"].get("clr_runtime"), report["dependencies"])
        mono = report["engines"]["monodis"]
        if _STATE.get("monodis") == "available":
            self.assertEqual(mono["status"], "ok", mono)
            self.assertIn("Calc::Add", next(Path(self.settings.data_dir).rglob("assembly.il")).read_text(encoding="utf-8"))
        ilspy = report["engines"]["ilspycmd"]
        self.assertEqual(ilspy["status"], "missing", ilspy)  # ILSpy não instalado neste servidor

    def test_identical_duplicates_are_deduplicated_and_analysis_completes(self) -> None:
        entries = real_apk_entries() + [("res/yHu.xml", b"<x/>", None), ("res/yHu.xml", b"<x/>", None)]
        apk = make_zip(self.tmp / "same.apk", entries)
        _, _, report = self.upload_and_analyze(apk.read_bytes())
        self.assertEqual(report["extraction"]["status"], "ok", report["extraction"])
        dup = [d for d in report["extraction"]["duplicates"] if d["name"] == "res/yHu.xml"][0]
        self.assertEqual(dup["status"], "identica")
        self.assertEqual(dup["occurrences"], 2)
        self.assertEqual(dup["quarantined"], [])
        self.assertEqual(dup["kept"], "res/yHu.xml")
        self.assertFalse([i for i in report["indicators"] if "conflito de conteúdo" in i["value"]])
        self.assertEqual(report["inventory"]["duplicates"][0]["crc_and_size"], "iguais")

    def test_many_duplicate_groups_in_one_apk_are_each_classified(self) -> None:
        entries = real_apk_entries() + [
            ("res/a.xml", b"<same/>", None), ("res/a.xml", b"<same/>", None),          # idênticas
            ("res/b.xml", b"<one/>", None), ("res/b.xml", b"<two/>", None),            # conflitantes
            ("res/c.xml", b"<p/>", None), ("res/c.xml", b"<q/>", None), ("res/c.xml", b"<r/>", None),
            ("res/d.xml", b"<k/>", None), ("res/d.xml", b"<k/>", None), ("res/d.xml", b"<k/>", None),
        ]
        apk = make_zip(self.tmp / "many.apk", entries)
        _, _, report = self.upload_and_analyze(apk.read_bytes())
        self.assertEqual(report["extraction"]["status"], "ok", report["extraction"])
        by_name = {d["name"]: d for d in report["extraction"]["duplicates"]}
        self.assertEqual(set(by_name), {"res/a.xml", "res/b.xml", "res/c.xml", "res/d.xml"})
        self.assertEqual(by_name["res/a.xml"]["status"], "identica")
        self.assertEqual(by_name["res/d.xml"]["status"], "identica")
        self.assertEqual(by_name["res/d.xml"]["occurrences"], 3)
        for name, copies in (("res/b.xml", 2), ("res/c.xml", 3)):
            self.assertEqual(by_name[name]["status"], "conflitante", name)
            self.assertIsNone(by_name[name]["kept"], name)
            self.assertEqual(len(by_name[name]["quarantined"]), copies, name)
            self.assertEqual(len(set(by_name[name]["sha256"])), copies, name)
        conflicts = sorted(i["value"] for i in report["indicators"] if "conflito de conteúdo" in i["value"])
        self.assertEqual(conflicts, ["conflito de conteúdo: res/b.xml", "conflito de conteúdo: res/c.xml"])
        inv = {d["name"]: d["crc_and_size"] for d in report["inventory"]["duplicates"]}
        self.assertEqual(inv, {"res/a.xml": "iguais", "res/b.xml": "diferentes",
                               "res/c.xml": "diferentes", "res/d.xml": "iguais"})
        self.assertNotIn("extração recusada", report["engines"]["apktool"].get("reason", ""))

    def test_unsafe_entry_blocks_decompilers_but_keeps_safe_inventory(self) -> None:
        entries = real_apk_entries() + [("../evil.txt", b"x", None)]
        apk = make_zip(self.tmp / "unsafe.apk", entries)
        _, _, report = self.upload_and_analyze(apk.read_bytes())
        self.assertEqual(report["extraction"]["status"], "failed")
        self.assertEqual(report["engines"]["apktool"]["status"], "skipped")
        self.assertIn("decompilador não executado", report["engines"]["apktool"]["reason"])
        self.assertEqual(report["engines"]["jadx"]["status"], "skipped")
        self.assertEqual(report["engines"]["lief"]["status"], "skipped")
        self.assertEqual(report["inventory"]["unsafe_entries"][0]["name"], "../evil.txt")
        self.assertEqual(report["dependencies"]["source"], "inventario")
        self.assertIn("classes.dex", report["dependencies"]["dex_files"])
        self.assertFalse((Path(self.settings.data_dir) / "evil.txt").exists())

    def test_corrupted_zip_is_rejected_or_analyzed_without_server_error(self) -> None:
        data = b"PK\x03\x04" + os.urandom(3000)
        pid = self.new_project()
        status, art = self._upload_raw(pid, "broken.apk", data)
        self.assertLess(status, 500, art)
        if status == 201:
            _, job = self.js("POST", f"/api/v1/projects/{pid}/artifacts/{art['id']}/analyze", {})
            job = self.wait_job(job["id"])
            self.assertIn(job["status"], ("done", "failed"))
            if job["status"] == "done":
                _, report = self.js("GET", f"/api/v1/projects/{pid}/artifacts/{art['id']}/report")
                self.assertEqual(report["extraction"]["status"], "failed")

    def test_original_apk_bytes_are_preserved_after_analysis(self) -> None:
        entries = real_apk_entries() + [("res/yHu.xml", b"<a/>", None), ("res/yHu.xml", b"<b/>", None)]
        apk = make_zip(self.tmp / "keep.apk", entries)
        raw = apk.read_bytes()
        pid, aid, _ = self.upload_and_analyze(raw)
        # O servidor guarda o original sob um nome próprio: a prova é o conteúdo idêntico.
        digest = hashlib.sha256(raw).hexdigest()
        stored = [p for p in Path(self.settings.data_dir).rglob("*")
                  if p.is_file() and hashlib.sha256(p.read_bytes()).hexdigest() == digest]
        self.assertTrue(stored, "o APK original, byte a byte, deve continuar armazenado")


if __name__ == "__main__":
    unittest.main()
