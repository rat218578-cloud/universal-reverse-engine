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

from tests.helpers import make_zip, native_fixture_bytes, real_apk_entries
from tests.test_api import ApiCase
from ure.tools import SPECS_BY_KEY, load_tools_env, resolve

load_tools_env()  # respeita URE_TOOLS_ENV / tools.env instalado pelo script
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
        self.assertEqual(engine["status"], "ok", engine)
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
