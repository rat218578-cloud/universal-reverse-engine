"""Testes da Fase 2: registro de ferramentas, limites de execução, jobs, análise e recuperação."""
from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from tests.helpers import AWS_EXAMPLE_KEY, find_real_pe, synthetic_apk, synthetic_pe32
from tests.test_api import ApiCase
from ure.app import App
from ure.config import Settings
from ure.tools import SPECS_BY_KEY, probe, probe_all, run_tool

AKIA = AWS_EXAMPLE_KEY  # chave de exemplo oficial da AWS, usada apenas para testar a regra


class ToolRegistryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_registry_reports_every_engine(self) -> None:
        keys = {item["key"] for item in probe_all()}
        self.assertTrue({"apktool", "jadx", "apkanalyzer", "ilspycmd", "ghidra", "lief", "java"} <= keys)
        for item in probe_all():
            self.assertIn(item["status"], ("available", "missing"))
            if item["status"] == "missing":
                self.assertTrue(item["note"], "ausente deve explicar o motivo")

    def test_env_override_to_missing_path_is_missing(self) -> None:
        with mock.patch.dict(os.environ, {"URE_APKTOOL": str(self.tmp / "nao-existe")}):
            self.assertEqual(probe(SPECS_BY_KEY["apktool"])["status"], "missing")

    def test_env_override_plumbing_with_stub_binary(self) -> None:
        # Teste de integração do mecanismo de detecção: o binário é um stub de TESTE, não o apktool.
        stub = self.tmp / "stub-tool"
        stub.write_text("#!/bin/sh\necho 'stub-de-teste 0.0'\n")
        stub.chmod(0o755)
        with mock.patch.dict(os.environ, {"URE_APKTOOL": str(stub)}):
            info = probe(SPECS_BY_KEY["apktool"])
        self.assertEqual(info["status"], "available")
        self.assertEqual(info["version"], "stub-de-teste 0.0")

    def test_run_tool_enforces_timeout(self) -> None:
        res = run_tool([sys.executable, "-c", "import time; time.sleep(30)"], cwd=self.tmp,
                       timeout_s=1, memory_mb=512, log=self.tmp / "t.log")
        self.assertEqual(res["status"], "timeout")

    def test_run_tool_enforces_memory_limit(self) -> None:
        res = run_tool([sys.executable, "-c", "x = bytearray(600 * 1024 * 1024); print('alocou')"],
                       cwd=self.tmp, timeout_s=60, memory_mb=256, log=self.tmp / "m.log")
        if not res.get("memory_limit_applied"):
            self.skipTest("limite de memória não aplicável nesta plataforma")
        self.assertEqual(res["status"], "failed")
        self.assertNotIn(b"alocou", (self.tmp / "m.log").read_bytes())

    def test_run_tool_success_records_log(self) -> None:
        res = run_tool([sys.executable, "-c", "print('ok-sem-erro')"], cwd=self.tmp,
                       timeout_s=30, memory_mb=512, log=self.tmp / "s.log")
        self.assertEqual(res["status"], "ok")
        self.assertIn(b"ok-sem-erro", (self.tmp / "s.log").read_bytes())


class AnalysisFlowTests(ApiCase):
    def wait_job(self, jid: str, timeout: float = 90.0) -> dict:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            _, job = self.js("GET", f"/api/v1/jobs/{jid}")
            if job["status"] not in ("queued", "running"):
                return job
            time.sleep(0.2)
        self.fail("job não terminou no tempo esperado")

    def upload_apk_with_secret(self, pid: str) -> dict:
        apk = synthetic_apk(
            self.tmp / "app.apk",
            extra=[("assets/config.txt", f'api_key = "{AKIA}"\n'.encode(), None)],
        )
        status, art = self._upload_raw(pid, "app.apk", apk.read_bytes())
        self.assertEqual(status, 201)
        return art

    def test_apk_analysis_end_to_end(self) -> None:
        pid = self.new_project()
        art = self.upload_apk_with_secret(pid)
        status, job = self.js("POST", f"/api/v1/projects/{pid}/artifacts/{art['id']}/analyze", {})
        self.assertEqual(status, 202)
        job = self.wait_job(job["id"])
        self.assertEqual(job["status"], "done", job.get("error"))
        status, report = self.js("GET", f"/api/v1/projects/{pid}/artifacts/{art['id']}/report")
        self.assertEqual(status, 200)
        self.assertEqual(report["integrity"], "ok")
        self.assertEqual(report["dependencies"]["dex_files"], ["classes.dex"])
        self.assertTrue(report["dependencies"]["has_android_manifest"])
        rules = {f["rule"] for f in report["secrets"]["findings"]}
        self.assertIn("aws-access-key-id", rules)
        for finding in report["secrets"]["findings"]:
            self.assertNotIn(AKIA, json.dumps(finding), "segredo completo não pode aparecer no relatório")
        for key in ("apktool", "jadx", "apkanalyzer"):
            engine = report["engines"][key]
            self.assertIn(engine["status"], ("missing", "ok", "failed", "timeout"))
            if engine["status"] == "missing":
                tool = next(t for t in report["tools"] if t["key"] == key)
                self.assertEqual(tool["status"], "missing", "motor ausente deve estar registrado como ausente")

    def test_sse_emits_progress_and_end(self) -> None:
        pid = self.new_project()
        art = self.upload_apk_with_secret(pid)
        _, job = self.js("POST", f"/api/v1/projects/{pid}/artifacts/{art['id']}/analyze", {})
        status, raw, headers = self.call("GET", f"/api/v1/jobs/{job['id']}/events")
        self.assertEqual(status, 200)
        self.assertIn("text/event-stream", headers.get("Content-Type", ""))
        text = raw.decode("utf-8")
        self.assertIn("event: progress", text)
        self.assertTrue(text.rstrip().endswith("data: {}"), text[-200:])

    def test_integrity_failure_then_retry_after_repair(self) -> None:
        pid = self.new_project()
        art = self.upload_apk_with_secret(pid)
        original = self.settings.data_dir / "projects" / pid / "artifacts" / art["id"] / "original" / "app.apk"
        good = original.read_bytes()
        os.chmod(original, 0o644)
        original.write_bytes(good + b"alterado")
        _, job = self.js("POST", f"/api/v1/projects/{pid}/artifacts/{art['id']}/analyze", {})
        job = self.wait_job(job["id"])
        self.assertEqual(job["status"], "failed")
        self.assertIn("não confere", job["error"])
        os.chmod(original, 0o644)
        original.write_bytes(good)
        os.chmod(original, 0o444)
        status, retry = self.js("POST", f"/api/v1/jobs/{job['id']}/retry")
        self.assertEqual(status, 202)
        self.assertEqual(self.wait_job(retry["id"])["status"], "done")

    def test_retry_of_completed_job_is_refused(self) -> None:
        pid = self.new_project()
        art = self.upload_apk_with_secret(pid)
        _, job = self.js("POST", f"/api/v1/projects/{pid}/artifacts/{art['id']}/analyze", {})
        self.assertEqual(self.wait_job(job["id"])["status"], "done")
        self.assertEqual(self.js("POST", f"/api/v1/jobs/{job['id']}/retry")[0], 409)

    def test_pe_analysis_with_dependencies(self) -> None:
        pid = self.new_project()
        exe = synthetic_pe32(self.tmp / "sample.exe")
        status, art = self._upload_raw(pid, "sample.exe", exe.read_bytes())
        self.assertEqual((status, art["kind"]), (201, "pe"))
        _, job = self.js("POST", f"/api/v1/projects/{pid}/artifacts/{art['id']}/analyze", {})
        self.assertEqual(self.wait_job(job["id"])["status"], "done")
        _, report = self.js("GET", f"/api/v1/projects/{pid}/artifacts/{art['id']}/report")
        self.assertEqual(report["dependencies"]["imported_dlls"], {"KERNEL32.dll": 1})
        self.assertEqual(report["engines"]["ghidra"]["status"], "skipped")
        self.assertEqual(report["indicators"], [])

    def test_real_pe_analysis_runs(self) -> None:
        pe = find_real_pe()
        if pe is None:
            self.skipTest("nenhum PE real disponível")
        pid = self.new_project()
        _, art = self._upload_raw(pid, "w32.exe", pe.read_bytes())
        _, job = self.js("POST", f"/api/v1/projects/{pid}/artifacts/{art['id']}/analyze", {})
        job = self.wait_job(job["id"])
        self.assertEqual(job["status"], "done", job.get("error"))
        _, report = self.js("GET", f"/api/v1/projects/{pid}/artifacts/{art['id']}/report")
        self.assertEqual(report["integrity"], "ok")


class RecoveryTests(unittest.TestCase):
    def test_interrupted_jobs_recovered_on_restart(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        try:
            settings = Settings(data_dir=tmp / "data", port=0)
            app = App(settings)
            app.store.create_job({"id": "a" * 32, "project_id": "b" * 32, "artifact_id": "c" * 32,
                                  "kind": "analyze", "status": "running", "progress": 0.4, "message": "x"})
            restarted = App(settings)
            job = restarted.store.get_job("a" * 32)
            self.assertEqual(job["status"], "interrupted")
            self.assertIn("encerramento", job["error"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
