"""Testes: IA externa com consentimento, licenças/tamanho e exportação Git local.
Test doubles declarados: o provedor OpenAI-compatível é um servidor FALSO em loopback."""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from tests.helpers import AWS_EXAMPLE_KEY, synthetic_apk
from tests.test_api import ApiCase
from ure.ai import AIError, AIRouter, url_is_allowed
from ure.compliance import detect_license_text, scan_licenses, size_summary
from ure.config import Settings
from ure.db import Store

AKIA = AWS_EXAMPLE_KEY
KEY = "chave-de-teste-nao-real-123"
REPORT = {"filename": "a.apk", "kind": "apk", "integrity": "ok", "dependencies": {"dex_files": ["classes.dex"]},
          "indicators": [], "engines": {"apktool": {"status": "missing"}},
          "secrets": {"findings": [{"file": "x", "rule": "aws-access-key-id", "offset": 0, "preview": "AKIA...LE"}]}}


class FakeOpenAI:
    """Test double: imita POST /v1/chat/completions e registra o que recebeu."""

    def __init__(self, fail: bool = False) -> None:
        self.received: list[dict] = []
        self.fail = fail
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                return

            def do_POST(self):  # noqa: N802
                n = int(self.headers.get("Content-Length") or 0)
                body = json.loads(self.rfile.read(n) or b"{}")
                outer.received.append({"auth": self.headers.get("Authorization"), "body": body})
                if outer.fail:
                    self.send_response(500)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                raw = json.dumps({"choices": [{"message": {"role": "assistant", "content": "Resposta externa [E1]"}}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}/v1/chat/completions"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


class ExternalAiTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.fake = FakeOpenAI()
        self.fail_fake = FakeOpenAI(fail=True)

    def tearDown(self) -> None:
        self.fake.close()
        self.fail_fake.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def router(self, **kw) -> AIRouter:
        base = dict(data_dir=self.tmp / "d", ai_enabled=True, ollama_url="http://127.0.0.1:9",
                    external_ai_url=self.fake.url, external_ai_key=KEY)
        base.update(kw)
        s = Settings(**base)
        return AIRouter(s, Store(self.tmp / f"{abs(hash(str(kw)))}.sqlite3"))

    def test_url_policy(self) -> None:
        self.assertTrue(url_is_allowed("https://api.exemplo.com/v1/chat/completions"))
        self.assertTrue(url_is_allowed("http://127.0.0.1:9/v1/chat/completions"))
        self.assertFalse(url_is_allowed("http://api.exemplo.com/v1/chat/completions"))
        self.assertFalse(url_is_allowed("ftp://127.0.0.1/x"))

    def test_consent_required(self) -> None:
        r = self.router()
        with self.assertRaises(AIError) as c:
            r.ask("pergunta", REPORT, provider="openai-compatible", model=None, consent=False)
        self.assertEqual(c.exception.status, 403)
        self.assertEqual(self.fake.received, [], "nenhum envio sem consentimento")

    def test_not_configured_is_501(self) -> None:
        r = self.router(external_ai_url=None, external_ai_key=None)
        with self.assertRaises(AIError) as c:
            r.ask("pergunta", REPORT, provider="openai-compatible", model=None, consent=True)
        self.assertEqual(c.exception.status, 501)

    def test_insecure_remote_url_refused_before_sending(self) -> None:
        r = self.router(external_ai_url="http://api.exemplo.com/v1/chat/completions")
        with self.assertRaises(AIError) as c:
            r.ask("pergunta", REPORT, provider="openai-compatible", model=None, consent=True)
        self.assertEqual(c.exception.status, 503)

    def test_success_sends_bearer_no_secret_values_and_caches(self) -> None:
        r = self.router()
        out = r.ask("quais dependências?", REPORT, provider="openai-compatible", model="m1", consent=True)
        self.assertEqual(out["answer"]["text"], "Resposta externa [E1]")
        self.assertEqual(out["answer"]["provider"], "openai-compatible")
        self.assertEqual(self.fake.received[0]["auth"], f"Bearer {KEY}")
        sent = json.dumps(self.fake.received[0]["body"], ensure_ascii=False)
        self.assertNotIn(AKIA, sent)
        self.assertNotIn(KEY, sent, "a chave de API não pode ir no corpo")
        self.assertNotIn(KEY, json.dumps(out), "a chave não aparece na resposta")
        again = r.ask("quais dependências?", REPORT, provider="openai-compatible", model="m1", consent=True)
        self.assertTrue(again["cached"])
        self.assertEqual(len(self.fake.received), 1)

    def test_provider_http_error_does_not_leak_key(self) -> None:
        r = self.router(external_ai_url=self.fail_fake.url)
        with self.assertRaises(AIError) as c:
            r.ask("pergunta", REPORT, provider="openai-compatible", model=None, consent=True)
        self.assertEqual(c.exception.status, 502)
        self.assertNotIn(KEY, c.exception.message)

    def test_status_never_exposes_key(self) -> None:
        r = self.router()
        st = r.status()
        self.assertTrue(st["external_configured"])
        self.assertNotIn(KEY, json.dumps(st))
        self.assertTrue(st["external_requires_consent"])


class ComplianceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_license_detection(self) -> None:
        self.assertEqual(detect_license_text("Apache License\nVersion 2.0"), ["Apache-2.0"])
        self.assertEqual(detect_license_text("GNU GENERAL PUBLIC LICENSE Version 3"), ["GPL-3.0"])
        self.assertEqual(detect_license_text("texto qualquer"), [])

    def test_scan_licenses_reports_unknown_honestly(self) -> None:
        (self.tmp / "LICENSE").write_text("MIT License\n\nCopyright ...")
        (self.tmp / "vendor").mkdir()
        (self.tmp / "vendor" / "COPYING.txt").write_text("sem texto reconhecível")
        (self.tmp / "main.java").write_text("class A {}")
        found = {r["file"]: r["detected"] for r in scan_licenses(self.tmp)}
        self.assertEqual(found, {"LICENSE": ["MIT"], "vendor/COPYING.txt": ["não identificada"]})

    def test_size_summary_skips_symlinks(self) -> None:
        (self.tmp / "a.bin").write_bytes(b"x" * 100)
        (self.tmp / "ln").symlink_to(self.tmp / "a.bin")
        self.assertEqual(size_summary(self.tmp), {"files": 1, "bytes": 100})


class GitAndAiRouteTests(ApiCase):
    settings_extra = {"ai_enabled": True, "ollama_url": "http://127.0.0.1:9"}

    def test_git_export_local_private_with_commits(self) -> None:
        if shutil.which("git") is None:
            self.skipTest("git ausente")
        pid = self.new_project()
        _, art = self._upload_raw(pid, "g.apk", synthetic_apk(self.tmp / "g.apk").read_bytes())
        base = f"/api/v1/projects/{pid}/artifacts/{art['id']}"
        self.assertEqual(self.js("POST", f"{base}/git-export")[0], 409, "sem extração não há o que versionar")
        self.js("POST", f"{base}/extract")
        status, res = self.js("POST", f"{base}/git-export")
        self.assertEqual(status, 201)
        self.assertEqual(res["remotes"], [])
        self.assertTrue(res["private"])
        self.assertEqual(len(res["commits"]), 1)
        out = subprocess.run(["git", "-C", res["path"], "ls-files"], capture_output=True, text=True).stdout
        self.assertIn("extracted/AndroidManifest.xml", out)
        log = subprocess.run(["git", "-C", res["path"], "log", "--format=%an"], capture_output=True, text=True).stdout
        self.assertEqual(log.strip(), "Universal Reverse Engine")

    def test_ai_route_external_requires_consent_over_http(self) -> None:
        pid = self.new_project()
        _, art = self._upload_raw(pid, "r.apk", synthetic_apk(self.tmp / "r.apk").read_bytes())
        base = f"/api/v1/projects/{pid}/artifacts/{art['id']}"
        self.js("POST", f"{base}/analyze", {})
        import time
        for _ in range(200):
            _, j = self.js("GET", f"/api/v1/jobs/{self.last_job_id(pid, art['id'])}")
            if j["status"] not in ("queued", "running"):
                break
            time.sleep(0.1)
        self.assertEqual(self.js("POST", f"{base}/ask", {"question": "x", "provider": "openai-compatible"})[0], 403)

    def last_job_id(self, pid: str, aid: str) -> str:
        return self._last_job

    def js(self, method, path, body=None, headers=None):
        result = super().js(method, path, body, headers)
        if method == "POST" and path.endswith("/analyze") and isinstance(result[1], dict) and "id" in result[1]:
            self._last_job = result[1]["id"]
        return result


if __name__ == "__main__":
    unittest.main()
