"""Testes da Fase 4 (IA opcional). O Ollama usado aqui é um SERVIDOR DE TESTE falso em loopback,
que imita as rotas /api/tags e /api/generate para validar o roteador. Não é um modelo real."""
from __future__ import annotations

import json
import socket
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from tests.helpers import synthetic_apk
from tests.test_api import ApiCase
from ure.ai import build_messages

AKIA = "AKIAIOSFODNN7EXAMPLE"


class FakeOllama:
    """Test double: registra as chamadas recebidas e responde de forma fixa."""

    def __init__(self) -> None:
        self.generate_calls = 0
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):  # silencia o log
                return

            def do_GET(self):  # noqa: N802
                body = {"models": [{"name": "test-model:latest", "digest": "sha-teste-1"}]}
                self._send(body)

            def do_POST(self):  # noqa: N802
                n = int(self.headers.get("Content-Length") or 0)
                payload = json.loads(self.rfile.read(n) or b"{}")
                outer.generate_calls += 1
                self._send({"response": f"Resposta de teste sobre {payload.get('model')} [E1]"})

            def _send(self, body):
                raw = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()


def closed_port_url() -> str:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return f"http://127.0.0.1:{port}"


class AiContextTests(unittest.TestCase):
    def test_context_never_contains_secret_values(self) -> None:
        report = {
            "filename": "a.apk", "kind": "apk", "integrity": "ok",
            "dependencies": {}, "indicators": [], "engines": {},
            "secrets": {"findings": [{"file": "x", "rule": "aws-access-key-id", "offset": 0,
                                      "preview": "AKIA...LE"}]},
        }
        system, user = build_messages("pergunta", report)
        self.assertIn("aws-access-key-id", user)
        self.assertNotIn("AKIA...LE", user)
        self.assertNotIn("AKIA...LE", system)
        self.assertIn("[E4]", user)


class AiFlowTests(ApiCase):
    settings_extra = {"ai_enabled": False}

    def make_report(self) -> str:
        pid = self.new_project()
        apk = synthetic_apk(self.tmp / "a.apk", extra=[("cfg.txt", f'token = "{AKIA}"\n'.encode(), None)])
        _, art = self._upload_raw(pid, "a.apk", apk.read_bytes())
        _, job = self.js("POST", f"/api/v1/projects/{pid}/artifacts/{art['id']}/analyze", {})
        for _ in range(300):
            _, j = self.js("GET", f"/api/v1/jobs/{job['id']}")
            if j["status"] not in ("queued", "running"):
                break
            time.sleep(0.2)
        self.assertEqual(j["status"], "done", j.get("error"))
        self._pid, self._aid = pid, art["id"]
        return art["id"]

    def ask(self, body: dict):
        return self.js("POST", f"/api/v1/projects/{self._pid}/artifacts/{self._aid}/ask", body)

    def test_disabled_by_default(self) -> None:
        self.make_report()
        status, body = self.js("GET", "/api/v1/ai/status")
        self.assertFalse(body["enabled"])
        self.assertEqual(self.ask({"question": "O que há?"})[0], 503)

    def test_requires_analysis_first(self) -> None:
        pid = self.new_project()
        apk = synthetic_apk(self.tmp / "b.apk")
        _, art = self._upload_raw(pid, "b.apk", apk.read_bytes())
        status, _ = self.js("POST", f"/api/v1/projects/{pid}/artifacts/{art['id']}/ask", {"question": "x"})
        self.assertEqual(status, 409)

    def test_external_provider_needs_consent_then_not_implemented(self) -> None:
        self.make_report()
        from ure.ai import AIError, AIRouter
        from ure.config import Settings
        from ure.db import Store
        s = Settings(data_dir=self.tmp / "d2", ai_enabled=True, ollama_url=closed_port_url())
        router = AIRouter(s, Store(self.tmp / "d2" / "x.sqlite3"))
        with self.assertRaises(AIError) as c1:
            router.ask("x", {}, provider="openai-compatible", model=None, consent=False)
        self.assertEqual(c1.exception.status, 403)
        with self.assertRaises(AIError) as c2:
            router.ask("x", {}, provider="openai-compatible", model=None, consent=True)
        self.assertEqual(c2.exception.status, 501)

    def test_ollama_unreachable_is_reported_not_faked(self) -> None:
        from ure.ai import AIError, AIRouter
        from ure.config import Settings
        from ure.db import Store
        s = Settings(data_dir=self.tmp / "d3", ai_enabled=True, ollama_url=closed_port_url())
        router = AIRouter(s, Store(self.tmp / "d3" / "x.sqlite3"))
        self.assertFalse(router.status()["ollama_reachable"])
        with self.assertRaises(AIError) as c:
            router.ask("x", {"filename": "f"}, provider="ollama", model=None, consent=False)
        self.assertEqual(c.exception.status, 503)

    def test_local_answer_cached_and_budget_enforced(self) -> None:
        fake = FakeOllama()
        self.addCleanup(fake.close)
        from ure.ai import AIError, AIRouter
        from ure.config import Settings
        from ure.db import Store
        report = {"filename": "a.apk", "kind": "apk", "integrity": "ok", "dependencies": {},
                  "indicators": [], "engines": {}, "secrets": {"findings": []}}
        s = Settings(data_dir=self.tmp / "d4", ai_enabled=True, ollama_url=fake.url,
                     ollama_model="test-model", ai_daily_budget=2)
        router = AIRouter(s, Store(self.tmp / "d4" / "x.sqlite3"))
        first = router.ask("Quais dependências?", report, provider="ollama", model=None, consent=False)
        self.assertFalse(first["cached"])
        self.assertEqual(first["answer"]["model_version"], "sha-teste-1")
        self.assertEqual(first["answer"]["evidence"], ["E1", "E2", "E3", "E4"])
        second = router.ask("Quais dependências?", report, provider="ollama", model=None, consent=False)
        self.assertTrue(second["cached"])
        self.assertEqual(fake.generate_calls, 1, "resposta em cache não deve chamar o modelo de novo")
        router.ask("outra pergunta", report, provider="ollama", model=None, consent=False)
        with self.assertRaises(AIError) as c:
            router.ask("terceira pergunta", report, provider="ollama", model=None, consent=False)
        self.assertEqual(c.exception.status, 429)

    def test_missing_model_is_reported(self) -> None:
        fake = FakeOllama()
        self.addCleanup(fake.close)
        from ure.ai import AIError, AIRouter
        from ure.config import Settings
        from ure.db import Store
        s = Settings(data_dir=self.tmp / "d5", ai_enabled=True, ollama_url=fake.url, ollama_model="outro-modelo")
        router = AIRouter(s, Store(self.tmp / "d5" / "x.sqlite3"))
        with self.assertRaises(AIError) as c:
            router.ask("x", {"filename": "f", "secrets": {"findings": []}}, provider="ollama", model=None, consent=False)
        self.assertEqual(c.exception.status, 503)


if __name__ == "__main__":
    unittest.main()
