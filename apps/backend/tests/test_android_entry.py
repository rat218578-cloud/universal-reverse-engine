"""Contrato do ponto de entrada Android (apps/desktop/android/python/ure_android.py).

Roda no Linux e no Windows como o restante do backend: o módulo usa só a stdlib e o pacote ure.
"""
from __future__ import annotations

import importlib.util
import os
import socket
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path

REPO = Path(__file__).resolve().parents[3]
ENTRY = REPO / "apps" / "desktop" / "android" / "python" / "ure_android.py"
WEB = REPO / "apps" / "web"
TOKEN = "a" * 64
ENV_KEYS = ("URE_DATA_DIR", "URE_WEB_DIR", "URE_HOST", "URE_PORT", "URE_TOKEN", "URE_AI_ENABLED", "URE_PARENT_WATCH")


def _load_entry():
    spec = importlib.util.spec_from_file_location("ure_android", ENTRY)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class AndroidEntryTests(unittest.TestCase):
    def setUp(self) -> None:
        self._saved = {k: os.environ.get(k) for k in ENV_KEYS}
        self._tmp = tempfile.TemporaryDirectory()
        self.entry = _load_entry()
        self.data = Path(self._tmp.name) / "data"

    def tearDown(self) -> None:
        self.entry.stop()
        for key, value in self._saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value
        self._tmp.cleanup()

    def _get(self, port: int, path: str):
        return urllib.request.urlopen(f"http://127.0.0.1:{port}{path}", timeout=5)

    def test_start_serves_health_and_interface(self) -> None:
        port = self.entry.start(str(self.data), str(WEB), _free_port(), TOKEN)
        with self._get(port, "/api/v1/health") as res:
            self.assertEqual(res.status, 200)
        with self._get(port, "/") as res:
            self.assertEqual(res.status, 200)
            body = res.read()
        self.assertEqual(body, (WEB / "index.html").read_bytes())

    def test_start_is_idempotent_and_stop_releases_port(self) -> None:
        port = self.entry.start(str(self.data), str(WEB), _free_port(), TOKEN)
        self.assertEqual(self.entry.start(str(self.data), str(WEB), 1, TOKEN), port)
        self.entry.stop()
        with self.assertRaises((urllib.error.URLError, ConnectionError, OSError)):
            self._get(port, "/api/v1/health")
        self.entry.stop()  # segunda chamada não falha

    def test_rejects_short_token_and_bad_port(self) -> None:
        with self.assertRaises(ValueError):
            self.entry.start(str(self.data), str(WEB), _free_port(), "curto")
        with self.assertRaises(ValueError):
            self.entry.start(str(self.data), str(WEB), 0, TOKEN)

    def test_binds_loopback_only(self) -> None:
        port = self.entry.start(str(self.data), str(WEB), _free_port(), TOKEN)
        self.assertEqual(self.entry._server.server_address[0], "127.0.0.1")
        self.assertGreater(port, 0)


if __name__ == "__main__":
    unittest.main()
