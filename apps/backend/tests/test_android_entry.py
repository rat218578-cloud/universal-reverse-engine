"""Funções de configuração remota do módulo de entrada do aparelho (ure_android.py).

Carrega o arquivo real do aplicativo. O servidor HTTP do aparelho não é iniciado aqui.
"""
from __future__ import annotations

import importlib.util
import json
import unittest
from pathlib import Path

from ure import remote, remote_session

ENTRY = Path(__file__).resolve().parents[2] / "desktop" / "android" / "python" / "ure_android.py"
TOKEN = "token-do-keystore-simulado-0123456789ab"


def _load_entry():
    spec = importlib.util.spec_from_file_location("ure_android_under_test", ENTRY)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class AndroidEntryRemoteTests(unittest.TestCase):
    def setUp(self) -> None:
        self.entry = _load_entry()
        remote_session.clear()

    def tearDown(self) -> None:
        remote_session.clear()

    def test_set_and_clear_remote_only_reports_state(self) -> None:
        state = self.entry.set_remote("https://ure.exemplo.org", TOKEN)
        self.assertEqual(state, {"configured": True, "server": "https://ure.exemplo.org"})
        self.assertNotIn(TOKEN, json.dumps(state))
        self.assertEqual(self.entry.clear_remote(), {"configured": False, "server": None})

    def test_plain_http_to_remote_host_is_refused_without_echoing_token(self) -> None:
        with self.assertRaises(remote.RemoteError) as ctx:
            self.entry.set_remote("http://192.168.0.20:8765", TOKEN)
        self.assertNotIn(TOKEN, ctx.exception.message)
        self.assertFalse(remote_session.status()["configured"])

    def test_short_token_is_refused_without_echoing_it(self) -> None:
        short = "curto-demais"
        with self.assertRaises(remote.RemoteError) as ctx:
            self.entry.set_remote("https://ure.exemplo.org", short)
        self.assertNotIn(short, ctx.exception.message)


if __name__ == "__main__":
    unittest.main()
