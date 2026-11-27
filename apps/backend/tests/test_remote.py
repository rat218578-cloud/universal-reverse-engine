"""Cliente do aparelho (ure.remote) contra um servidor HTTP real em outra thread.

O servidor é o mesmo ``make_server`` usado em produção; a comunicação passa por socket real.
"""
from __future__ import annotations

import json
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from tests.helpers import run_server_in_thread
from ure import remote
from ure.app import make_server
from ure.config import Settings
from ure.tools import load_tools_env

load_tools_env()  # o servidor de produção faz o mesmo na inicialização

TOKEN = "token-remoto-de-teste-0123456789abcdef"
FIXTURE_APK = Path(__file__).parent / "fixtures" / "real" / "fixture.apk"


class ServerConfigTests(unittest.TestCase):
    def test_https_and_loopback_http_are_accepted(self) -> None:
        self.assertEqual(remote.validate_base_url("https://ure.exemplo.org/"), "https://ure.exemplo.org")
        self.assertEqual(remote.validate_base_url("http://127.0.0.1:8765"), "http://127.0.0.1:8765")

    def test_plain_http_to_other_hosts_is_refused(self) -> None:
        with self.assertRaises(remote.RemoteError) as ctx:
            remote.validate_base_url("http://192.168.0.10:8765")
        self.assertIn("TLS", ctx.exception.message)

    def test_credentials_in_url_and_unknown_schemes_are_refused(self) -> None:
        for bad in ("https://user:senha@ure.exemplo.org", "ftp://ure.exemplo.org", "ure.exemplo.org", ""):
            with self.subTest(bad=bad), self.assertRaises(remote.RemoteError):
                remote.validate_base_url(bad)

    def test_short_token_is_refused_and_never_shown_in_repr(self) -> None:
        with self.assertRaises(remote.RemoteError):
            remote.RemoteConfig("http://127.0.0.1:1", "curto")
        cfg = remote.RemoteConfig("http://127.0.0.1:1", TOKEN)
        self.assertNotIn(TOKEN, repr(cfg))


class RemoteFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp())
        settings = Settings(data_dir=cls.tmp / "data", port=0, token=TOKEN, max_upload_bytes=64 * 1024 * 1024)
        cls.server = make_server(settings)
        cls.base = f"http://127.0.0.1:{cls.server.server_address[1]}"
        run_server_in_thread(cls.server)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def config(self, token: str = TOKEN) -> remote.RemoteConfig:
        return remote.RemoteConfig(self.base, token)

    def test_wrong_token_is_refused_by_server(self) -> None:
        cli = remote.RemoteClient(self.config("token-errado-com-trinta-e-dois-caracteres"))
        with self.assertRaises(remote.RemoteError) as ctx:
            cli.create_project("não deve existir")
        self.assertEqual(ctx.exception.status, 401)

    def test_upload_detects_hash_mismatch_from_server(self) -> None:
        cli = remote.RemoteClient(self.config())
        pid = cli.create_project("divergência")["id"]
        with mock.patch.object(remote, "sha256_file", return_value="0" * 64):
            with self.assertRaises(remote.RemoteError) as ctx:
                cli.upload(pid, FIXTURE_APK)
        self.assertIn("SHA-256 não confere", ctx.exception.message)

    def test_full_send_downloads_report_and_export_zip(self) -> None:
        progress: list[dict] = []
        out = Path(tempfile.mkdtemp())
        try:
            summary = remote.send_apk(self.config(), FIXTURE_APK, out / "resultado",
                                      on_progress=progress.append, poll_s=0.2, timeout_s=600)
            self.assertEqual(summary["sha256"], remote.sha256_file(FIXTURE_APK))
            self.assertEqual(summary["job"]["status"], "done", summary["job"])
            self.assertTrue(progress, "o aparelho deve receber ao menos um andamento do job")
            self.assertIsNotNone(summary["report"], summary.get("report_error"))
            self.assertEqual(json.loads(Path(summary["report_path"]).read_text(encoding="utf-8")),
                             summary["report"])
            engines = summary["report"]["engines"]
            self.assertEqual(engines["apktool"]["status"], "ok", engines["apktool"])
            export = Path(summary["export_path"])
            self.assertTrue(zipfile.is_zipfile(export), "a exportação deve ser um ZIP válido")
        finally:
            shutil.rmtree(out, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
