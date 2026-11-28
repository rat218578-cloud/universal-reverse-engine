"""Sessão remota no aparelho: rotas, envio de um artefato local ao servidor e segredo fora da API.

Dois servidores HTTP reais: o do 'aparelho' (ApiCase) e o 'servidor remoto' (outro make_server).
"""
from __future__ import annotations

import json
import shutil
import tempfile
import time
import unittest
import zipfile
from pathlib import Path

from tests.helpers import run_server_in_thread
from tests.test_api import ApiCase
from ure import remote_session
from ure.app import make_server
from ure.config import Settings
from ure.tools import load_tools_env

load_tools_env()
remote_session.install_routes()

TOKEN = "token-sessao-de-teste-0123456789abcdef0"
WRONG = "token-errado-de-teste-0123456789abcdef0"
FIXTURE_APK = Path(__file__).parent / "fixtures" / "real" / "fixture.apk"


def _files_containing(root: Path, needle: bytes) -> list[str]:
    """Procura o segredo em todo arquivo do diretório, inclusive dentro de ZIPs (conteúdo comprimido)."""
    hits: list[str] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if needle in path.read_bytes():
            hits.append(str(path))
        if zipfile.is_zipfile(path):
            with zipfile.ZipFile(path) as zf:
                for info in zf.infolist():
                    if needle in zf.read(info.filename):
                        hits.append(f"{path}!{info.filename}")
    return hits


class RemoteSessionTests(ApiCase):
    token = "token-do-aparelho-0123456789abcdef-xyz"

    @classmethod
    def setUpClass(cls) -> None:
        cls.remote_tmp = Path(tempfile.mkdtemp())
        cls.remote_settings = Settings(data_dir=cls.remote_tmp / "data", port=0, token=TOKEN,
                                       max_upload_bytes=64 * 1024 * 1024)
        cls.remote = make_server(cls.remote_settings)
        cls.remote_base = f"http://127.0.0.1:{cls.remote.server_address[1]}"
        run_server_in_thread(cls.remote)

    @classmethod
    def tearDownClass(cls) -> None:
        cls.remote.shutdown()
        cls.remote.server_close()
        shutil.rmtree(cls.remote_tmp, ignore_errors=True)

    def tearDown(self) -> None:
        remote_session.clear()
        super().tearDown()

    def _wait(self, jid: str, timeout_s: float = 600.0) -> dict:
        deadline = time.monotonic() + timeout_s
        while True:
            status, body = self.js("GET", f"/api/v1/remote/jobs/{jid}")
            self.assertEqual(status, 200, body)
            if body["status"] in ("done", "failed"):
                return body
            if time.monotonic() > deadline:
                self.fail("envio não terminou no prazo do teste")
            time.sleep(0.3)

    def test_status_reports_configuration_without_the_token(self) -> None:
        remote_session.configure(self.remote_base, TOKEN)
        status, raw, _ = self.call("GET", "/api/v1/remote")
        self.assertEqual(status, 200)
        body = json.loads(raw)
        self.assertTrue(body["configured"])
        self.assertEqual(body["server"], self.remote_base)
        self.assertNotIn(TOKEN, raw.decode("utf-8"))

    def test_send_requires_configuration(self) -> None:
        pid = self.new_project("sem servidor")
        _, art = self._upload_raw(pid, "fixture.apk", FIXTURE_APK.read_bytes())
        status, body = self.js("POST", f"/api/v1/projects/{pid}/artifacts/{art['id']}/remote-send", {})
        self.assertEqual(status, 409)
        self.assertIn("não configurado", body["error"])

    def test_send_forwards_original_and_stores_results_locally(self) -> None:
        remote_session.configure(self.remote_base, TOKEN)
        pid = self.new_project("envio real")
        _, art = self._upload_raw(pid, "fixture.apk", FIXTURE_APK.read_bytes())
        status, job = self.js("POST", f"/api/v1/projects/{pid}/artifacts/{art['id']}/remote-send", {})
        self.assertEqual(status, 202, job)
        final = self._wait(job["id"])
        self.assertEqual(final["status"], "done", final)
        root = self.server.ure_app.root_of(pid, art["id"])
        self.assertTrue(zipfile.is_zipfile(root / "remote" / "export.zip"))
        report = json.loads((root / "remote" / "analysis.json").read_text(encoding="utf-8"))
        self.assertEqual(report["engines"]["apktool"]["status"], "ok")
        self.assertNotIn(TOKEN, json.dumps(final))
        self.assertEqual(_files_containing(self.server.ure_app.settings.data_dir, TOKEN.encode()), [],
                         "o token não pode ser gravado em nenhum arquivo do aparelho")
        # Resultados disponíveis pela API local (relatório e exportação do servidor)
        status, rep = self.js("GET", f"/api/v1/projects/{pid}/artifacts/{art['id']}/remote-report")
        self.assertEqual(status, 200)
        self.assertEqual(rep["engines"]["apktool"]["status"], "ok")
        status, raw, headers = self.call("GET", f"/api/v1/projects/{pid}/artifacts/{art['id']}/remote-export")
        self.assertEqual(status, 200)
        self.assertTrue(raw.startswith(b"PK"), "exportação deve ser um ZIP")

    def test_failed_send_does_not_leave_previous_results_visible(self) -> None:
        remote_session.configure(self.remote_base, TOKEN)
        pid = self.new_project("resultado antigo")
        _, art = self._upload_raw(pid, "fixture.apk", FIXTURE_APK.read_bytes())
        _, job = self.js("POST", f"/api/v1/projects/{pid}/artifacts/{art['id']}/remote-send", {})
        self.assertEqual(self._wait(job["id"])["status"], "done")
        remote_session.configure(self.remote_base, WRONG)
        _, job = self.js("POST", f"/api/v1/projects/{pid}/artifacts/{art['id']}/remote-send", {})
        self.assertEqual(self._wait(job["id"])["status"], "failed")
        status, _ = self.js("GET", f"/api/v1/projects/{pid}/artifacts/{art['id']}/remote-report")
        self.assertEqual(status, 404)

    def test_wrong_token_fails_the_job_without_leaking_the_token(self) -> None:
        remote_session.configure(self.remote_base, WRONG)
        pid = self.new_project("token errado")
        _, art = self._upload_raw(pid, "fixture.apk", FIXTURE_APK.read_bytes())
        _, job = self.js("POST", f"/api/v1/projects/{pid}/artifacts/{art['id']}/remote-send", {})
        final = self._wait(job["id"])
        self.assertEqual(final["status"], "failed")
        self.assertIn("401", final["error"])
        for secret in (WRONG, TOKEN, self.token):
            self.assertNotIn(secret, json.dumps(final))

    def test_local_api_keeps_working_when_server_is_unreachable(self) -> None:
        remote_session.configure("http://127.0.0.1:1", TOKEN)
        pid = self.new_project("servidor fora do ar")
        _, art = self._upload_raw(pid, "fixture.apk", FIXTURE_APK.read_bytes())
        _, job = self.js("POST", f"/api/v1/projects/{pid}/artifacts/{art['id']}/remote-send", {})
        final = self._wait(job["id"], timeout_s=60)
        self.assertEqual(final["status"], "failed")
        self.assertIn("não foi possível falar com o servidor", final["error"])
        status, _ = self.js("GET", f"/api/v1/projects/{pid}/artifacts/{art['id']}")
        self.assertEqual(status, 200)
        status, _ = self.js("GET", "/api/v1/projects")
        self.assertEqual(status, 200)

    def test_unknown_job_is_404(self) -> None:
        status, _ = self.js("GET", "/api/v1/remote/jobs/" + "0" * 32)
        self.assertEqual(status, 404)


if __name__ == "__main__":
    unittest.main()
