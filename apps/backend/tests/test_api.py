"""Testes de integração HTTP: fluxo completo, limites, rejeições e segurança da API."""
from __future__ import annotations

import hashlib
import json
import shutil
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path

from tests.helpers import find_real_pe, make_zip, run_server_in_thread, synthetic_apk
from ure.app import make_server
from ure.config import Settings


class ApiCase(unittest.TestCase):
    token: str | None = None
    max_upload: int = 8 * 1024 * 1024
    settings_extra: dict = {}

    def setUp(self) -> None:
        self._td = tempfile.mkdtemp()
        self.tmp = Path(self._td)
        self.settings = Settings(
            data_dir=self.tmp / "data",
            port=0,
            max_upload_bytes=self.max_upload,
            token=self.token,
            **self.settings_extra,
        )
        self.server = make_server(self.settings)
        self.port = self.server.server_address[1]
        run_server_in_thread(self.server)

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        shutil.rmtree(self._td, ignore_errors=True)

    def call(self, method: str, path: str, data: bytes | None = None, headers: dict[str, str] | None = None):
        hdrs = dict(headers or {})
        if self.token and "Authorization" not in hdrs:
            hdrs["Authorization"] = f"Bearer {self.token}"
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=data, method=method, headers=hdrs)
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.status, r.read(), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read(), dict(e.headers)

    def js(self, method: str, path: str, body: dict | None = None, headers: dict[str, str] | None = None):
        data = json.dumps(body).encode() if body is not None else None
        h = {"Content-Type": "application/json", **(headers or {})}
        status, raw, _ = self.call(method, path, data, h)
        return status, (json.loads(raw) if raw and raw[:1] in b"{[" else raw)

    def new_project(self, name: str = "Projeto teste") -> str:
        status, body = self.js("POST", "/api/v1/projects", {"name": name})
        self.assertEqual(status, 201)
        return body["id"]

    def upload(self, pid: str, filename: str, data: bytes):
        return self.js("POST", f"/api/v1/projects/{pid}/artifacts", headers={"X-Filename": filename,
                       "Content-Type": "application/octet-stream"}) if False else self._upload_raw(pid, filename, data)

    def _upload_raw(self, pid: str, filename: str, data: bytes):
        status, raw, _ = self.call(
            "POST", f"/api/v1/projects/{pid}/artifacts", data,
            {"X-Filename": filename, "Content-Type": "application/octet-stream"},
        )
        return status, json.loads(raw)


class ApiFlowTests(ApiCase):
    def test_health_and_static_ui(self) -> None:
        status, body = self.js("GET", "/api/v1/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "ok")
        self.assertFalse(body["ai_enabled"])

    def test_project_crud_and_invalid_ids(self) -> None:
        pid = self.new_project("Alpha")
        status, body = self.js("GET", f"/api/v1/projects/{pid}")
        self.assertEqual((status, body["name"]), (200, "Alpha"))
        status, body = self.js("GET", "/api/v1/projects")
        self.assertEqual(len(body["projects"]), 1)
        self.assertIn(self.js("GET", "/api/v1/projects/..%2F..%2Fetc")[0], (400, 404))
        self.assertEqual(self.js("GET", "/api/v1/projects/" + "0" * 32)[0], 404)
        self.assertEqual(self.js("POST", "/api/v1/projects", {"name": ""})[0], 400)

    def test_delete_requires_explicit_confirmation(self) -> None:
        pid = self.new_project("Confirmar")
        self.assertEqual(self.js("DELETE", f"/api/v1/projects/{pid}")[0], 409)
        self.assertEqual(self.js("DELETE", f"/api/v1/projects/{pid}", headers={"X-Confirm-Delete": "errado"})[0], 409)
        self.assertEqual(self.js("DELETE", f"/api/v1/projects/{pid}", headers={"X-Confirm-Delete": "Confirmar"})[0], 200)
        self.assertEqual(self.js("GET", f"/api/v1/projects/{pid}")[0], 404)

    def test_real_pe_upload_hash_and_readonly(self) -> None:
        pe = find_real_pe()
        if pe is None:
            self.skipTest("nenhum PE real disponível")
        pid = self.new_project()
        status, art = self._upload_raw(pid, "w32.exe", pe.read_bytes())
        self.assertEqual(status, 201)
        self.assertEqual(art["kind"], "pe")
        self.assertEqual(art["sha256"], hashlib.sha256(pe.read_bytes()).hexdigest())
        self.assertFalse(art["details"]["extension_mismatch"])
        stored = self.settings.data_dir / "projects" / pid / "artifacts" / art["id"] / "original" / "w32.exe"
        self.assertEqual(stored.stat().st_mode & 0o777, 0o444)
        self.assertEqual(stored.read_bytes(), pe.read_bytes())

    def test_text_disguised_as_exe_rejected_and_cleaned(self) -> None:
        pid = self.new_project()
        status, body = self._upload_raw(pid, "virus.exe", b"MZ isto nao e um executavel valido" * 4)
        self.assertEqual(status, 415)
        status, body = self._upload_raw(pid, "notes.txt", b"apenas texto")
        self.assertEqual(status, 415)
        self.assertEqual(self.js("GET", f"/api/v1/projects/{pid}/artifacts")[1]["artifacts"], [])
        self.assertEqual(list((self.settings.data_dir / "projects" / pid / "artifacts").glob("*")), [])

    def test_oversized_upload_rejected_before_reading_body(self) -> None:
        pid = self.new_project()
        status, raw, _ = self.call(
            "POST", f"/api/v1/projects/{pid}/artifacts", b"x" * 10,
            {"X-Filename": "big.apk", "Content-Length": str(self.max_upload + 1)},
        )
        self.assertEqual(status, 413)

    def test_apk_extract_tree_preview_and_export(self) -> None:
        pid = self.new_project()
        apk = synthetic_apk(self.tmp / "app.apk")
        status, art = self._upload_raw(pid, "app.apk", apk.read_bytes())
        self.assertEqual((status, art["kind"]), (201, "apk"))
        aid = art["id"]
        status, body = self.js("POST", f"/api/v1/projects/{pid}/artifacts/{aid}/extract")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "extracted")
        status, tree = self.js("GET", f"/api/v1/projects/{pid}/artifacts/{aid}/tree?root=extracted&path=assets")
        self.assertEqual([e["name"] for e in tree["entries"]], ["notes.txt"])
        status, prev = self.js("GET", f"/api/v1/projects/{pid}/artifacts/{aid}/file?root=extracted&path=assets/notes.txt")
        self.assertEqual((prev["mode"], prev["content"]), ("text", "hello from ure\n"))
        status, raw, headers = self.call("GET", f"/api/v1/projects/{pid}/artifacts/{aid}/export")
        self.assertEqual(status, 200)
        self.assertIn("app-export.zip", headers.get("Content-Disposition", ""))
        exp = self.tmp / "export.zip"
        exp.write_bytes(raw)
        import zipfile

        with zipfile.ZipFile(exp) as zf:
            names = zf.namelist()
            manifest = json.loads(zf.read("MANIFEST.json"))
        self.assertIn("MANIFEST.json", names)
        self.assertIn("extracted/assets/notes.txt", names)
        self.assertFalse(any(n.startswith("original/") for n in names))
        self.assertFalse(manifest["include_original"])
        status, raw, _ = self.call("GET", f"/api/v1/projects/{pid}/artifacts/{aid}/export?include_original=1")
        exp.write_bytes(raw)
        with zipfile.ZipFile(exp) as zf:
            self.assertIn("original/app.apk", zf.namelist())


class ApiSecurityTests(ApiCase):
    def test_traversal_in_file_and_tree_blocked(self) -> None:
        pid = self.new_project()
        _, art = self._upload_raw(pid, "app.apk", synthetic_apk(self.tmp / "s.apk").read_bytes())
        aid = art["id"]
        self.js("POST", f"/api/v1/projects/{pid}/artifacts/{aid}/extract")
        for path in ["../../../etc/passwd", "..%2F..%2Fetc%2Fpasswd", "%2e%2e/%2e%2e/x"]:
            with self.subTest(path=path):
                status, _ = self.js("GET", f"/api/v1/projects/{pid}/artifacts/{aid}/file?root=extracted&path={path}")
                self.assertIn(status, (400, 404))
        self.assertEqual(self.js("GET", f"/api/v1/projects/{pid}/artifacts/{aid}/tree?root=../../x")[0], 400)

    def test_traversal_zip_rejected_at_extraction(self) -> None:
        pid = self.new_project()
        evil = make_zip(
            self.tmp / "evil.apk",
            [("AndroidManifest.xml", b"m", None), ("classes.dex", b"dex\n035\x00", None), ("../../pwned.txt", b"x", None)],
        )
        status, art = self._upload_raw(pid, "evil.apk", evil.read_bytes())
        self.assertEqual(status, 201)
        status, body = self.js("POST", f"/api/v1/projects/{pid}/artifacts/{art['id']}/extract")
        self.assertEqual(status, 422)
        self.assertFalse((self.settings.data_dir / "pwned.txt").exists())
        self.assertFalse((self.settings.data_dir.parent / "pwned.txt").exists())
        status, got = self.js("GET", f"/api/v1/projects/{pid}/artifacts/{art['id']}")
        self.assertEqual(got["status"], "rejected")

    def test_unknown_route_and_bad_method(self) -> None:
        self.assertEqual(self.js("GET", "/api/v1/nao-existe")[0], 404)
        self.assertEqual(self.js("PUT", "/api/v1/health")[0], 405)

    def test_bind_outside_loopback_requires_token(self) -> None:
        with self.assertRaises(RuntimeError):
            Settings(data_dir=self.tmp, host="0.0.0.0").check_bind()
        Settings(data_dir=self.tmp, host="0.0.0.0", token="segredo-longo").check_bind()


class AuthTests(ApiCase):
    token = "token-de-teste-123"

    def test_api_requires_token_when_configured(self) -> None:
        raw_status, _, _ = self._raw("GET", "/api/v1/projects", None)
        self.assertEqual(raw_status, 401)
        self.assertEqual(self._raw("GET", "/api/v1/projects", "Bearer errado")[0], 401)
        self.assertEqual(self._raw("GET", "/api/v1/projects", f"Bearer {self.token}")[0], 200)

    def _raw(self, method: str, path: str, auth: str | None):
        headers = {"Authorization": auth} if auth else {}
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, r.read(), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read(), dict(e.headers)


if __name__ == "__main__":
    unittest.main()
