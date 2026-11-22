"""Regressões desta rodada: tipos Unix em ZIP, ZIP bomb medida e declarada, rotas HTTP,
árvore e visualização de arquivos extraídos. Os arquivos são sintéticos, exceto onde indicado."""
from __future__ import annotations

import io
import os
import shutil
import stat
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path

from tests.helpers import find_real_pe, make_zip, synthetic_apk
from tests.test_api import ApiCase
from ure.safezip import ArchiveLimitError, _write_entry, safe_extract_zip

LIMITS = {"max_entries": 1000, "max_total_bytes": 256 * 1024 * 1024, "max_ratio": 200.0}


class UnixTypeTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_explicit_regular_file_type_is_extracted(self) -> None:
        arc = make_zip(self.tmp / "r.zip", [("regular.txt", b"conteudo", stat.S_IFREG | 0o644)])
        report = safe_extract_zip(arc, self.tmp / "out", **LIMITS)
        self.assertEqual(report.files, 1)
        self.assertEqual(report.skipped, [])
        self.assertEqual((self.tmp / "out" / "regular.txt").read_bytes(), b"conteudo")

    def test_fifo_and_device_entries_are_skipped(self) -> None:
        arc = make_zip(self.tmp / "s.zip", [
            ("fifo", b"", stat.S_IFIFO | 0o644),
            ("dev", b"", stat.S_IFCHR | 0o600),
            ("ok.txt", b"x", stat.S_IFREG | 0o644),
        ])
        report = safe_extract_zip(arc, self.tmp / "out", **LIMITS)
        self.assertEqual(report.files, 1)
        self.assertEqual(len(report.skipped), 2)
        self.assertFalse((self.tmp / "out" / "fifo").exists())

    def test_symlink_type_bits_detected_from_high_bits(self) -> None:
        arc = make_zip(self.tmp / "l.zip", [("ln", b"/etc/passwd", stat.S_IFLNK | 0o777)])
        report = safe_extract_zip(arc, self.tmp / "out", **LIMITS)
        self.assertEqual(report.files, 0)
        self.assertTrue(any("link simbólico" in s for s in report.skipped))
        self.assertFalse(os.path.lexists(self.tmp / "out" / "ln"))


class _FakeZip:
    """Substituto mínimo de ZipFile: entrega um fluxo de dados já descompactados.
    Usado só para exercitar a checagem de razão de compressão medida."""

    def __init__(self, payload: bytes) -> None:
        self._payload = payload

    def open(self, info):  # noqa: A003
        return io.BytesIO(self._payload)


def _info(name: str, file_size: int, compress_size: int) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name)
    info.file_size = file_size
    info.compress_size = compress_size
    return info


class ZipBombTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.payload = os.urandom(2 * 1024 * 1024)  # 2 MiB reais, incompressíveis (para o teste)

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_declared_ratio_over_limit_is_refused(self) -> None:
        # tamanho declarado 8 MiB para 1 KiB comprimido: razão 8192:1
        info = _info("a.bin", 8 * 1024 * 1024, 1024)
        with self.assertRaises(ArchiveLimitError) as ctx:
            _write_entry(_FakeZip(self.payload), info, self.tmp / "a.bin", 200.0, 10**9)
        self.assertIn("declarada", str(ctx.exception))
        self.assertFalse((self.tmp / "a.bin").exists() and (self.tmp / "a.bin").stat().st_size > 0)

    def test_measured_ratio_over_limit_is_refused_even_if_declared_is_small(self) -> None:
        # declarado 1.5 MiB para 8000 bytes comprimidos (razão 192, dentro do limite),
        # mas o fluxo real entrega 2 MiB: a razão medida (~262:1) deve bloquear.
        info = _info("b.bin", int(1.5 * 1024 * 1024), 8000)
        with self.assertRaises(ArchiveLimitError) as ctx:
            _write_entry(_FakeZip(self.payload), info, self.tmp / "b.bin", 200.0, 10**9)
        self.assertIn("medida", str(ctx.exception))

    def test_total_budget_enforced_on_actual_bytes(self) -> None:
        info = _info("c.bin", len(self.payload), len(self.payload))  # razão 1:1, não é bomba
        with self.assertRaises(ArchiveLimitError):
            _write_entry(_FakeZip(self.payload), info, self.tmp / "c.bin", 200.0, 1024 * 1024)

    def test_legitimate_compressible_file_passes(self) -> None:
        arc = make_zip(self.tmp / "ok.zip", [("texto.txt", b"linha de texto\n" * 20000, None)])
        report = safe_extract_zip(arc, self.tmp / "out", **LIMITS)
        self.assertEqual(report.files, 1)


class HttpRouteRegressionTests(ApiCase):
    def test_home_page_answers_get_and_head(self) -> None:
        status, raw, headers = self.call("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"Universal Reverse Engine", raw)
        status, raw, headers = self.call("HEAD", "/")
        self.assertEqual(status, 200)
        self.assertEqual(raw, b"")
        self.assertIn("text/html", headers.get("Content-Type", ""))

    def test_options_and_wrong_methods_return_json_405(self) -> None:
        status, raw, _ = self.call("OPTIONS", "/")
        self.assertEqual(status, 405)
        self.assertIn("error", __import__("json").loads(raw))
        self.assertEqual(self.call("PUT", "/")[0], 405)
        self.assertEqual(self.call("DELETE", "/")[0], 405)

    def test_wrong_method_on_known_api_route_is_405_not_404(self) -> None:
        self.assertEqual(self.call("DELETE", "/api/v1/health")[0], 405)
        self.assertEqual(self.call("POST", "/api/v1/health")[0], 405)
        self.assertEqual(self.call("PATCH", "/api/v1/projects")[0], 405)

    def test_unknown_api_route_is_404(self) -> None:
        self.assertEqual(self.call("GET", "/api/v1/nao-existe")[0], 404)
        self.assertEqual(self.call("GET", "/api/v1/")[0], 404)

    def test_head_on_api_is_refused_without_body(self) -> None:
        status, raw, _ = self.call("HEAD", "/api/v1/health")
        self.assertEqual(status, 405)
        self.assertEqual(raw, b"")

    def test_invalid_ids_and_encoded_traversal(self) -> None:
        self.assertEqual(self.call("GET", "/api/v1/projects/%2e%2e")[0], 400)
        self.assertEqual(self.call("GET", "/api/v1/projects/xyz")[0], 400)
        self.assertEqual(self.call("GET", "/%2e%2e/etc/passwd")[0], 404)


class TreeAndPreviewTests(ApiCase):
    def test_full_http_flow_upload_identify_extract_tree_view_export(self) -> None:
        pid = self.new_project("Fluxo completo")
        apk = synthetic_apk(self.tmp / "flow.apk", extra=[("lib/arm64-v8a/libnative.so", b"\x7fELF" + b"\x00" * 60, None)])
        status, art = self._upload_raw(pid, "flow.apk", apk.read_bytes())
        self.assertEqual((status, art["kind"]), (201, "apk"))
        aid = art["id"]
        base = f"/api/v1/projects/{pid}/artifacts/{aid}"
        self.assertEqual(self.js("POST", f"{base}/extract")[0], 200)

        _, root = self.js("GET", f"{base}/tree?root=extracted")
        names = {e["name"] for e in root["entries"]}
        self.assertTrue({"AndroidManifest.xml", "classes.dex", "assets", "lib"} <= names)

        _, lib = self.js("GET", f"{base}/tree?root=extracted&path=lib/arm64-v8a")
        self.assertEqual([e["name"] for e in lib["entries"]], ["libnative.so"])

        _, dex = self.js("GET", f"{base}/file?root=extracted&path=classes.dex")
        self.assertEqual(dex["mode"], "hex")
        self.assertTrue(dex["content"].startswith("00000000  64 65 78 0a 30 33 35"))

        _, txt = self.js("GET", f"{base}/file?root=extracted&path=assets/notes.txt")
        self.assertEqual(txt["mode"], "text")
        self.assertEqual(txt["content"], "hello from ure\n")

        status, raw, headers = self.call("GET", f"{base}/export")
        self.assertEqual(status, 200)
        self.assertIn("flow-export.zip", headers.get("Content-Disposition", ""))
        out = self.tmp / "e.zip"
        out.write_bytes(raw)
        with zipfile.ZipFile(out) as zf:
            self.assertIn("extracted/lib/arm64-v8a/libnative.so", zf.namelist())
            self.assertIn("MANIFEST.json", zf.namelist())
            self.assertIsNone(zf.testzip())

    def test_directory_as_file_preview_is_rejected(self) -> None:
        pid = self.new_project()
        _, art = self._upload_raw(pid, "d.apk", synthetic_apk(self.tmp / "d.apk").read_bytes())
        base = f"/api/v1/projects/{pid}/artifacts/{art['id']}"
        self.js("POST", f"{base}/extract")
        self.assertEqual(self.js("GET", f"{base}/file?root=extracted&path=assets")[0], 400)
        self.assertEqual(self.js("GET", f"{base}/file?root=extracted&path=nao-existe.txt")[0], 404)


if __name__ == "__main__":
    unittest.main()
