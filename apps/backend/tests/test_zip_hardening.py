"""Endurecimento do processamento de ZIP/APK: duplicatas, caminhos inseguros, links, bombas e corrupção.

Os arquivos de entrada são construídos aqui ou vêm de tests/fixtures/real (APK gerado pelo Apktool).
Nenhum deles é executado.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
import unittest
import warnings
import zipfile
from pathlib import Path

from tests.helpers import make_zip
from ure.safezip import ArchiveLimitError, UnsafeArchiveError, inventory_zip, safe_extract_zip

# zipfile avisa ao gravar nomes repetidos; a duplicata é intencional neste módulo.
warnings.filterwarnings("ignore", message="Duplicate name", category=UserWarning)

FIXTURES = Path(__file__).parent / "fixtures" / "real"
LIMITS = {"max_entries": 1000, "max_total_bytes": 64 * 1024 * 1024, "max_ratio": 100.0}


def real_apk_entries() -> list[tuple[str, bytes, int | None]]:
    with zipfile.ZipFile(FIXTURES / "fixture.apk") as zf:
        return [(i.filename, zf.read(i.filename), None) for i in zf.infolist() if not i.is_dir()]


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class ZipHardeningTests(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.mkdtemp()
        self.tmp = Path(self._td)

    def tearDown(self) -> None:
        shutil.rmtree(self._td, ignore_errors=True)

    def test_real_apk_extracts_dex_manifest_and_resources(self) -> None:
        arc = make_zip(self.tmp / "app.apk", real_apk_entries())
        out = self.tmp / "out"
        rep = safe_extract_zip(arc, out, **LIMITS)
        self.assertEqual(rep.duplicates, [])
        self.assertTrue((out / "classes.dex").is_file())
        self.assertTrue((out / "AndroidManifest.xml").is_file())
        self.assertTrue((out / "resources.arsc").is_file())

    def test_identical_duplicate_keeps_one_copy_and_is_reported(self) -> None:
        entries = real_apk_entries() + [("res/yHu.xml", b"<x/>", None), ("res/yHu.xml", b"<x/>", None)]
        arc = make_zip(self.tmp / "dup.apk", entries)
        out = self.tmp / "out"
        rep = safe_extract_zip(arc, out, **LIMITS)
        self.assertEqual((out / "res" / "yHu.xml").read_bytes(), b"<x/>")
        dup = [d for d in rep.duplicates if d["name"] == "res/yHu.xml"]
        self.assertEqual(len(dup), 1)
        self.assertEqual(dup[0]["status"], "identica")
        self.assertEqual(dup[0]["occurrences"], 2)
        self.assertEqual(dup[0]["quarantined"], [])
        self.assertFalse((self.tmp / "quarantine" / "conflitantes").exists())

    def test_conflicting_duplicate_is_quarantined_and_never_chosen(self) -> None:
        entries = real_apk_entries() + [("res/yHu.xml", b"<a/>", None), ("res/yHu.xml", b"<b/>", None)]
        arc = make_zip(self.tmp / "conflict.apk", entries)
        out = self.tmp / "out"
        rep = safe_extract_zip(arc, out, **LIMITS)
        self.assertFalse((out / "res" / "yHu.xml").exists(), "nenhuma versão deve ser escolhida")
        dup = [d for d in rep.duplicates if d["name"] == "res/yHu.xml"][0]
        self.assertEqual(dup["status"], "conflitante")
        self.assertIsNone(dup["kept"])
        self.assertEqual(len(dup["quarantined"]), 2)
        self.assertEqual(len(set(dup["sha256"])), 2)
        contents = sorted((self.tmp / "quarantine" / rel).read_bytes() for rel in dup["quarantined"])
        self.assertEqual(contents, [b"<a/>", b"<b/>"])
        # o restante do APK continua disponível para a análise
        self.assertTrue((out / "classes.dex").is_file())

    def test_original_archive_is_not_modified(self) -> None:
        arc = make_zip(self.tmp / "orig.apk", real_apk_entries() + [("r.xml", b"a", None), ("r.xml", b"b", None)])
        before = sha256_of(arc)
        safe_extract_zip(arc, self.tmp / "out", **LIMITS)
        self.assertEqual(sha256_of(arc), before)

    def test_path_traversal_and_unsafe_names_abort_without_writing(self) -> None:
        bad_names = ["../escape.txt", "/abs.txt", "a\\b.txt", "C:/drive.txt", "res/../../up.txt"]
        for i, bad in enumerate(bad_names):
            with self.subTest(name=bad):
                arc = make_zip(self.tmp / f"bad{i}.zip", [("ok.txt", b"1", None), (bad, b"2", None)])
                out = self.tmp / f"out{i}"
                with self.assertRaises(UnsafeArchiveError):
                    safe_extract_zip(arc, out, **LIMITS)
                self.assertFalse(out.exists())
        self.assertFalse((self.tmp / "escape.txt").exists())
        self.assertFalse((self.tmp / "up.txt").exists())

    def test_unsafe_names_are_listed_by_inventory(self) -> None:
        arc = make_zip(self.tmp / "inv.zip", [("ok.txt", b"1", None), ("../x.txt", b"2", None)])
        inv = inventory_zip(arc, max_entries=100)
        self.assertEqual(len(inv["unsafe_entries"]), 1)
        self.assertEqual(inv["unsafe_entries"][0]["name"], "../x.txt")

    def test_symlink_entry_is_skipped_and_never_created(self) -> None:
        arc = make_zip(self.tmp / "l.zip", [("link", b"/etc/passwd", 0o120777), ("real.txt", b"ok", None)])
        out = self.tmp / "out"
        rep = safe_extract_zip(arc, out, **LIMITS)
        self.assertFalse((out / "link").exists() or (out / "link").is_symlink())
        self.assertTrue(any("link simbólico" in s for s in rep.skipped))
        self.assertTrue((out / "real.txt").is_file())

    def test_invalid_zip_is_reported_not_crashing_the_process(self) -> None:
        bad = self.tmp / "random.apk"
        bad.write_bytes(os.urandom(4096))
        with self.assertRaises(zipfile.BadZipFile):
            safe_extract_zip(bad, self.tmp / "out", **LIMITS)
        with self.assertRaises(zipfile.BadZipFile):
            inventory_zip(bad, max_entries=100)

    def test_zip_bomb_is_stopped_by_measured_compression_ratio(self) -> None:
        bomb = make_zip(self.tmp / "bomb.zip", [("big.bin", b"\x00" * (32 * 1024 * 1024), None)])
        out = self.tmp / "out"
        with self.assertRaises(ArchiveLimitError):
            safe_extract_zip(bomb, out, **LIMITS)
        self.assertFalse(out.exists())

    def test_corrupted_stored_entry_fails_crc_check(self) -> None:
        arc = self.tmp / "crc.zip"
        with zipfile.ZipFile(arc, "w", zipfile.ZIP_STORED) as zf:
            zf.writestr("data.txt", b"HELLOWORLDPAYLOAD")
        raw = bytearray(arc.read_bytes())
        raw[raw.index(b"HELLOWORLD")] ^= 0x20  # altera um byte dos dados armazenados
        arc.write_bytes(bytes(raw))
        with self.assertRaises(UnsafeArchiveError):
            safe_extract_zip(arc, self.tmp / "out", **LIMITS)

    def test_inventory_counts_identical_and_conflicting_duplicates(self) -> None:
        arc = make_zip(self.tmp / "inv2.zip", [
            ("res/a.xml", b"same", None), ("res/a.xml", b"same", None),
            ("res/b.xml", b"one", None), ("res/b.xml", b"two", None),
        ])
        inv = inventory_zip(arc, max_entries=100)
        by_name = {d["name"]: d for d in inv["duplicates"]}
        self.assertEqual(by_name["res/a.xml"]["crc_and_size"], "iguais")
        self.assertEqual(by_name["res/b.xml"]["crc_and_size"], "diferentes")
        self.assertEqual(inv["unique_names"], 2)


if __name__ == "__main__":
    unittest.main()
