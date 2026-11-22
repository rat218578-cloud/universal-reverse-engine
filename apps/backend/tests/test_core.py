"""Testes unitários: identificação, PE, extração segura, caminhos e armazenamento."""
from __future__ import annotations

import shutil
import tempfile
import unittest
import warnings
from pathlib import Path

from tests.helpers import SYMLINK_SKIP_REASON, can_create_symlinks, find_real_pe, make_zip, synthetic_apk, synthetic_pe32
from ure.identify import KIND_APK, KIND_CORRUPT, KIND_ELF, KIND_EMPTY, KIND_JAR, KIND_PE, KIND_UNKNOWN, identify
from ure.pe import PEError, parse_pe
from ure.safezip import ArchiveLimitError, UnsafeArchiveError, clean_entry_name, safe_extract_zip
from ure.storage import PathRejectedError, artifact_root, safe_join, valid_id


class TmpCase(unittest.TestCase):
    def setUp(self) -> None:
        self._td = tempfile.mkdtemp()
        self.tmp = Path(self._td)

    def tearDown(self) -> None:
        shutil.rmtree(self._td, ignore_errors=True)


class IdentifyTests(TmpCase):
    def test_real_pe_identified_and_parsed(self) -> None:
        pe = find_real_pe()
        if pe is None:
            self.skipTest("nenhum PE real disponível neste ambiente")
        result = identify(pe)
        self.assertEqual(result["kind"], KIND_PE)
        d = result["details"]
        self.assertIn(d["format"], ("PE32", "PE32+"))
        self.assertTrue(d["sections"], "PE real deve ter seções")
        self.assertIn(d["machine"], ("x86", "x64"))
        self.assertIsInstance(d["import_count"], int)

    def test_real_elf_identified(self) -> None:
        elf = Path("/usr/bin/ls")
        if not elf.is_file():
            self.skipTest("ELF de referência ausente")
        result = identify(elf)
        self.assertEqual(result["kind"], KIND_ELF)
        self.assertEqual(result["details"]["bits"], 64)

    def test_synthetic_pe_parsed_exactly(self) -> None:
        pe = synthetic_pe32(self.tmp / "sample.exe")
        d = parse_pe(pe)
        self.assertEqual(d["format"], "PE32")
        self.assertEqual(d["machine"], "x86")
        self.assertEqual(d["subsystem"], "windows-cui")
        self.assertFalse(d["is_dll"])
        self.assertEqual(d["imports"], {"KERNEL32.dll": ["ExitProcess"]})
        self.assertEqual(d["import_count"], 1)
        self.assertEqual(d["sections"][0]["name"], ".idata")
        self.assertFalse(d["signed"])
        self.assertEqual(d["overlay_bytes"], 0)

    def test_mz_without_pe_header_is_corrupt(self) -> None:
        f = self.tmp / "bad.exe"
        f.write_bytes(b"MZ" + b"\x00" * 200)
        self.assertEqual(identify(f)["kind"], KIND_CORRUPT)

    def test_pe_with_truncated_section_table_rejected(self) -> None:
        pe = synthetic_pe32(self.tmp / "ok.exe")
        data = pe.read_bytes()[:0x150]
        cut = self.tmp / "cut.exe"
        cut.write_bytes(data)
        with self.assertRaises(PEError):
            parse_pe(cut)

    def test_empty_file(self) -> None:
        f = self.tmp / "empty.apk"
        f.write_bytes(b"")
        self.assertEqual(identify(f)["kind"], KIND_EMPTY)

    def test_extension_does_not_decide_format(self) -> None:
        f = self.tmp / "fake.exe"
        f.write_text("isto é texto, não um executável")
        self.assertEqual(identify(f)["kind"], KIND_UNKNOWN)

    def test_apk_structure_detected(self) -> None:
        apk = synthetic_apk(self.tmp / "app.apk")
        self.assertEqual(identify(apk)["kind"], KIND_APK)

    def test_jar_detected(self) -> None:
        jar = make_zip(self.tmp / "lib.jar", [("META-INF/MANIFEST.MF", b"Manifest-Version: 1.0\n", None)])
        self.assertEqual(identify(jar)["kind"], KIND_JAR)

    def test_truncated_zip_is_corrupt(self) -> None:
        f = self.tmp / "broken.apk"
        f.write_bytes(b"PK\x03\x04" + b"lixo" * 10)
        self.assertEqual(identify(f)["kind"], KIND_CORRUPT)


class SafeZipTests(TmpCase):
    LIMITS = {"max_entries": 1000, "max_total_bytes": 64 * 1024 * 1024, "max_ratio": 200.0}

    def test_normal_extraction(self) -> None:
        apk = synthetic_apk(self.tmp / "a.apk")
        out = self.tmp / "out"
        report = safe_extract_zip(apk, out, **self.LIMITS)
        self.assertEqual(report.files, 3)
        self.assertEqual((out / "assets/notes.txt").read_text(), "hello from ure\n")

    def test_bad_names_rejected(self) -> None:
        for name in ["../evil", "a/../../evil", "/etc/passwd", "C:/x.dll", "a\\b", "x\x00y", ""]:
            with self.subTest(name=name), self.assertRaises(UnsafeArchiveError):
                clean_entry_name(name)

    def test_traversal_in_archive_writes_nothing_outside(self) -> None:
        arc = make_zip(self.tmp / "t.zip", [("ok.txt", b"x", None), ("../../escape.txt", b"pwn", None)])
        out = self.tmp / "dest" / "out"
        with self.assertRaises(UnsafeArchiveError):
            safe_extract_zip(arc, out, **self.LIMITS)
        self.assertFalse((self.tmp / "dest" / "escape.txt").exists())
        self.assertFalse((self.tmp / "escape.txt").exists())

    def test_symlink_entry_is_skipped_not_created(self) -> None:
        arc = make_zip(self.tmp / "l.zip", [("link", b"/etc/passwd", 0o120777), ("real.txt", b"ok", None)])
        out = self.tmp / "out"
        report = safe_extract_zip(arc, out, **self.LIMITS)
        self.assertFalse((out / "link").exists() or (out / "link").is_symlink())
        self.assertTrue(any("link simbólico" in s for s in report.skipped))
        self.assertTrue((out / "real.txt").is_file())

    def test_duplicate_names_rejected(self) -> None:
        arc = self.tmp / "d.zip"
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            make_zip(arc, [("A.txt", b"1", None), ("a.txt", b"2", None)])
        with self.assertRaises(UnsafeArchiveError):
            safe_extract_zip(arc, self.tmp / "out", **self.LIMITS)

    def test_entry_count_limit(self) -> None:
        arc = make_zip(self.tmp / "n.zip", [(f"f{i}.txt", b"x", None) for i in range(5)])
        with self.assertRaises(ArchiveLimitError):
            safe_extract_zip(arc, self.tmp / "out", **{**self.LIMITS, "max_entries": 3})

    def test_total_size_limit(self) -> None:
        arc = make_zip(self.tmp / "s.zip", [("big.bin", b"a" * 4096, None)])
        with self.assertRaises(ArchiveLimitError):
            safe_extract_zip(arc, self.tmp / "out", **{**self.LIMITS, "max_total_bytes": 1024})

    def test_zip_bomb_detected_by_declared_ratio(self) -> None:
        arc = make_zip(self.tmp / "bomb.zip", [("zeros.bin", b"\x00" * (8 * 1024 * 1024), None)])
        with self.assertRaises(ArchiveLimitError):
            safe_extract_zip(arc, self.tmp / "out", **self.LIMITS)

    def test_high_entropy_file_is_not_flagged(self) -> None:
        import os as _os

        arc = make_zip(self.tmp / "rand.zip", [("rand.bin", _os.urandom(2 * 1024 * 1024), None)])
        report = safe_extract_zip(arc, self.tmp / "out", **self.LIMITS)
        self.assertEqual(report.files, 1)


class StorageTests(TmpCase):
    def test_safe_join_blocks_traversal_and_absolute(self) -> None:
        base = self.tmp / "base"
        base.mkdir()
        for bad in ["../x", "a/../../x", "/etc/passwd", "a\\b", "x\x00"]:
            with self.subTest(path=bad), self.assertRaises(PathRejectedError):
                safe_join(base, bad)

    @unittest.skipUnless(can_create_symlinks(), SYMLINK_SKIP_REASON)
    def test_safe_join_blocks_symlink_component(self) -> None:
        base = self.tmp / "base"
        base.mkdir()
        (self.tmp / "outside").mkdir()
        (base / "link").symlink_to(self.tmp / "outside")
        with self.assertRaises(PathRejectedError):
            safe_join(base, "link/secret.txt")

    def test_safe_join_accepts_normal_paths(self) -> None:
        base = self.tmp / "base"
        (base / "a").mkdir(parents=True)
        self.assertEqual(safe_join(base, "a/./b.txt"), base / "a" / "b.txt")

    def test_ids_validated(self) -> None:
        self.assertTrue(valid_id("0" * 32))
        self.assertFalse(valid_id("../../etc"))
        self.assertFalse(valid_id("G" * 32))
        with self.assertRaises(PathRejectedError):
            artifact_root(self.tmp, "../x", "0" * 32)


if __name__ == "__main__":
    unittest.main()
