"""Androguard, apksigner e radare2: execução real sobre os arquivos de tests/fixtures/real.

Cada teste roda a ferramenta de verdade. Ele só é pulado quando a ferramenta não está instalada
neste servidor, e a ausência aparece como motivo no teste. Nenhum resultado é simulado.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from ure.config import Settings
from ure.engines import androguard_decompile, androguard_summary, apksigner_verify, monodis_disassemble, radare2_functions
from ure.tools import SPECS_BY_KEY, load_tools_env, probe_all, resolve

load_tools_env()  # respeita URE_TOOLS_ENV / tools.env instalado pelo script
FIXTURES = Path(__file__).parent / "fixtures" / "real"
FIXTURE_APK = FIXTURES / "fixture.apk"
FIXTURE_SO = FIXTURES / "libfixture.so"
HAS_ANDROGUARD = {r["key"]: r for r in probe_all()}["androguard"]["status"] == "available"  # módulo Python
HAS_APKSIGNER = resolve(SPECS_BY_KEY["apksigner"]) is not None
HAS_R2 = resolve(SPECS_BY_KEY["radare2"]) is not None
HAS_KEYTOOL = shutil.which("keytool") is not None
HAS_MONODIS = resolve(SPECS_BY_KEY["monodis"]) is not None
DOTNET_SAMPLE = Path(__file__).parent / "fixtures" / "dotnet" / "UreSample.dll"


class _Work(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.logs = self.tmp / "logs"
        self.logs.mkdir()
        self.settings = Settings.from_env()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)


class AndroguardTests(_Work):
    @unittest.skipUnless(HAS_ANDROGUARD, "Androguard não instalado neste servidor")
    def test_summary_reads_manifest_and_classes_of_real_apk(self) -> None:
        res = androguard_summary(FIXTURE_APK, self.settings, self.logs, "fx")
        self.assertEqual(res["status"], "ok", res)
        self.assertEqual(res["result"]["package"], "com.ure.fixture")
        self.assertEqual(res["result"]["min_sdk"], "31")
        self.assertIn("com.ure.fixture.Main", res["result"]["activities"])
        self.assertIn("Lcom/ure/fixture/Main;", res["result"]["classes_sample"])

    @unittest.skipUnless(HAS_ANDROGUARD, "Androguard não instalado neste servidor")
    def test_summary_of_non_apk_is_failed_with_reason_not_missing(self) -> None:
        res = androguard_summary(FIXTURE_SO, self.settings, self.logs, "so")
        self.assertEqual(res["status"], "failed", res)
        self.assertTrue(res["reason"], res)

    @unittest.skipUnless(HAS_ANDROGUARD, "Androguard não instalado neste servidor")
    def test_decompile_produces_java_source_from_dex(self) -> None:
        out = self.tmp / "java"
        res = androguard_decompile(FIXTURE_APK, out, self.settings, self.logs)
        self.assertEqual(res["status"], "ok", res)
        self.assertGreaterEqual(res["produced"]["java_sources"], 1)
        source = (out / "com" / "ure" / "fixture" / "Main.java").read_text(encoding="utf-8")
        self.assertIn("public class Main", source)
        self.assertIn("hello from fixture", source)


class ApksignerTests(_Work):
    @unittest.skipUnless(HAS_APKSIGNER, "apksigner não instalado neste servidor")
    def test_unsigned_apk_is_reported_as_not_verified_with_reason(self) -> None:
        res = apksigner_verify(FIXTURE_APK, self.settings, self.logs, "unsigned")
        self.assertEqual(res["status"], "ok", res)
        self.assertFalse(res["verified"], res)
        self.assertTrue(res["reasons"], res)

    @unittest.skipUnless(HAS_APKSIGNER and HAS_KEYTOOL, "apksigner ou keytool ausente")
    def test_signed_apk_reports_certificate_digest(self) -> None:
        key = self.tmp / "test.jks"
        subprocess.run(["keytool", "-genkeypair", "-keystore", str(key), "-storepass", "ure-test-pass",
                        "-keypass", "ure-test-pass", "-alias", "ure", "-keyalg", "RSA", "-keysize", "2048",
                        "-validity", "2", "-dname", "CN=URE Teste, O=URE, C=BR"],
                       check=True, capture_output=True)
        signed = self.tmp / "signed.apk"
        subprocess.run(["apksigner", "sign", "--ks", str(key), "--ks-pass", "pass:ure-test-pass",
                        "--ks-key-alias", "ure", "--key-pass", "pass:ure-test-pass",
                        "--out", str(signed), str(FIXTURE_APK)], check=True, capture_output=True)
        res = apksigner_verify(signed, self.settings, self.logs, "signed")
        self.assertEqual(res["status"], "ok", res)
        self.assertTrue(res["verified"], res)
        self.assertEqual(res["signers"][0]["dn"], "CN=URE Teste, O=URE, C=BR")
        self.assertEqual(len(res["signers"][0]["sha256"]), 64)


class Radare2Tests(_Work):
    @unittest.skipUnless(HAS_R2, "radare2 não instalado neste servidor")
    def test_native_library_functions_are_listed(self) -> None:
        res = radare2_functions(FIXTURE_SO, self.settings, self.logs, "so")
        self.assertEqual(res["status"], "ok", res)
        self.assertIn("sym.ure_fixture_add", res["result"]["names"])
        self.assertGreaterEqual(res["result"]["functions"], 1)


class MonodisTests(_Work):
    @unittest.skipUnless(HAS_MONODIS, "monodis não instalado neste servidor")
    def test_il_of_dotnet_assembly_contains_the_method(self) -> None:
        res = monodis_disassemble(DOTNET_SAMPLE, self.tmp / "il", self.settings, self.logs)
        self.assertEqual(res["status"], "ok", res)
        text = (self.tmp / "il" / "assembly.il").read_text(encoding="utf-8")
        self.assertIn("Calc::Add", text)
        self.assertGreaterEqual(res["produced"]["methods"], 2)

    @unittest.skipUnless(HAS_MONODIS, "monodis não instalado neste servidor")
    def test_non_dotnet_file_is_failed_even_though_monodis_exits_zero(self) -> None:
        res = monodis_disassemble(FIXTURE_SO, self.tmp / "il", self.settings, self.logs)
        self.assertEqual(res["status"], "failed", res)
        self.assertIn("não é um assembly .NET", res["reason"])


class ProbeOfNewToolsTests(unittest.TestCase):
    def test_new_tools_are_reported_with_real_state(self) -> None:
        rows = {r["key"]: r for r in probe_all()}
        for key in ("androguard", "radare2", "apksigner", "monodis"):
            self.assertIn(key, rows)
            if rows[key]["status"] == "available":
                self.assertTrue(rows[key]["version"], rows[key])
            else:
                self.assertTrue(rows[key]["note"], rows[key])


if __name__ == "__main__":
    unittest.main()
