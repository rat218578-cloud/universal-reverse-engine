"""Testes da versão 1.0.0: arquivo de configuração ure.env, versão exposta pela API e documentação de release."""
from __future__ import annotations

import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from tests.test_api import ApiCase
from ure import __version__
from ure.config import Settings, load_env_file

REPO = Path(__file__).resolve().parents[3]


class EnvFileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_values_loaded_from_file(self) -> None:
        f = self.tmp / "ure.env"
        f.write_text("# comentário\nURE_PORT=9123\nURE_MAX_UPLOAD_MB = 64\nURE_AI_ENABLED=\"0\"\nOUTRA_VAR=1\n")
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("URE_PORT", None)
            os.environ.pop("URE_MAX_UPLOAD_MB", None)
            self.assertEqual(load_env_file(f), 3)
            self.assertEqual(os.environ["URE_PORT"], "9123")
            self.assertEqual(os.environ["URE_MAX_UPLOAD_MB"], "64")
            self.assertNotIn("OUTRA_VAR", os.environ, "só chaves URE_ são aceitas")

    def test_environment_takes_precedence_over_file(self) -> None:
        f = self.tmp / "ure.env"
        f.write_text("URE_PORT=9123\n")
        with mock.patch.dict(os.environ, {"URE_PORT": "7000"}):
            load_env_file(f)
            self.assertEqual(os.environ["URE_PORT"], "7000")

    def test_missing_file_is_not_an_error(self) -> None:
        self.assertEqual(load_env_file(self.tmp / "nao-existe.env"), 0)

    def test_from_env_reads_config_path_from_variable(self) -> None:
        f = self.tmp / "custom.env"
        f.write_text("URE_PORT=9124\n")
        with mock.patch.dict(os.environ, {"URE_CONFIG": str(f)}, clear=False):
            os.environ.pop("URE_PORT", None)
            self.assertEqual(Settings.from_env().port, 9124)
            os.environ.pop("URE_PORT", None)


class ReleaseVersionTests(ApiCase):
    def test_package_and_api_report_version_1_0_0(self) -> None:
        self.assertEqual(__version__, "1.0.0")
        self.assertEqual(self.js("GET", "/api/v1/health")[1]["version"], "1.0.0")

    def test_release_documents_exist(self) -> None:
        for name in ["LICENSE", "CHANGELOG.md", "INSTALL.md", "ure.env.example",
                     "docs/PRIMEIROS-PASSOS.md", "docs/SOLUCAO-DE-PROBLEMAS.md"]:
            self.assertTrue((REPO / name).is_file(), name)

    def test_changelog_has_1_0_0_entry(self) -> None:
        self.assertIn("## 1.0.0 ", (REPO / "CHANGELOG.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
