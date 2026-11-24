"""Ambiente de ferramentas: sondagem real, dependências, teste de execução, arquivo de ambiente,
API de ferramentas e persistência após reinício do servidor."""
from __future__ import annotations

import io
import os
import shutil
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from tests.helpers import run_server_in_thread
from tests.test_api import ApiCase
from ure.app import make_server
from ure.tools import SPECS, SPECS_BY_KEY, load_tools_env, probe_all, resolve, self_test, startup_lines

load_tools_env()  # respeita URE_TOOLS_ENV / tools.env instalado pelo script
HAS_APKTOOL = resolve(SPECS_BY_KEY["apktool"]) is not None


class ProbeTests(unittest.TestCase):
    def test_every_spec_is_reported_with_real_state(self) -> None:
        rows = {r["key"]: r for r in probe_all()}
        self.assertEqual(set(rows), {s.key for s in SPECS})
        for row in rows.values():
            self.assertIn(row["status"], ("available", "missing"))
            if row["status"] == "available":
                self.assertTrue(row["path"] and os.path.exists(row["path"]), row)
                self.assertTrue(row["version"])
            else:
                # Para o LIEF, o caminho informa o interpretador testado (útil para diagnóstico).
                if row["key"] != "lief":
                    self.assertIsNone(row["path"])
                self.assertTrue(row["note"], "ausência precisa de motivo")

    def test_missing_dependency_is_listed_as_pending(self) -> None:
        real_resolve = resolve

        def fake_resolve(spec):
            return None if spec.key == "java" else real_resolve(spec)

        with mock.patch("ure.tools.resolve", side_effect=fake_resolve):
            rows = {r["key"]: r for r in probe_all()}
        self.assertEqual(rows["apktool"]["pending"], ["java"])
        self.assertIn("dependência ausente: java", rows["apktool"]["note"])
        self.assertEqual(rows["java"]["status"], "missing")

    def test_missing_tool_keeps_its_reason_and_lists_missing_dependency(self) -> None:
        real_resolve = resolve

        def fake_resolve(spec):
            return None if spec.key in ("java", "apktool") else real_resolve(spec)

        with mock.patch("ure.tools.resolve", side_effect=fake_resolve):
            rows = {r["key"]: r for r in probe_all()}
        self.assertEqual(rows["apktool"]["status"], "missing")
        self.assertIn("não encontrado", rows["apktool"]["note"])
        self.assertIn("dependência ausente: java", rows["apktool"]["note"])

    @unittest.skipUnless(HAS_APKTOOL, "apktool não instalado neste servidor")
    def test_self_test_runs_apktool_for_real(self) -> None:
        result = self_test(SPECS_BY_KEY["apktool"])
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["exit_code"], 0)
        self.assertTrue(result["detail"].strip())

    def test_self_test_of_missing_tool_is_not_ok(self) -> None:
        with mock.patch("ure.tools.resolve", return_value=None):
            result = self_test(SPECS_BY_KEY["jadx"])
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "missing")

    def test_startup_lines_show_status_path_and_reason(self) -> None:
        rows = [
            {"key": "apktool", "status": "available", "version": "2.7.0", "path": "/usr/bin/apktool", "note": ""},
            {"key": "jadx", "status": "missing", "version": None, "path": None, "note": "não encontrado"},
        ]
        lines = startup_lines(rows)
        self.assertEqual(lines[0], "[ferramentas] apktool: 2.7.0 em /usr/bin/apktool")
        self.assertEqual(lines[1], "[ferramentas] jadx: AUSENTE. não encontrado")


class RunToolLimitsTests(unittest.TestCase):
    def test_limited_run_caps_jvm_heap_below_address_space_limit(self) -> None:
        from ure import tools as ure_tools

        captured: dict = {}

        class FakeProc:
            returncode = 0

            def __init__(self, cmd, **kwargs):
                captured["env"] = kwargs["env"]
                self.stdout = io.BytesIO(b"")
                self.stderr = io.BytesIO(b"")

            def wait(self, timeout=None):
                return 0

        tmp = Path(tempfile.mkdtemp())
        try:
            with mock.patch.object(ure_tools.subprocess, "Popen", FakeProc):
                ure_tools.run_tool(["/bin/true"], cwd=tmp, timeout_s=10, memory_mb=3072,
                                   log=tmp / "x.log")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        if os.name == "posix":
            self.assertEqual(captured["env"]["JAVA_TOOL_OPTIONS"], "-Xmx1536m")


class ToolsEnvFileTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_loads_only_ure_keys_and_never_overrides_environment(self) -> None:
        env_file = self.tmp / "tools.env"
        env_file.write_text("URE_TEST_TOOLS_KEY=do-arquivo\nPATH=/nada\nURE_TEST_ALREADY=do-arquivo\n", encoding="utf-8")
        env = {"URE_TOOLS_ENV": str(env_file), "URE_TEST_ALREADY": "do-ambiente"}
        with mock.patch.dict(os.environ, env, clear=False):
            os.environ.pop("URE_TEST_TOOLS_KEY", None)
            loaded = load_tools_env()
            self.assertEqual(loaded, env_file)
            self.assertEqual(os.environ["URE_TEST_TOOLS_KEY"], "do-arquivo")
            self.assertEqual(os.environ["URE_TEST_ALREADY"], "do-ambiente")
            self.assertNotEqual(os.environ.get("PATH"), "/nada")

    def test_missing_env_file_is_not_an_error(self) -> None:
        with mock.patch.dict(os.environ, {"URE_TOOLS_ENV": str(self.tmp / "inexistente.env")}):
            self.assertIsNone(load_tools_env())


class ToolsApiTests(ApiCase):
    def test_tools_endpoint_reports_pending_and_requires(self) -> None:
        status, body = self.js("GET", "/api/v1/tools")
        self.assertEqual(status, 200)
        rows = {r["key"]: r for r in body["tools"]}
        self.assertIn("requires", rows["apktool"])
        self.assertIn("pending", rows["apktool"])
        self.assertIn("java", rows["apktool"]["requires"])

    @unittest.skipUnless(HAS_APKTOOL, "apktool não instalado neste servidor")
    def test_self_test_endpoint_runs_the_tool(self) -> None:
        status, body = self.js("POST", "/api/v1/tools/apktool/test", {})
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"], body)

    def test_self_test_endpoint_rejects_unknown_tool(self) -> None:
        status, body = self.js("POST", "/api/v1/tools/nao-existe/test", {})
        self.assertEqual(status, 404)

    def test_self_test_endpoint_requires_token(self) -> None:
        saved = self.token
        self.token = None
        try:
            status, _ = self.js("POST", "/api/v1/tools/apktool/test", {})
        finally:
            self.token = saved
        self.assertIn(status, (401, 403))


class RestartTests(ApiCase):
    def test_projects_and_tool_state_survive_server_restart(self) -> None:
        pid = self.new_project("Antes do reinício")
        before = {r["key"]: r["status"] for r in self.js("GET", "/api/v1/tools")[1]["tools"]}
        self.server.shutdown()
        self.server.server_close()
        self.server = make_server(self.settings)
        self.port = self.server.server_address[1]
        run_server_in_thread(self.server)
        status, projects = self.js("GET", "/api/v1/projects")
        self.assertEqual(status, 200)
        self.assertIn(pid, [p["id"] for p in projects["projects"]] if isinstance(projects, dict) else [p["id"] for p in projects])
        after = {r["key"]: r["status"] for r in self.js("GET", "/api/v1/tools")[1]["tools"]}
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
