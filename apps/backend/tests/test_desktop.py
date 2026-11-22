"""Contrato usado pelo lançador desktop (apps/desktop) e garantias de processo.

Estes testes rodam em qualquer plataforma e não dependem de Tauri nem de Windows:
sobem o backend como processo real, exatamente como o lançador faz, e verificam
autenticação, Host, persistência entre reinícios e liberação da porta ao encerrar.
"""
from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from ure.tools import child_env, kill_tree

BACKEND_ROOT = Path(__file__).resolve().parents[1]
TOKEN = "t" * 64  # mesmo formato do lançador: 32 bytes em hexadecimal


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def port_open(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", port)) == 0


class ChildEnvTests(unittest.TestCase):
    def test_windows_runtime_variables_are_forwarded(self) -> None:
        source = {"PATH": "C:\\bin", "SYSTEMROOT": "C:\\Windows", "PATHEXT": ".EXE;.BAT", "USERPROFILE": "C:\\u"}
        env = child_env(source, platform_name="nt")
        self.assertEqual(env["SYSTEMROOT"], "C:\\Windows")
        self.assertEqual(env["PATHEXT"], ".EXE;.BAT")
        self.assertEqual(env["USERPROFILE"], "C:\\u")

    def test_windows_only_variables_are_not_forwarded_on_posix(self) -> None:
        env = child_env({"PATH": "/bin", "SYSTEMROOT": "x"}, platform_name="posix")
        self.assertEqual(env, {"PATH": "/bin"})

    def test_secrets_from_user_environment_are_never_forwarded(self) -> None:
        source = {"PATH": "/bin", "URE_TOKEN": "segredo", "URE_EXTERNAL_AI_KEY": "k", "AWS_SECRET_ACCESS_KEY": "s"}
        env = child_env(source, platform_name="posix")
        self.assertNotIn("URE_TOKEN", env)
        self.assertNotIn("URE_EXTERNAL_AI_KEY", env)
        self.assertNotIn("AWS_SECRET_ACCESS_KEY", env)


class KillTreeTests(unittest.TestCase):
    def test_kill_tree_terminates_running_process(self) -> None:
        proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        kill_tree(proc)
        self.assertIsNotNone(proc.returncode)

    def test_kill_tree_on_windows_invokes_taskkill_with_tree_flag(self) -> None:
        proc = mock.Mock(pid=4242)
        with mock.patch("ure.tools.os.name", "nt"), mock.patch("ure.tools.subprocess.run") as run:
            kill_tree(proc)
        argv = run.call_args.args[0]
        self.assertEqual(argv[:1], ["taskkill"])
        self.assertIn("/T", argv)
        self.assertIn("4242", argv)
        proc.kill.assert_called_once()


class LauncherContractTests(unittest.TestCase):
    """Sobe o backend como o lançador faz: processo filho, token por ambiente, porta escolhida."""

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.data = self.tmp / "data"
        self.port = free_port()
        self.proc: subprocess.Popen | None = None

    def tearDown(self) -> None:
        if self.proc is not None and self.proc.poll() is None:
            kill_tree(self.proc)
        shutil.rmtree(self.tmp, ignore_errors=True)

    def start(self) -> None:
        env = {k: v for k, v in os.environ.items() if not k.startswith("URE_")}
        env.update({
            "URE_HOST": "127.0.0.1",
            "URE_PORT": str(self.port),
            "URE_TOKEN": TOKEN,
            "URE_DATA_DIR": str(self.data),
            "URE_CONFIG": str(self.tmp / "inexistente.env"),
            "PYTHONUNBUFFERED": "1",
            "URE_PARENT_WATCH": "1",
        })
        self.log = self.tmp / "backend.log"
        with self.log.open("wb") as log_file:
            self.proc = subprocess.Popen(
                [sys.executable, "-m", "ure.server"], cwd=BACKEND_ROOT, env=env,
                stdin=subprocess.PIPE, stdout=log_file, stderr=subprocess.STDOUT,
            )
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                self.fail("backend terminou antes de responder: " + self.log.read_text(errors="replace"))
            try:
                if self.request("GET", "/api/v1/health")[0] == 200:
                    return
            except OSError:
                pass
            time.sleep(0.1)
        self.fail("backend não respondeu à verificação de saúde")

    def request(self, method: str, path: str, token: str | None = TOKEN, host: str | None = None,
                body: dict | None = None) -> tuple[int, dict]:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}", data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if token is not None:
            req.add_header("Authorization", f"Bearer {token}")
        if host is not None:
            req.add_header("Host", host)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                raw = resp.read()
                return resp.status, json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            return exc.code, {}

    def test_health_is_public_and_api_requires_launcher_token(self) -> None:
        self.start()
        self.assertEqual(self.request("GET", "/api/v1/health", token=None)[0], 200)
        self.assertEqual(self.request("GET", "/api/v1/projects", token=None)[0], 401)
        self.assertEqual(self.request("GET", "/api/v1/projects", token="errado")[0], 401)
        self.assertEqual(self.request("GET", "/api/v1/projects")[0], 200)

    def test_foreign_host_header_is_refused(self) -> None:
        self.start()
        self.assertEqual(self.request("GET", "/api/v1/projects", host="evil.example")[0], 403)

    def test_projects_survive_restart_and_port_is_released_on_stop(self) -> None:
        self.start()
        status, project = self.request("POST", "/api/v1/projects", body={"name": "Persistente"})
        self.assertEqual(status, 201)
        pid = project["id"]

        kill_tree(self.proc)
        self.assertFalse(port_open(self.port), "porta deve ser liberada após o encerramento")

        self.start()
        status, listing = self.request("GET", "/api/v1/projects")
        self.assertEqual(status, 200)
        self.assertIn(pid, [p["id"] for p in listing["projects"]])
        self.assertEqual(self.request("GET", f"/api/v1/projects/{pid}")[1]["name"], "Persistente")

    def test_backend_exits_when_launcher_pipe_closes(self) -> None:
        """Simula o aplicativo morrendo sem encerrar o backend: o pipe de stdin é fechado."""
        self.start()
        self.proc.stdin.close()
        self.assertEqual(self.proc.wait(timeout=15), 0)
        self.assertFalse(port_open(self.port), "porta deve ser liberada quando o backend se encerra sozinho")

    def test_data_dir_receives_no_token_file_when_token_is_supplied(self) -> None:
        self.start()
        self.assertFalse((self.data / "session.token").exists(),
                         "o lançador já fornece o token; o arquivo não deve ser criado")


if __name__ == "__main__":
    unittest.main()
