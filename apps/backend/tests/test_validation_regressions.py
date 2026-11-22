"""Regressões da validação de release (1.0.0rc1). Cada teste reproduz um problema comprovado
na validação e falharia na RC original (bd51013)."""
from __future__ import annotations

import io
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

from tests.helpers import make_stub, make_zip
from tests.test_api import ApiCase
from ure.config import Settings
from ure.tools import SPECS_BY_KEY, probe, run_tool
from ure.tools import MB


class ToolOutputTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_java_version_skips_jvm_warning_lines(self) -> None:
        """RC: a versão exibida era 'Picked up JAVA_TOOL_OPTIONS...' (primeira linha do stderr)."""
        stub = make_stub(self.tmp / "java-stub",
                         ["echo 'Picked up JAVA_TOOL_OPTIONS: -Dteste=1' >&2",
                          "echo 'openjdk version \"21.0.1\" 2023-10-17' >&2"],
                         ["echo Picked up JAVA_TOOL_OPTIONS: -Dteste=1 1>&2",
                          "echo openjdk version \"21.0.1\" 2023-10-17 1>&2"])
        with mock.patch.dict(os.environ, {"URE_JAVA": str(stub)}):
            info = probe(SPECS_BY_KEY["java"])
        self.assertEqual(info["status"], "available")
        self.assertEqual(info["version"], 'openjdk version "21.0.1" 2023-10-17')

    def test_engine_log_is_capped(self) -> None:
        """RC: a regressão da reescrita gravava stdout sem limite (49 MiB medidos num teste)."""
        code = "import sys\nfor i in range(60000):\n    sys.stdout.write('x' * 256 + '\\n')\n"  # ~15 MiB
        res = run_tool([sys.executable, "-c", code], cwd=self.tmp, timeout_s=60, memory_mb=512,
                       log=self.tmp / "big.log")
        self.assertEqual(res["status"], "ok", "processo deve terminar mesmo com saída maior que o limite")
        size = (self.tmp / "big.log").stat().st_size
        self.assertLessEqual(size, 4 * MB + 200, f"log com {size} bytes ultrapassa o teto")
        self.assertIn(b"saida truncada", (self.tmp / "big.log").read_bytes())

    def test_engine_stdout_file_is_capped_and_stderr_separate(self) -> None:
        code = ("import sys\nsys.stderr.write('aviso-do-motor\\n')\n"
                "for i in range(30000):\n    sys.stdout.write('y' * 512 + '\\n')\n")
        out = self.tmp / "saida.xml"
        res = run_tool([sys.executable, "-c", code], cwd=self.tmp, timeout_s=60, memory_mb=512,
                       log=self.tmp / "err.log", stdout_file=out)
        self.assertEqual(res["status"], "ok")
        self.assertLessEqual(out.stat().st_size, 4 * MB + 200)
        self.assertIn(b"aviso-do-motor", (self.tmp / "err.log").read_bytes())
        self.assertNotIn(b"yyyy", (self.tmp / "err.log").read_bytes())

    def test_output_below_cap_is_kept_whole(self) -> None:
        res = run_tool([sys.executable, "-c", "print('ok-sem-erro')"], cwd=self.tmp, timeout_s=30,
                       memory_mb=512, log=self.tmp / "s.log")
        self.assertEqual(res["status"], "ok")
        self.assertEqual((self.tmp / "s.log").read_bytes().strip(), b"ok-sem-erro")


class HttpRegressionTests(ApiCase):
    def test_rejection_message_is_plain_language(self) -> None:
        """RC: 'formato não aceito: unknown. assinatura não reconhecida' (termo técnico ao usuário)."""
        pid = self.new_project()
        status, raw, _ = self.call("POST", f"/api/v1/projects/{pid}/artifacts", b"isto e so texto " * 20,
                                   {"X-Filename": "falso.exe"})
        self.assertEqual(status, 415)
        message = __import__("json").loads(raw)["error"]
        self.assertIn("formato não aceito", message)
        self.assertNotIn("unknown", message)
        self.assertIn("APK", message)

    def test_client_disconnect_does_not_produce_tracebacks(self) -> None:
        """RC: cliente que desconecta no meio de um upload gerava tracebacks (BrokenPipeError)."""
        pid = self.new_project()
        buf = io.StringIO()
        with redirect_stderr(buf):
            for _ in range(3):
                s = socket.create_connection(("127.0.0.1", self.port), timeout=10)
                s.sendall((f"POST /api/v1/projects/{pid}/artifacts HTTP/1.0\r\nHost: 127.0.0.1:{self.port}\r\n"
                           f"Authorization: Bearer {self.token}\r\nX-Filename: parcial.apk\r\n"
                           f"Content-Length: {50 * 1024 * 1024}\r\n\r\n").encode() + b"x" * 4096)
                s.close()
            s = socket.create_connection(("127.0.0.1", self.port), timeout=10)
            s.sendall((f"POST /api/v1/projects HTTP/1.0\r\nHost: 127.0.0.1:{self.port}\r\n"
                       f"Authorization: Bearer {self.token}\r\nContent-Type: application/json\r\n"
                       f"Content-Length: 500\r\n\r\n{{\"na").encode())
            s.close()
            time.sleep(1.5)
        self.assertNotIn("Traceback", buf.getvalue(), buf.getvalue()[:500])
        self.assertEqual(self.js("GET", "/api/v1/projects")[0], 200, "servidor deve continuar atendendo")

    def test_busy_port_gives_clear_message_not_traceback(self) -> None:
        blocker = socket.socket()
        blocker.bind(("127.0.0.1", 0))
        blocker.listen(1)
        port = blocker.getsockname()[1]
        tmp = Path(tempfile.mkdtemp())
        try:
            env = dict(os.environ, URE_DATA_DIR=str(tmp / "d"), URE_PORT=str(port))
            proc = subprocess.run([sys.executable, "-m", "ure.server"], env=env, cwd=str(Path(__file__).resolve().parents[1]),
                                  capture_output=True, text=True, timeout=30)
            self.assertEqual(proc.returncode, 1)
            self.assertIn("Não foi possível abrir", proc.stderr)
            self.assertIn("URE_PORT", proc.stderr)
            self.assertNotIn("Traceback", proc.stderr)
        finally:
            blocker.close()
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
