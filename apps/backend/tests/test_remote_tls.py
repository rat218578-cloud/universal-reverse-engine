"""HTTPS do cliente remoto: certificado validado, sem enfraquecer a verificação.

Usa um servidor TLS real com certificado autoassinado gerado na hora (openssl). Sem openssl,
os testes são pulados; a verificação em si nunca é desligada para fazê-los passar.
"""
from __future__ import annotations

import shutil
import ssl
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.helpers import run_server_in_thread
from ure import remote
from ure.app import make_server
from ure.config import Settings

TOKEN = "token-tls-de-teste-0123456789abcdef-x"


@unittest.skipUnless(shutil.which("openssl"), "openssl indisponível neste ambiente")
class TlsRemoteTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = Path(tempfile.mkdtemp())
        cert, key = cls.tmp / "cert.pem", cls.tmp / "key.pem"
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
             "-keyout", str(key), "-out", str(cert), "-subj", "/CN=localhost",
             "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1"],
            check=True, capture_output=True,
        )
        cls.cert = cert
        server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_ctx.load_cert_chain(cert, key)
        cls.server = make_server(Settings(data_dir=cls.tmp / "data", port=0, token=TOKEN))
        cls.server.socket = server_ctx.wrap_socket(cls.server.socket, server_side=True)
        run_server_in_thread(cls.server)
        cls.base = f"https://localhost:{cls.server.server_address[1]}"

    @classmethod
    def tearDownClass(cls) -> None:
        cls.server.shutdown()
        cls.server.server_close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    def test_untrusted_self_signed_certificate_is_refused_by_default(self) -> None:
        cli = remote.RemoteClient(remote.RemoteConfig(self.base, TOKEN))
        with self.assertRaises(remote.RemoteError) as ctx:
            cli.health()
        self.assertIn("SSLCertVerificationError", ctx.exception.message)
        self.assertNotIn(TOKEN, ctx.exception.message)

    def test_pinned_trust_anchor_is_accepted(self) -> None:
        ctx = ssl.create_default_context(cafile=str(self.cert))
        cli = remote.RemoteClient(remote.RemoteConfig(self.base, TOKEN), ssl_context=ctx)
        self.assertIsInstance(cli.health(), dict)

    def test_wrong_token_over_tls_is_still_refused(self) -> None:
        ctx = ssl.create_default_context(cafile=str(self.cert))
        cli = remote.RemoteClient(remote.RemoteConfig(self.base, "outro-token-com-mais-de-trinta-e-dois"),
                                  ssl_context=ctx)
        with self.assertRaises(remote.RemoteError) as err:
            cli.create_project("x")
        self.assertEqual(err.exception.status, 401)

    def test_context_that_disables_verification_is_rejected_by_client(self) -> None:
        insecure = ssl.create_default_context()
        insecure.check_hostname = False
        insecure.verify_mode = ssl.CERT_NONE
        with self.assertRaises(remote.RemoteError) as ctx:
            remote.RemoteClient(remote.RemoteConfig(self.base, TOKEN), ssl_context=insecure)
        self.assertIn("não pode ser desligada", ctx.exception.message)


if __name__ == "__main__":
    unittest.main()
