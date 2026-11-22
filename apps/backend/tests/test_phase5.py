"""Testes da Fase 5: entrega da interface estática com cabeçalhos de segurança."""
from __future__ import annotations

import unittest

from tests.test_api import ApiCase


class StaticUiTests(ApiCase):
    def test_index_served_with_csp_and_module_script(self) -> None:
        status, raw, headers = self.call("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b'<script type="module" src="app.js">', raw)
        self.assertIn("default-src 'self'", headers.get("Content-Security-Policy", ""))
        self.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
        self.assertNotIn(b"<script>", raw, "CSP estrita: nenhum script inline")

    def test_assets_served_with_types(self) -> None:
        for path, ctype in [("/app.js", "javascript"), ("/style.css", "text/css")]:
            status, _, headers = self.call("GET", path)
            self.assertEqual(status, 200, path)
            self.assertIn(ctype, headers.get("Content-Type", ""))

    def test_static_traversal_blocked(self) -> None:
        status, _, _ = self.call("GET", "/%2e%2e/backend/ure/config.py")
        self.assertEqual(status, 404)
        status, _, _ = self.call("GET", "/..%2F..%2Fetc%2Fpasswd")
        self.assertEqual(status, 404)

    def test_unknown_static_is_404_and_post_static_refused(self) -> None:
        self.assertEqual(self.call("GET", "/nao-existe.html")[0], 404)
        self.assertEqual(self.call("POST", "/")[0], 405)
        self.assertEqual(self.call("HEAD", "/")[0], 200)  # HEAD em página estática é válido


if __name__ == "__main__":
    unittest.main()
