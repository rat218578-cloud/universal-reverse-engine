"""Regressão: DEFLATE seguido de bytes extras travava o laço de descompressão (DoS)."""
from __future__ import annotations

import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path

from tests.helpers import make_zip
from ure.safezip import safe_extract_zip

LIMITS = {"max_entries": 1000, "max_total_bytes": 64 * 1024 * 1024, "max_ratio": 200.0}


class TrailingDataTerminationTests(unittest.TestCase):
    def test_bytes_after_deflate_end_do_not_hang(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        try:
            arc = make_zip(tmp / "a.zip", [("a.txt", b"conteudo " * 1000, None)])
            data = bytearray(arc.read_bytes())
            # insere lixo logo após o fluxo comprimido da entrada (antes do diretório central)
            cd = data.find(b"PK\x01\x02")
            data[cd:cd] = b"\xAA" * 4096
            arc.write_bytes(bytes(data))
            try:
                safe_extract_zip(arc, tmp / "out", **LIMITS)
            except (zipfile.BadZipFile, ValueError):
                pass  # rejeitar é aceitável; o que não pode é travar
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
