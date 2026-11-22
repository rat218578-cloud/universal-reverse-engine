"""Ponto de entrada: python3 -m ure.server"""
from __future__ import annotations

import sys

from .app import make_server
from .config import Settings


def main() -> None:
    settings = Settings.from_env()
    try:
        server = make_server(settings)
    except OSError as exc:
        print(f"Não foi possível abrir {settings.host}:{settings.port} ({exc.strerror or exc}). "
              "Escolha outra porta com URE_PORT ou encerre o processo que a usa.", file=sys.stderr)
        raise SystemExit(1) from None
    host, port = server.server_address[:2]
    print(f"Universal Reverse Engine em http://{host}:{port}", flush=True)
    print(f"Token de sessão: {settings.data_dir / 'session.token'} (ou variável URE_TOKEN)", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
