"""Ponto de entrada: python3 -m ure.server"""
from __future__ import annotations

from .app import make_server
from .config import Settings


def main() -> None:
    settings = Settings.from_env()
    server = make_server(settings)
    host, port = server.server_address[:2]
    print(f"Universal Reverse Engine em http://{host}:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
