"""Ponto de entrada: python3 -m ure.server"""
from __future__ import annotations

import os
import sys
import threading

from .app import make_server
from .config import Settings


def _watch_parent_pipe() -> None:
    """Encerra o servidor quando o processo pai (o aplicativo desktop) desaparece.

    O lançador mantém o stdin deste processo aberto por um pipe. Se o aplicativo morrer por
    qualquer motivo (crash, encerramento forçado), o sistema fecha o pipe, a leitura devolve
    EOF e o backend termina. Não depende de sinais, então funciona em Windows e POSIX.
    """
    try:
        while sys.stdin.buffer.read(4096):
            pass
    except (OSError, ValueError):
        pass
    os._exit(0)


def main() -> None:
    settings = Settings.from_env()
    if os.environ.get("URE_PARENT_WATCH") == "1":
        threading.Thread(target=_watch_parent_pipe, name="parent-watch", daemon=True).start()
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
