"""Entrada do backend no Android (Chaquopy).

O aplicativo Android chama `start` uma vez. O servidor HTTP do URE sobe em uma thread do
próprio processo, escutando somente em 127.0.0.1, com o token de sessão recebido por argumento.
Não há subprocesso nem variável de ambiente herdada: tudo vem dos parâmetros.

As ferramentas externas (apktool, JADX, apkanalyzer, ILSpy, Ghidra) não existem no aparelho.
O backend já trata essa ausência: elas aparecem como indisponíveis no relatório, sem simular
resultado. Ver docs/ANDROID.md.
"""
from __future__ import annotations

import os
import threading

_lock = threading.Lock()
_server = None
_thread = None

MIN_TOKEN_LENGTH = 32


def start(data_dir: str, web_dir: str, port: int, token: str) -> int:
    """Inicia o servidor (uma vez). Devolve a porta efetiva."""
    global _server, _thread
    if not isinstance(token, str) or len(token) < MIN_TOKEN_LENGTH:
        raise ValueError("token de sessão ausente ou curto demais")
    if not (0 < int(port) < 65536):
        raise ValueError(f"porta inválida: {port}")
    with _lock:
        if _server is not None:
            return int(_server.server_address[1])
        os.environ.update({
            "URE_DATA_DIR": data_dir,
            "URE_WEB_DIR": web_dir,
            "URE_HOST": "127.0.0.1",
            "URE_PORT": str(int(port)),
            "URE_TOKEN": token,
            "URE_AI_ENABLED": "0",
        })
        os.environ.pop("URE_PARENT_WATCH", None)

        from pathlib import Path

        from ure import app as ure_app
        from ure.config import Settings

        # A interface é resolvida na importação do módulo. Se ele já tiver sido importado com
        # outra pasta, apontamos para a pasta recebida agora.
        ure_app.WEB_ROOT = Path(web_dir).resolve()
        server = ure_app.make_server(Settings.from_env())
        thread = threading.Thread(target=server.serve_forever, name="ure-http", daemon=True)
        thread.start()
        _server, _thread = server, thread
        return int(server.server_address[1])


def stop() -> None:
    """Encerra o servidor, se estiver rodando. Seguro para chamadas repetidas."""
    global _server, _thread
    with _lock:
        server, thread = _server, _thread
        _server = _thread = None
    if server is not None:
        app = getattr(server, "ure_app", None)
        server.shutdown()
        server.server_close()
        if thread is not None:
            thread.join(timeout=5)
        if app is not None:
            app.jobs.shutdown()
            app.store.close()
