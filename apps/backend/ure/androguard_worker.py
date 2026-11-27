"""Resumo de APK com o Androguard. Roda como script separado, com o interpretador do venv.

Não importa o pacote `ure` (o venv do Androguard não o contém). Lê o APK e imprime JSON:
manifesto (pacote, SDKs, componentes, permissões) e lista de classes dos DEX. Não executa o APK.
Em erro, imprime {"error": ..., "reason": ...} e sai com código 0; quem chama decide o status.
"""
from __future__ import annotations

import json
import sys


def summarize(path: str) -> dict:
    from androguard.misc import AnalyzeAPK

    apk, dex_list, dx = AnalyzeAPK(path)
    classes = [c.name for c in dx.get_classes()]
    return {
        "package": apk.get_package(),
        "version_name": apk.get_androidversion_name(),
        "version_code": apk.get_androidversion_code(),
        "min_sdk": apk.get_min_sdk_version(),
        "target_sdk": apk.get_target_sdk_version(),
        "activities": sorted(apk.get_activities()),
        "services": sorted(apk.get_services()),
        "receivers": sorted(apk.get_receivers()),
        "providers": sorted(apk.get_providers()),
        "permissions": sorted(apk.get_permissions()),
        "dex_files": len(dex_list),
        "class_count": len(classes),
        "classes_sample": classes[:50],
    }


def main(argv: list[str]) -> int:
    if len(argv) != 2 or argv[0] != "summary":
        sys.stdout.write(json.dumps({"error": "uso", "reason": "summary <apk>"}))
        return 0
    try:
        data = summarize(argv[1])
    except ModuleNotFoundError as exc:
        data = {"error": "ModuleNotFoundError", "reason": str(exc)}
    except Exception as exc:  # o Androguard levanta exceções variadas para entradas inválidas
        data = {"error": type(exc).__name__, "reason": str(exc)[:500]}
    sys.stdout.write(json.dumps(data, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
