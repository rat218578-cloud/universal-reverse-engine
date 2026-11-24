"""Diagnóstico das ferramentas: `python3 -m ure.toolcheck [--json] [--manifest ARQUIVO] [--no-selftest]`.

Usa a mesma sondagem da interface e do servidor. Não instala nada e não simula resultados.
Código de saída 0 somente se as ferramentas obrigatórias (java, apktool, lief) estiverem disponíveis
e passarem no teste de execução; caso contrário 1.
"""
from __future__ import annotations

import argparse
import datetime as _dt
import json
import platform
import sys
from pathlib import Path

from .tools import SPECS_BY_KEY, load_tools_env, probe_all, self_test

REQUIRED = ("java", "apktool", "lief")


def collect(run_selftest: bool = True) -> dict:
    tools_env = load_tools_env()
    rows = probe_all()
    if run_selftest:
        for row in rows:
            if row["status"] == "available":
                row["selftest"] = self_test(SPECS_BY_KEY[row["key"]])
    ready = {
        r["key"] for r in rows
        if r["status"] == "available" and (not run_selftest or r.get("selftest", {}).get("ok"))
    }
    required_ok = all(k in ready for k in REQUIRED)
    return {
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "host": {"system": platform.system(), "release": platform.release(), "machine": platform.machine(),
                 "python": sys.version.split()[0]},
        "tools_env": str(tools_env) if tools_env else None,
        "required": list(REQUIRED),
        "required_ready": required_ok,
        "tools": rows,
    }


def _print_table(report: dict) -> None:
    print(f"Arquivo de ferramentas: {report['tools_env'] or 'não encontrado (PATH)'}")
    for r in report["tools"]:
        mark = "OK      " if r["status"] == "available" else "AUSENTE "
        test = ""
        if "selftest" in r:
            test = " teste=" + ("ok" if r["selftest"]["ok"] else "FALHOU")
        version = r.get("version") or r.get("note", "")
        print(f"{mark}{r['key']:<12} {version[:60]:<60} {r.get('path') or '-'}{test}")
        if r.get("pending"):
            print(f"          dependências pendentes: {', '.join(r['pending'])}")
    print(f"Obrigatórias prontas ({', '.join(REQUIRED)}): {'sim' if report['required_ready'] else 'NÃO'}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ure.toolcheck", description=__doc__.splitlines()[0])
    parser.add_argument("--json", action="store_true", help="saída em JSON")
    parser.add_argument("--manifest", type=Path, help="grava o estado real em ARQUIVO (JSON)")
    parser.add_argument("--no-selftest", action="store_true", help="só sonda, sem executar as ferramentas")
    args = parser.parse_args(argv)
    report = collect(run_selftest=not args.no_selftest)
    if args.manifest:
        args.manifest.parent.mkdir(parents=True, exist_ok=True)
        args.manifest.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    if args.json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
    else:
        _print_table(report)
    return 0 if report["required_ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
