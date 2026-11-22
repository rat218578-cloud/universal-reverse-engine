"""Gera os artefatos de distribuição do Universal Reverse Engine.

- copia a interface (apps/web) para o pacote, gera o wheel e remove a cópia (não fica no repositório);
- gera um arquivo de código-fonte a partir do commit HEAD (git archive);
- grava SHA256SUMS e BUILDINFO.txt em dist/.

Não publica nada. Exige git e setuptools. Não usa rede.
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "apps" / "backend"
WEB = ROOT / "apps" / "web"
DIST = ROOT / "dist"
PKG_WEB = BACKEND / "ure" / "web"
VERSION = "1.0.0rc1"


def run(cmd: list[str], cwd: Path) -> str:
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise SystemExit(f"falha: {' '.join(cmd)}\n{proc.stderr[-2000:]}")
    return proc.stdout.strip()


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main() -> None:
    dirty = run(["git", "status", "--porcelain"], ROOT)
    if dirty:
        print("AVISO: árvore com alterações não commitadas; o código-fonte gerado usa apenas o HEAD.")
    commit = run(["git", "rev-parse", "HEAD"], ROOT)
    DIST.mkdir(exist_ok=True)
    for old in DIST.glob("*"):
        if old.is_file():
            old.unlink()
    PKG_WEB.mkdir(parents=True, exist_ok=True)
    try:
        for item in WEB.iterdir():
            if item.is_file() and item.name != "package.json":
                shutil.copy2(item, PKG_WEB / item.name)
        run([sys.executable, "-m", "pip", "wheel", ".", "--no-build-isolation", "--no-deps", "-w", str(DIST)], BACKEND)
    finally:
        shutil.rmtree(PKG_WEB, ignore_errors=True)
        shutil.rmtree(BACKEND / "build", ignore_errors=True)
        for egg in BACKEND.glob("*.egg-info"):
            shutil.rmtree(egg, ignore_errors=True)
    src = DIST / f"universal-reverse-engine-{VERSION}-source.tar.gz"
    run(["git", "archive", "--format=tar.gz", f"--prefix=universal-reverse-engine-{VERSION}/",
         "-o", str(src), "HEAD"], ROOT)
    artifacts = sorted(p for p in DIST.iterdir() if p.is_file())
    sums = "\n".join(f"{sha256(p)}  {p.name}" for p in artifacts) + "\n"
    (DIST / "SHA256SUMS").write_text(sums, encoding="utf-8")
    info = (f"versao: {VERSION}\ncommit: {commit}\n"
            f"gerado_em: {datetime.now(timezone.utc).isoformat(timespec='seconds')}\n"
            f"python_do_build: {sys.version.split()[0]}\n")
    (DIST / "BUILDINFO.txt").write_text(info, encoding="utf-8")
    for p in sorted(DIST.iterdir()):
        print(p.name, p.stat().st_size)


if __name__ == "__main__":
    main()
