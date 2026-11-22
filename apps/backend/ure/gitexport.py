"""Exportação para repositório Git LOCAL. Privado por padrão: não há remoto configurado e nenhum
push é feito. Cada fonte vira um commit separado. Links simbólicos nunca são copiados."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

GIT_ENV = {
    "GIT_AUTHOR_NAME": "Universal Reverse Engine",
    "GIT_AUTHOR_EMAIL": "ure@localhost",
    "GIT_COMMITTER_NAME": "Universal Reverse Engine",
    "GIT_COMMITTER_EMAIL": "ure@localhost",
    "GIT_CONFIG_NOSYSTEM": "1",
    "GIT_TERMINAL_PROMPT": "0",
}


class GitUnavailable(RuntimeError):
    pass


def _git(args: list[str], cwd: Path) -> str:
    env = {k: v for k, v in os.environ.items() if k in ("PATH", "HOME", "LANG", "TMPDIR")}
    env.update(GIT_ENV)
    proc = subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True,
                          timeout=120, stdin=subprocess.DEVNULL, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"git {args[0]} falhou: {proc.stderr.strip()[:300]}")
    return proc.stdout.strip()


def _copy_no_links(src: Path, dst: Path) -> int:
    count = 0
    for dirpath, dirnames, filenames in os.walk(src, followlinks=False):
        dirnames[:] = [d for d in dirnames if not os.path.islink(os.path.join(dirpath, d))]
        rel = Path(dirpath).relative_to(src)
        (dst / rel).mkdir(parents=True, exist_ok=True)
        for name in filenames:
            s = Path(dirpath, name)
            if s.is_symlink() or not s.is_file():
                continue
            shutil.copy2(s, dst / rel / name)
            count += 1
    return count


def export_local_repo(sources: list[tuple[str, Path]], dest: Path) -> dict[str, Any]:
    if shutil.which("git") is None:
        raise GitUnavailable("git não encontrado no PATH")
    if dest.exists():
        raise FileExistsError("destino já existe")
    dest.mkdir(parents=True)
    _git(["init", "-q", "-b", "main"], dest)
    commits: list[dict[str, str]] = []
    for label, src in sources:
        if not src.is_dir():
            continue
        target = dest / label
        target.mkdir()
        files = _copy_no_links(src, target)
        if files == 0:
            continue
        _git(["add", "-A"], dest)
        _git(["commit", "-q", "--no-gpg-sign", "-m", f"importa {label} ({files} arquivos)"], dest)
        commits.append({"source": label, "hash": _git(["rev-parse", "HEAD"], dest), "files": str(files)})
    remotes = _git(["remote"], dest)
    return {"path": str(dest), "commits": commits, "remotes": remotes.splitlines(), "private": not remotes}
