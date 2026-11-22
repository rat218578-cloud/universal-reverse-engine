"""API HTTP (biblioteca padrão), interface estática e servidor. Rotas em /api/v1.

Controles de segurança aplicados a TODA requisição, nesta ordem:
1. Host: só loopback (127.0.0.1, localhost, [::1]) na porta do servidor, mais URE_ALLOWED_HOSTS.
   Bloqueia DNS rebinding: o navegador envia o nome do atacante no cabeçalho Host.
2. Origin (quando presente): só origens locais ou tauri://localhost.
3. Autenticação: token de sessão obrigatório em /api, exceto /api/v1/health e arquivos estáticos.
4. Timeout de socket em cada conexão. Erros internos viram mensagem genérica.
"""
from __future__ import annotations

import dataclasses
import hashlib
import hmac
import json
import mimetypes
import os
import re
import shutil
import sys
import threading
import time
import traceback
from collections.abc import Iterator
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable
from urllib.parse import parse_qs, unquote, urlparse

from . import __version__
from .ai import AIError, AIRouter
from .analysis import IntegrityError, run_analysis
from .config import LOOPBACK, MB, Settings, load_or_create_token
from .db import Store, utcnow
from .files import build_tree, export_project_zip, read_preview
from .gitexport import GitUnavailable, export_local_repo
from .identify import KIND_APK, KIND_JAR, KIND_PE, KIND_ZIP, UPLOADABLE_KINDS, identify
from .jobs import BusyError, JobRunner
from .limits import Guard, TimeLimitExceeded
from .safezip import ArchiveLimitError, UnsafeArchiveError, safe_extract_zip
from .storage import (
    READ_ROOTS,
    PathRejectedError,
    artifact_root,
    ensure_layout,
    make_readonly,
    new_id,
    safe_join,
    valid_id,
)
from .tools import probe_all

def _resolve_web_root() -> Path:
    """Interface: URE_WEB_DIR, depois a cópia empacotada (wheel), depois o repositório (desenvolvimento)."""
    env = os.environ.get("URE_WEB_DIR")
    if env:
        return Path(env).expanduser().resolve()
    packaged = Path(__file__).resolve().parent / "web"
    if (packaged / "index.html").is_file():
        return packaged
    return Path(__file__).resolve().parents[2] / "web"


WEB_ROOT = _resolve_web_root()
CHUNK = MB
JSON_LIMIT = 64 * 1024
EXTRACTABLE = frozenset({KIND_APK, KIND_JAR, KIND_ZIP})
EXPECTED_EXT = {KIND_APK: {"apk", "zip"}, KIND_PE: {"exe", "dll", "sys", "scr"}}
PUBLIC_API = frozenset({"/api/v1/health"})
DESKTOP_ORIGINS = frozenset({"tauri://localhost"})
_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")
ID = r"([^/]+)"
CSP = ("default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
TERMINAL = frozenset({"done", "failed", "interrupted", "cancelled"})
SSE_MAX_SECONDS = 1800


class ApiError(Exception):
    def __init__(self, status: int, message: str, headers: dict[str, str] | None = None) -> None:
        super().__init__(message)
        self.status = status
        self.message = message
        self.headers = headers or {}


@dataclass
class SseStream:
    job_id: str


@dataclass
class FileResponse:
    path: Path
    mime: str
    filename: str | None = None


def allowed_host_names(host: str, port: int, extra: tuple[str, ...]) -> frozenset[str]:
    names = {f"127.0.0.1:{port}", f"localhost:{port}", f"[::1]:{port}"}
    if host not in LOOPBACK and host != "0.0.0.0":
        names.add(f"{host}:{port}")
    names.update(extra)
    return frozenset(n.lower() for n in names)


def sanitize_filename(raw: str) -> str:
    base = raw.replace("\\", "/").split("/")[-1]
    clean = _UNSAFE.sub("_", base).strip("._")[:120]
    return clean or "upload.bin"


def _extension_mismatch(name: str, kind: str) -> bool:
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return ext not in EXPECTED_EXT.get(kind, set())


KIND_MESSAGES = {
    "unknown": "o conteúdo não é um APK nem um executável PE (assinatura não reconhecida)",
    "corrupt": "arquivo corrompido ou cabeçalho inválido",
    "empty": "arquivo vazio",
    "zip": "arquivo ZIP genérico, não é um APK",
    "jar": "arquivo JAR, não aceito nesta versão",
    "elf": "executável ELF, não aceito nesta versão",
    "macho": "executável Mach-O, não aceito nesta versão",
    "dex": "bytecode DEX isolado; envie o APK completo",
}


def _format_rejection(info: dict[str, Any]) -> str:
    message = f"formato não aceito: {KIND_MESSAGES.get(info['kind'], info['kind'])}"
    reason = info.get("reason")
    if reason and info["kind"] == "corrupt":
        message += f" ({reason})"
    return message


def _summarize(info: dict[str, Any]) -> dict[str, Any]:
    summary: dict[str, Any] = {"kind": info["kind"]}
    if "reason" in info:
        summary["reason"] = info["reason"]
    if info["kind"] == KIND_PE:
        pe = dict(info["details"])
        imports = pe.pop("imports", {})
        pe["imported_dlls"] = {dll: len(names) for dll, names in imports.items()}
        summary["pe"] = pe
    elif "details" in info:
        summary["details"] = info["details"]
    return summary


class App:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        settings.data_dir.mkdir(parents=True, exist_ok=True)
        self.store = Store(settings.data_dir / "ure.sqlite3")
        self.store.recover_interrupted_jobs()
        self.allowed_hosts: frozenset[str] = frozenset({"127.0.0.1", "localhost", "[::1]"})
        self.allowed_origins: frozenset[str] = DESKTOP_ORIGINS
        self._art_locks: dict[str, threading.Lock] = {}
        self._locks_guard = threading.Lock()
        self._mutation_lock = threading.Lock()
        self._deleting: set[str] = set()
        self.jobs = JobRunner(
            self.store, settings.job_workers, settings.job_timeout_s,
            safe_exceptions=(IntegrityError, ArchiveLimitError, UnsafeArchiveError),
        )
        self.jobs.register("analyze", lambda pid, aid, params, guard: run_analysis(self, pid, aid, params, guard))
        self.ai = AIRouter(settings, self.store)

    def artifact_lock(self, aid: str) -> threading.Lock:
        with self._locks_guard:
            return self._art_locks.setdefault(aid, threading.Lock())

    def project_or_404(self, pid: str) -> dict[str, Any]:
        if not valid_id(pid):
            raise ApiError(400, "identificador inválido")
        project = self.store.get_project(pid)
        if project is None:
            raise ApiError(404, "projeto não encontrado")
        return project

    def artifact_or_404(self, pid: str, aid: str) -> dict[str, Any]:
        self.project_or_404(pid)
        if not valid_id(aid):
            raise ApiError(400, "identificador inválido")
        art = self.store.get_artifact(pid, aid)
        if art is None:
            raise ApiError(404, "artefato não encontrado")
        return art

    def root_of(self, pid: str, aid: str) -> Path:
        return artifact_root(self.settings.data_dir, pid, aid)


@contextmanager
def exclusive_artifact(app: App, aid: str) -> Iterator[None]:
    lock = app.artifact_lock(aid)
    if not lock.acquire(blocking=False):
        raise ApiError(409, "artefato em uso por outro processamento")
    try:
        yield
    finally:
        lock.release()


# --- rotas ----------------------------------------------------------------

def health(a: App, h: Any, m: Any, q: dict[str, str]) -> tuple[int, Any]:
    return 200, {"status": "ok", "version": __version__}


def list_projects(a: App, h: Any, m: Any, q: dict[str, str]) -> tuple[int, Any]:
    return 200, {"projects": a.store.list_projects()}


def create_project(a: App, h: Any, m: Any, q: dict[str, str]) -> tuple[int, Any]:
    body = h.read_json()
    name = str(body.get("name", "")).strip()
    if not 1 <= len(name) <= 120:
        raise ApiError(400, "nome deve ter de 1 a 120 caracteres")
    desc = str(body.get("description", ""))[:2000]
    return 201, a.store.create_project(new_id(), name, desc)


def get_project(a: App, h: Any, m: Any, q: dict[str, str]) -> tuple[int, Any]:
    return 200, a.project_or_404(m.group(1))


def delete_project(a: App, h: Any, m: Any, q: dict[str, str]) -> tuple[int, Any]:
    project = a.project_or_404(m.group(1))
    confirm = unquote(h.headers.get("X-Confirm-Delete") or "")
    if confirm != project["name"]:
        raise ApiError(409, "confirmação não confere: envie o nome do projeto em X-Confirm-Delete")
    pid = project["id"]
    with a._mutation_lock:
        if a.store.active_jobs(pid):
            raise ApiError(409, "há processamentos ativos neste projeto; cancele-os antes de excluir")
        a._deleting.add(pid)
    try:
        with ExitStack() as stack:
            for art in a.store.list_artifacts(pid):
                stack.enter_context(exclusive_artifact(a, art["id"]))
            shutil.rmtree(a.settings.data_dir / "projects" / pid, ignore_errors=True)
            a.store.delete_project(pid)
    finally:
        with a._mutation_lock:
            a._deleting.discard(pid)
    return 200, {"deleted": pid}


def list_artifacts(a: App, h: Any, m: Any, q: dict[str, str]) -> tuple[int, Any]:
    a.project_or_404(m.group(1))
    return 200, {"artifacts": a.store.list_artifacts(m.group(1))}


def get_artifact(a: App, h: Any, m: Any, q: dict[str, str]) -> tuple[int, Any]:
    return 200, a.artifact_or_404(m.group(1), m.group(2))


def upload_artifact(a: App, h: Any, m: Any, q: dict[str, str]) -> tuple[int, Any]:
    pid = m.group(1)
    a.project_or_404(pid)
    length = h.headers.get("Content-Length")
    if length is None:
        raise ApiError(411, "Content-Length obrigatório")
    try:
        size = int(length)
    except ValueError as exc:
        raise ApiError(400, "Content-Length inválido") from exc
    if size <= 0:
        raise ApiError(400, "arquivo vazio")
    if size > a.settings.max_upload_bytes:
        raise ApiError(413, f"arquivo excede o limite de {a.settings.max_upload_bytes // MB} MB")
    name = sanitize_filename(unquote(h.headers.get("X-Filename") or ""))
    aid = new_id()
    root = a.root_of(pid, aid)
    ensure_layout(root)
    tmp = root / "original" / ".upload.part"
    digest = hashlib.sha256()
    remaining = size
    try:
        with tmp.open("wb") as out:
            while remaining:
                chunk = h.rfile.read(min(CHUNK, remaining))
                if not chunk:
                    raise ApiError(400, "upload interrompido")
                out.write(chunk)
                digest.update(chunk)
                remaining -= len(chunk)
        info = identify(tmp)
        if info["kind"] not in UPLOADABLE_KINDS:
            raise ApiError(415, _format_rejection(info))
        final = root / "original" / name
        os.replace(tmp, final)
        make_readonly(final)
    except BaseException:
        shutil.rmtree(root, ignore_errors=True)
        raise
    (root / "reports" / "identify.json").write_text(
        json.dumps(info, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    details = _summarize(info)
    details["extension_mismatch"] = _extension_mismatch(name, info["kind"])
    row = a.store.add_artifact({
        "id": aid, "project_id": pid, "filename": name, "kind": info["kind"], "size": size,
        "sha256": digest.hexdigest(), "status": "uploaded", "details": details, "created_at": utcnow(),
    })
    return 201, row


def _read_root(q: dict[str, str]) -> str:
    root = q.get("root", "original")
    if root not in READ_ROOTS:
        raise ApiError(400, "raiz inválida")
    return root


def tree_artifact(a: App, h: Any, m: Any, q: dict[str, str]) -> tuple[int, Any]:
    art = a.artifact_or_404(m.group(1), m.group(2))
    base = a.root_of(art["project_id"], art["id"]) / _read_root(q)
    return 200, build_tree(safe_join(base, q.get("path", "")))


def preview_artifact(a: App, h: Any, m: Any, q: dict[str, str]) -> tuple[int, Any]:
    art = a.artifact_or_404(m.group(1), m.group(2))
    base = a.root_of(art["project_id"], art["id"]) / _read_root(q)
    target = safe_join(base, q.get("path", ""))
    if not target.exists():
        raise ApiError(404, "arquivo não encontrado")
    return 200, {"path": q.get("path", ""), **read_preview(target)}


def extract_artifact(a: App, h: Any, m: Any, q: dict[str, str]) -> tuple[int, Any]:
    art = a.artifact_or_404(m.group(1), m.group(2))
    if art["kind"] not in EXTRACTABLE:
        raise ApiError(409, f"tipo {art['kind']} não é extraível")
    root = a.root_of(art["project_id"], art["id"])
    src = root / "original" / art["filename"]
    if not src.is_file():
        raise ApiError(404, "arquivo original ausente")
    s = a.settings
    with exclusive_artifact(a, art["id"]):
        out = root / "extracted"
        shutil.rmtree(out, ignore_errors=True)
        try:
            report = safe_extract_zip(src, out, max_entries=s.max_entries,
                                      max_total_bytes=s.max_extract_bytes, max_ratio=s.max_ratio,
                                      guard=Guard(s.job_timeout_s))
        except (UnsafeArchiveError, ArchiveLimitError) as exc:
            a.store.patch_artifact(art["id"], status="rejected", details_patch={"extraction": {"error": str(exc)}})
            raise
        except TimeLimitExceeded as exc:
            raise ApiError(503, "tempo limite da extração excedido") from exc
        a.store.patch_artifact(art["id"], status="extracted",
                               details_patch={"extraction": dataclasses.asdict(report)})
    return 200, a.store.get_artifact(art["project_id"], art["id"])


def export_artifact(a: App, h: Any, m: Any, q: dict[str, str]) -> tuple[int, Any]:
    art = a.artifact_or_404(m.group(1), m.group(2))
    root = a.root_of(art["project_id"], art["id"])
    include = q.get("include_original") == "1"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    out = root / "exports" / f"export-{stamp}.zip"
    with exclusive_artifact(a, art["id"]):
        export_project_zip(root, out, include)
    return 200, FileResponse(out, "application/zip", f"{Path(art['filename']).stem}-export.zip")


def git_export(a: App, h: Any, m: Any, q: dict[str, str]) -> tuple[int, Any]:
    art = a.artifact_or_404(m.group(1), m.group(2))
    root = a.root_of(art["project_id"], art["id"])
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%f")
    with exclusive_artifact(a, art["id"]):
        try:
            result = export_local_repo(
                [("extracted", root / "extracted"), ("decompiled", root / "decompiled")],
                root / "exports" / f"git-{stamp}",
            )
        except GitUnavailable as exc:
            raise ApiError(503, str(exc)) from exc
    if not result["commits"]:
        raise ApiError(409, "nada para versionar: extraia ou decompile o artefato antes")
    return 201, result


def start_analysis(a: App, h: Any, m: Any, q: dict[str, str]) -> tuple[int, Any]:
    pid, aid = m.group(1), m.group(2)
    a.artifact_or_404(pid, aid)
    params = h.read_json()
    with a._mutation_lock:
        if pid in a._deleting:
            raise ApiError(409, "projeto em exclusão")
        return 202, a.jobs.submit("analyze", pid, aid, params)


def get_job_route(a: App, h: Any, m: Any, q: dict[str, str]) -> tuple[int, Any]:
    job = a.store.get_job(m.group(1)) if valid_id(m.group(1)) else None
    if job is None:
        raise ApiError(404, "job não encontrado")
    return 200, job


def job_events(a: App, h: Any, m: Any, q: dict[str, str]) -> tuple[int, Any]:
    if not valid_id(m.group(1)) or a.store.get_job(m.group(1)) is None:
        raise ApiError(404, "job não encontrado")
    return 200, SseStream(m.group(1))


def cancel_job(a: App, h: Any, m: Any, q: dict[str, str]) -> tuple[int, Any]:
    if not valid_id(m.group(1)):
        raise ApiError(404, "job não encontrado")
    try:
        return 202, a.jobs.cancel(m.group(1))
    except KeyError as exc:
        raise ApiError(404, "job não encontrado") from exc
    except ValueError as exc:
        raise ApiError(409, str(exc)) from exc


def retry_job(a: App, h: Any, m: Any, q: dict[str, str]) -> tuple[int, Any]:
    if not valid_id(m.group(1)):
        raise ApiError(404, "job não encontrado")
    try:
        return 202, a.jobs.retry(m.group(1))
    except KeyError as exc:
        raise ApiError(404, "job não encontrado") from exc
    except ValueError as exc:
        raise ApiError(409, str(exc)) from exc


def get_report(a: App, h: Any, m: Any, q: dict[str, str]) -> tuple[int, Any]:
    art = a.artifact_or_404(m.group(1), m.group(2))
    path = a.root_of(art["project_id"], art["id"]) / "reports" / "analysis.json"
    if not path.is_file():
        raise ApiError(404, "relatório ainda não gerado")
    return 200, json.loads(path.read_text(encoding="utf-8"))


def tools_status(a: App, h: Any, m: Any, q: dict[str, str]) -> tuple[int, Any]:
    return 200, {"tools": probe_all()}


def ai_status(a: App, h: Any, m: Any, q: dict[str, str]) -> tuple[int, Any]:
    return 200, a.ai.status()


def ask_artifact(a: App, h: Any, m: Any, q: dict[str, str]) -> tuple[int, Any]:
    art = a.artifact_or_404(m.group(1), m.group(2))
    body = h.read_json()
    path = a.root_of(art["project_id"], art["id"]) / "reports" / "analysis.json"
    if not path.is_file():
        raise ApiError(409, "execute a análise antes de perguntar à IA")
    report = json.loads(path.read_text(encoding="utf-8"))
    try:
        result = a.ai.ask(str(body.get("question", "")), report,
                          provider=str(body.get("provider", "ollama")),
                          model=body.get("model") or None, consent=body.get("consent") is True)
    except AIError as exc:
        raise ApiError(exc.status, exc.message) from exc
    return 200, result


ROUTES: list[tuple[str, re.Pattern[str], Callable[..., tuple[int, Any]]]] = [
    ("GET", re.compile(r"/api/v1/health"), health),
    ("GET", re.compile(r"/api/v1/projects"), list_projects),
    ("POST", re.compile(r"/api/v1/projects"), create_project),
    ("GET", re.compile(rf"/api/v1/projects/{ID}"), get_project),
    ("DELETE", re.compile(rf"/api/v1/projects/{ID}"), delete_project),
    ("GET", re.compile(rf"/api/v1/projects/{ID}/artifacts"), list_artifacts),
    ("POST", re.compile(rf"/api/v1/projects/{ID}/artifacts"), upload_artifact),
    ("GET", re.compile(rf"/api/v1/projects/{ID}/artifacts/{ID}"), get_artifact),
    ("GET", re.compile(rf"/api/v1/projects/{ID}/artifacts/{ID}/tree"), tree_artifact),
    ("GET", re.compile(rf"/api/v1/projects/{ID}/artifacts/{ID}/file"), preview_artifact),
    ("POST", re.compile(rf"/api/v1/projects/{ID}/artifacts/{ID}/extract"), extract_artifact),
    ("GET", re.compile(rf"/api/v1/projects/{ID}/artifacts/{ID}/export"), export_artifact),
    ("POST", re.compile(rf"/api/v1/projects/{ID}/artifacts/{ID}/git-export"), git_export),
    ("POST", re.compile(rf"/api/v1/projects/{ID}/artifacts/{ID}/analyze"), start_analysis),
    ("GET", re.compile(rf"/api/v1/projects/{ID}/artifacts/{ID}/report"), get_report),
    ("GET", re.compile(r"/api/v1/jobs/" + ID), get_job_route),
    ("GET", re.compile(r"/api/v1/jobs/" + ID + "/events"), job_events),
    ("POST", re.compile(r"/api/v1/jobs/" + ID + "/cancel"), cancel_job),
    ("POST", re.compile(r"/api/v1/jobs/" + ID + "/retry"), retry_job),
    ("GET", re.compile(r"/api/v1/tools"), tools_status),
    ("GET", re.compile(r"/api/v1/ai/status"), ai_status),
    ("POST", re.compile(rf"/api/v1/projects/{ID}/artifacts/{ID}/ask"), ask_artifact),
]


def make_handler(app: App) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        server_version = "URE/0.1"
        sys_version = ""
        timeout = app.settings.socket_timeout_s  # timeout de socket: leituras e escritas

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

        def handle(self) -> None:
            # cliente desconectou antes de receber a resposta: não é erro interno do servidor
            try:
                super().handle()
            except (BrokenPipeError, ConnectionResetError, TimeoutError):
                self.close_connection = True

        def do_GET(self) -> None:  # noqa: N802
            self._dispatch("GET")

        def do_HEAD(self) -> None:  # noqa: N802
            self._dispatch("HEAD")

        def do_POST(self) -> None:  # noqa: N802
            self._dispatch("POST")

        def do_DELETE(self) -> None:  # noqa: N802
            self._dispatch("DELETE")

        def do_OPTIONS(self) -> None:  # noqa: N802
            self._dispatch("OPTIONS")

        def do_PUT(self) -> None:  # noqa: N802
            self._dispatch("PUT")

        def do_PATCH(self) -> None:  # noqa: N802
            self._dispatch("PATCH")

        def _dispatch(self, method: str) -> None:
            url = urlparse(self.path)
            path = unquote(url.path)
            query = {k: v[-1] for k, v in parse_qs(url.query, keep_blank_values=True).items()}
            head_only = method == "HEAD"
            try:
                self._check_host_and_origin()
                if method not in ("GET", "HEAD", "POST", "DELETE"):
                    raise ApiError(405, "método não permitido")
                if not path.startswith("/api/"):
                    if method not in ("GET", "HEAD"):
                        raise ApiError(405, "método não permitido")
                    self._static(path, head_only=head_only)
                    return
                if head_only:
                    raise ApiError(405, "use GET nas rotas da API")
                if path not in PUBLIC_API:
                    self._check_auth()
                matched_other = False
                for route_method, pattern, fn in ROUTES:
                    match = pattern.fullmatch(path)
                    if not match:
                        continue
                    if route_method != method:
                        matched_other = True
                        continue
                    status, payload = fn(app, self, match, query)
                    self._send(status, payload)
                    return
                if matched_other:
                    raise ApiError(405, "método não permitido para este recurso")
                raise ApiError(404, "rota inexistente")
            except ApiError as exc:
                self._json(exc.status, {"error": exc.message}, head_only=head_only, extra=exc.headers)
            except PathRejectedError as exc:
                self._json(400, {"error": str(exc)}, head_only=head_only)
            except UnsafeArchiveError as exc:
                self._json(422, {"error": str(exc)}, head_only=head_only)
            except ArchiveLimitError as exc:
                self._json(413, {"error": str(exc)}, head_only=head_only)
            except Exception:
                traceback.print_exc(file=sys.stderr)
                self._json(500, {"error": "erro interno"}, head_only=head_only)

        def _check_host_and_origin(self) -> None:
            host = (self.headers.get("Host") or "").strip().lower()
            if not host or host not in app.allowed_hosts:
                raise ApiError(403, "Host não permitido")
            origin = self.headers.get("Origin")
            if origin is not None and origin not in app.allowed_origins:
                origin_ok = origin.strip().lower() in {f"http://{h}" for h in app.allowed_hosts}
                if not origin_ok:
                    raise ApiError(403, "Origin não permitida")

        def _check_auth(self) -> None:
            token = app.settings.token
            if not token:  # nunca deve ocorrer: make_server garante o token
                raise ApiError(401, "não autorizado")
            supplied = (self.headers.get("Authorization") or "").encode("utf-8", "replace")
            if not hmac.compare_digest(supplied, f"Bearer {token}".encode("utf-8")):
                raise ApiError(401, "não autorizado", {"WWW-Authenticate": "Bearer"})

        def read_json(self) -> dict[str, Any]:
            n = int(self.headers.get("Content-Length") or 0)
            if n < 0 or n > JSON_LIMIT:
                raise ApiError(413, "corpo JSON excede o limite")
            raw = self.rfile.read(n) if n else b"{}"
            try:
                data = json.loads(raw or b"{}")
            except ValueError as exc:
                raise ApiError(400, "JSON inválido") from exc
            if not isinstance(data, dict):
                raise ApiError(400, "o corpo deve ser um objeto JSON")
            return data

        def _headers(self, status: int, ctype: str, length: int, extra: dict[str, str] | None = None) -> None:
            self.send_response(status)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(length))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("Cache-Control", "no-store")
            for key, value in (extra or {}).items():
                self.send_header(key, value)
            self.end_headers()

        def _json(self, status: int, payload: Any, head_only: bool = False,
                  extra: dict[str, str] | None = None) -> None:
            body = json.dumps(payload, ensure_ascii=False, default=str).encode("utf-8")
            self._headers(status, "application/json; charset=utf-8", len(body), extra)
            if not head_only:
                self.wfile.write(body)

        def _send(self, status: int, payload: Any) -> None:
            if isinstance(payload, SseStream):
                self._sse(payload.job_id)
                return
            if isinstance(payload, FileResponse):
                extra = {}
                if payload.filename:
                    extra["Content-Disposition"] = f'attachment; filename="{payload.filename}"'
                self._stream(payload.path, payload.mime, extra)
            else:
                self._json(status, payload)

        def _sse(self, jid: str) -> None:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Accel-Buffering", "no")
            self.send_header("Content-Security-Policy", CSP)
            self.send_header("Connection", "close")
            self.end_headers()
            last: dict[str, Any] | None = None
            deadline = time.monotonic() + SSE_MAX_SECONDS
            try:
                while time.monotonic() < deadline:
                    job = app.store.get_job(jid) or {}
                    state = {k: job.get(k) for k in ("status", "progress", "message", "error")}
                    if state != last:
                        data = json.dumps(state, ensure_ascii=False)
                        self.wfile.write(f"event: progress\ndata: {data}\n\n".encode("utf-8"))
                        self.wfile.flush()
                        last = state
                    if state["status"] in TERMINAL:
                        self.wfile.write(b"event: end\ndata: {}\n\n")
                        self.wfile.flush()
                        return
                    time.sleep(0.5)
            except (BrokenPipeError, ConnectionResetError, TimeoutError):
                return

        def _stream(self, path: Path, mime: str, extra: dict[str, str] | None = None,
                    head_only: bool = False) -> None:
            self._headers(200, mime, path.stat().st_size, extra)
            if head_only:
                return
            with path.open("rb") as f:
                while True:
                    chunk = f.read(CHUNK)
                    if not chunk:
                        break
                    self.wfile.write(chunk)

        def _static(self, path: str, head_only: bool = False) -> None:
            rel = "index.html" if path in ("", "/") else path.lstrip("/")
            try:
                target = safe_join(WEB_ROOT, rel)
            except PathRejectedError as exc:
                raise ApiError(404, "não encontrado") from exc
            if not target.is_file():
                raise ApiError(404, "não encontrado")
            mime = mimetypes.guess_type(target.name)[0] or "application/octet-stream"
            self._stream(target, mime, head_only=head_only)

    return Handler


def make_server(settings: Settings) -> ThreadingHTTPServer:
    """Cria o servidor. Garante token de sessão e restringe Host/Origin à porta real do servidor."""
    if not settings.token:
        settings = dataclasses.replace(settings, token=load_or_create_token(settings.data_dir))
    settings.check_bind()
    app = App(settings)
    server = ThreadingHTTPServer((settings.host, settings.port), make_handler(app))
    server.daemon_threads = True
    host, port = server.server_address[:2]
    app.allowed_hosts = allowed_host_names(settings.host, port, settings.extra_hosts)
    app.allowed_origins = frozenset(DESKTOP_ORIGINS | {f"http://{h}" for h in app.allowed_hosts})
    server.ure_app = app  # type: ignore[attr-defined]
    return server
