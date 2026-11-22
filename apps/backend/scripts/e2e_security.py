import json, os, shutil, socket, struct, subprocess, sys, tempfile, time, urllib.request, urllib.error, glob
sys.path.insert(0, ".")
from pathlib import Path
from tests.helpers import make_zip, synthetic_apk
from tests.helpers import find_real_pe
from tests.test_security import forge_central_sizes

DATA = Path(tempfile.mkdtemp(prefix="ure-e2e-"))
PORT = 8794
env = dict(os.environ, URE_DATA_DIR=str(DATA), URE_PORT=str(PORT), URE_SOCKET_TIMEOUT_S="2")
PYTHON = os.environ.get("URE_E2E_PYTHON", sys.executable)
if "URE_E2E_PYTHON" not in os.environ:
    # código-fonte: o pacote fica em apps/backend, que não é o diretório de dados
    env["PYTHONPATH"] = str(Path(__file__).resolve().parents[1])
srv = subprocess.Popen([PYTHON, "-m", "ure.server"], env=env, cwd=str(DATA), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
for _ in range(100):
    if (DATA / "session.token").is_file() or srv.poll() is not None:
        break
    time.sleep(0.1)
if srv.poll() is not None or not (DATA / "session.token").is_file():
    err = srv.communicate(timeout=10)[1].decode(errors="replace")
    raise SystemExit("servidor não iniciou:\n" + err[-2000:])
B = f"http://127.0.0.1:{PORT}"
TOKEN = (DATA / "session.token").read_text().strip()
AUTH = {"Authorization": f"Bearer {TOKEN}"}
results = []

def req(method, path, data=None, headers=None):
    h = dict(headers or {})
    r = urllib.request.Request(B + path, data=data, method=method, headers=h)
    try:
        with urllib.request.urlopen(r, timeout=20) as x:
            return x.status, x.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()

def check(name, cond, detail=""):
    results.append((name, bool(cond), detail))
    print(("PASS " if cond else "FAIL ") + name + (f"  [{detail}]" if detail else ""))

try:
    # --- Host / DNS rebinding ---
    s, _ = req("GET", "/api/v1/health", headers={"Host": "atacante.example:%d" % PORT, **AUTH})
    check("DNS rebinding: Host estrangeiro bloqueado (health)", s == 403, f"HTTP {s}")
    s, b = req("GET", "/api/v1/projects", headers={"Host": "atacante.example:%d" % PORT, **AUTH})
    check("DNS rebinding: Host estrangeiro bloqueado (projetos com token)", s == 403, f"HTTP {s}")
    s, _ = req("GET", "/", headers={"Host": "atacante.example:%d" % PORT})
    check("DNS rebinding: página estática bloqueada", s == 403, f"HTTP {s}")
    s, _ = req("GET", "/api/v1/health", headers={"Host": f"127.0.0.1:{PORT}"})
    check("Host legítimo aceito (health público)", s == 200, f"HTTP {s}")

    # --- Token ---
    s, _ = req("GET", "/api/v1/projects")
    check("API sem token: 401", s == 401, f"HTTP {s}")
    s, _ = req("GET", "/api/v1/projects", headers={"Authorization": "Bearer errado"})
    check("API com token errado: 401", s == 401, f"HTTP {s}")
    s, _ = req("GET", "/api/v1/projects", headers=AUTH)
    check("API com token correto: 200", s == 200, f"HTTP {s}")
    s, _ = req("GET", "/", None)
    check("interface estática pública sem token", s == 200, f"HTTP {s}")
    s, _ = req("GET", "/api/v1/projects?token=" + TOKEN)
    check("token na query string não autentica", s == 401, f"HTTP {s}")

    # --- Origin ---
    s, _ = req("GET", "/api/v1/health", headers={"Origin": "http://atacante.example", "Host": f"127.0.0.1:{PORT}"})
    check("Origin estrangeira bloqueada", s == 403, f"HTTP {s}")

    # --- Timeout de socket (cliente lento) ---
    sock = socket.create_connection(("127.0.0.1", PORT), timeout=10)
    sock.sendall(f"GET /api/v1/health HTTP/1.1\r\nHost: 127.0.0.1:{PORT}\r\n".encode())
    t0 = time.monotonic(); data = sock.recv(100); el = time.monotonic() - t0; sock.close()
    check("cliente lento desconectado pelo timeout de socket", data == b"" and el < 6, f"{el:.1f}s")

    # --- Erros sem informação interna ---
    s, b = req("GET", "/api/v1/projects/" + "0" * 32, headers=AUTH)
    check("404 sem caminhos internos", s == 404 and str(DATA).encode() not in b, f"HTTP {s}")
    s, b = req("GET", "/api/v1/projects/..%2F..%2Fetc", headers=AUTH)
    check("ID inválido: 400/404 sem caminhos", s in (400, 404) and b"/etc" not in b, f"HTTP {s}")

    # --- Upload de ZIP bomb com cabeçalho forjado pela rede ---
    tmp = Path(tempfile.mkdtemp())
    arc = make_zip(tmp / "bomba.apk", [("AndroidManifest.xml", b"m", None), ("classes.dex", b"dex\n035\x00", None),
                                       ("bomba.bin", b"\x00" * (8 * 1024 * 1024), None)])
    forge_central_sizes(arc, "bomba.bin", compress_size=0xFFFFFFFF, file_size=1024)
    s, b = req("POST", "/api/v1/projects", json.dumps({"name": "e2e"}).encode(),
               {"Content-Type": "application/json", **AUTH})
    pid = json.loads(b)["id"]
    s, b = req("POST", f"/api/v1/projects/{pid}/artifacts", arc.read_bytes(), {"X-Filename": "bomba.apk", **AUTH})
    art = json.loads(b); aid = art["id"]
    check("upload do APK com bomba aceito como APK (conteúdo)", s == 201 and art["kind"] == "apk", f"HTTP {s}")
    s, b = req("POST", f"/api/v1/projects/{pid}/artifacts/{aid}/extract", b"{}", {"Content-Type": "application/json", **AUTH})
    check("extração da bomba com cabeçalho forjado rejeitada", s in (413, 422), f"HTTP {s} {b[:120]!r}")
    check("saída parcial da bomba removida do disco",
          not (DATA / "projects" / pid / "artifacts" / aid / "extracted").exists())
    s, b = req("GET", f"/api/v1/projects/{pid}/artifacts/{aid}", headers=AUTH)
    check("artefato marcado como rejeitado", json.loads(b)["status"] == "rejected")

    # --- APK legítimo continua funcionando ---
    apk = synthetic_apk(tmp / "ok.apk")
    s, b = req("POST", f"/api/v1/projects/{pid}/artifacts", apk.read_bytes(), {"X-Filename": "ok.apk", **AUTH})
    aid2 = json.loads(b)["id"]
    s, b = req("POST", f"/api/v1/projects/{pid}/artifacts/{aid2}/extract", b"{}", {"Content-Type": "application/json", **AUTH})
    check("APK legítimo extraído", s == 200, f"HTTP {s}")
    s, b = req("GET", f"/api/v1/projects/{pid}/artifacts/{aid2}/file?root=extracted&path=assets/notes.txt", headers=AUTH)
    check("visualização do arquivo extraído", s == 200 and b"hello from ure" in b, f"HTTP {s}")

    # --- Trabalho pesado com token: análise do PE real ---
    pe_path = find_real_pe()
    pe = [str(pe_path)] if pe_path else []
    if pe:
        s, b = req("POST", f"/api/v1/projects/{pid}/artifacts", Path(pe[0]).read_bytes(), {"X-Filename": "w32.exe", **AUTH})
        aid3 = json.loads(b)["id"]
        s, b = req("POST", f"/api/v1/projects/{pid}/artifacts/{aid3}/analyze", b"{}", {"Content-Type": "application/json", **AUTH})
        jid = json.loads(b)["id"]
        status = "queued"
        for _ in range(120):
            s, b = req("GET", f"/api/v1/jobs/{jid}", headers=AUTH)
            status = json.loads(b)["status"]
            if status not in ("queued", "running"):
                break
            time.sleep(0.5)
        check("análise do PE real concluída", status == "done", status)
        s, b = req("GET", f"/api/v1/projects/{pid}/artifacts/{aid3}/report", headers=AUTH)
        rep = json.loads(b)
        check("relatório do PE real com integridade ok", rep.get("integrity") == "ok")
    else:
        check("PE real disponível", False, "não encontrado")

    # --- Exclusão exige confirmação ---
    s, _ = req("DELETE", f"/api/v1/projects/{pid}", headers=AUTH)
    check("exclusão sem confirmação recusada", s == 409, f"HTTP {s}")
finally:
    srv.terminate()
    try:
        out, err = srv.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        srv.kill(); out, err = srv.communicate()
    shutil.rmtree(DATA, ignore_errors=True)
    print("tracebacks no log do servidor:", err.decode(errors="replace").count("Traceback"))
passed = sum(1 for _, ok, _ in results if ok)
print(f"RESULTADO: {passed}/{len(results)} verificações passaram")
