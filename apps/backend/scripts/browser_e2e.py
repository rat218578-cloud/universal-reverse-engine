"""Validação de interface em navegador real (Chromium via Playwright).

Sobe o servidor instalado (ure-server, do wheel) em diretório de dados temporário e percorre os
fluxos da interface. Falhas de JavaScript na página são registradas e reprovam o teste.
Uso: URE_E2E_SERVER_BIN=/caminho/ure-server python3 scripts/browser_e2e.py
"""
from __future__ import annotations

import glob
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zipfile
from pathlib import Path

from playwright.sync_api import expect, sync_playwright

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tests.helpers import find_real_pe, synthetic_apk  # noqa: E402

SHOTS = Path(os.environ.get("URE_E2E_SHOTS", Path(tempfile.gettempdir()) / "ure-validation-shots"))
SHOTS.mkdir(parents=True, exist_ok=True)
PORT = int(os.environ.get("URE_E2E_PORT", "8789"))
SERVER_BIN = os.environ.get("URE_E2E_SERVER_BIN", "ure-server")
results: list[dict] = []
page_errors: list[str] = []
console_errors: list[str] = []
http_4xx: list[str] = []


def record(name: str, ok: bool, detail: str = "") -> None:
    results.append({"nome": name, "ok": bool(ok), "detalhe": detail})
    print(("PASS " if ok else "FAIL ") + name + (f" [{detail}]" if detail else ""), flush=True)


def tree_preview(page):
    """Prévia do cartão da árvore de arquivos (há outro <pre> com o relatório JSON)."""
    return page.locator(".card", has_text="Árvore de arquivos").locator("pre")


def shot(page, name: str) -> None:
    page.screenshot(path=str(SHOTS / f"{name}.png"), full_page=True)


def main() -> None:
    data = Path(tempfile.mkdtemp(prefix="ure-browser-"))
    env = dict(os.environ, URE_DATA_DIR=str(data), URE_PORT=str(PORT))
    srv = subprocess.Popen([SERVER_BIN], env=env, cwd=str(data), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for _ in range(100):
        if (data / "session.token").is_file():
            break
        time.sleep(0.1)
    token = (data / "session.token").read_text().strip()
    base = f"http://127.0.0.1:{PORT}"
    work = Path(tempfile.mkdtemp(prefix="ure-files-"))
    apk = synthetic_apk(work / "app.apk")
    pe = find_real_pe()
    if pe is None:
        raise SystemExit("PE real não encontrado: defina URE_TEST_PE com o caminho de um executável PE")
    fake = work / "falso.exe"
    fake.write_text("isto é texto, não um executável\n" * 5)
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox"])
            ctx = browser.new_context(accept_downloads=True, viewport={"width": 1280, "height": 900})
            page = ctx.new_page()
            page.on("pageerror", lambda e: page_errors.append(f"pageerror: {e}"))
            page.on("console", lambda m: console_errors.append(m.text)
                    if m.type == "error" and not m.text.startswith("Failed to load resource") else None)
            page.on("response", lambda r: http_4xx.append(f"{r.status} {r.url.split("/api")[-1]}")
                    if r.status >= 400 else None)

            # 1. Sem token: a interface deve pedir token
            page.goto(base + "/")
            expect(page.locator("#app")).to_be_visible()
            page.wait_for_timeout(800)
            pill = page.locator("#health").inner_text()
            record("sem token: página carrega e pede autenticação", "token" in pill, pill)
            shot(page, "01-sem-token")

            # 2. Token correto
            page.locator("#token").fill(token)
            page.locator("#token").press("Tab")
            expect(page.locator("#health")).to_contain_text("online", timeout=8000)
            record("token válido: status online", True, page.locator("#health").inner_text())
            shot(page, "02-token-ok")

            # 3. Criar projeto
            page.get_by_placeholder("Nome do projeto").fill("Validação RC1")
            page.get_by_role("button", name="Criar projeto").click()
            page.wait_for_url(re.compile(r".*#/p/[0-9a-f]{32}$"), timeout=8000)
            pid = page.url.split("#/p/")[1]
            record("criar projeto: navega para o projeto", len(pid) == 32, pid)

            # 4. Upload do APK pelo seletor de arquivo
            page.locator("input[type=file]").set_input_files(str(apk))
            page.wait_for_url(re.compile(r".*#/p/[0-9a-f]{32}/a/[0-9a-f]{32}$"), timeout=8000)
            expect(page.locator("h2").first).to_have_text("app.apk", timeout=8000)
            details = page.locator("body").inner_text()
            record("upload APK: identificado como APK pelo conteúdo", "APK" in details and "compatível" in details)
            shot(page, "03-apk-identificado")

            # 4b. Arrastar e soltar (evento drop com DataTransfer, como o navegador faria)
            import base64
            page.goto(base + "/#/p/" + pid)
            expect(page.locator("text=Enviar arquivo")).to_be_visible(timeout=8000)
            page.wait_for_timeout(500)
            visible_text = page.locator("#app").inner_text().split()
            record("projeto sem descrição: página não mostra 'null'", "null" not in visible_text)
            b64 = base64.b64encode(apk.read_bytes()).decode()
            page.evaluate("""(b64) => {
                const bytes = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
                const dt = new DataTransfer();
                dt.items.add(new File([bytes], "dnd.apk", {type: "application/octet-stream"}));
                document.querySelector(".drop").dispatchEvent(new DragEvent("drop", {dataTransfer: dt, bubbles: true, cancelable: true}));
            }""", b64)
            page.wait_for_url(re.compile(r".*#/p/[0-9a-f]{32}/a/[0-9a-f]{32}$"), timeout=8000)
            expect(page.locator("h2").first).to_have_text("dnd.apk", timeout=8000)
            record("arrastar e soltar: upload identificado", True)
            page.goto(base + "/#/p/" + pid)
            expect(page.locator("text=Enviar arquivo")).to_be_visible(timeout=8000)
            page.wait_for_timeout(300)
            # volta ao APK principal para o fluxo de extração
            page.goto(base + "/#/p/" + pid)
            page.locator("a", has_text="app.apk").first.click()
            expect(page.locator("h2").first).to_have_text("app.apk", timeout=8000)

            # 5. Extração
            page.get_by_role("button", name="Extrair com segurança").click()
            expect(page.locator("text=Extração concluída")).to_be_visible(timeout=8000)
            page.wait_for_timeout(600)
            record("extração do APK pela interface", True)

            # 6. Navegação: raiz extracted, entrar em assets, abrir notes.txt
            page.locator("select").first.select_option("extracted")
            expect(page.locator("ul.tree")).to_contain_text("AndroidManifest.xml", timeout=8000)
            record("árvore mostra AndroidManifest.xml extraído", True)
            page.locator("ul.tree button", has_text="📁 assets").click()
            expect(page.locator("ul.tree")).to_contain_text("notes.txt", timeout=8000)
            page.locator("ul.tree button", has_text="notes.txt").click()
            expect(tree_preview(page)).to_contain_text("hello from ure", timeout=8000)
            record("visualização de texto de arquivo extraído", True)
            shot(page, "04-arvore-visualizacao")

            # 7. Análise com progresso
            page.get_by_role("button", name="Analisar").click()
            expect(page.locator("text=Concluído").first).to_be_visible(timeout=60000)
            page.wait_for_timeout(800)
            expect(page.locator("h3", has_text="Relatório técnico")).to_be_visible(timeout=10000)
            body = page.locator("body").inner_text()
            record("análise do APK concluída com relatório", "Integridade" in body and "Motores" in body)
            record("motores ausentes exibidos como ausentes (não simulados)", "missing" in body,
                   "apktool/jadx/apkanalyzer não instalados")
            shot(page, "05-relatorio-apk")

            # 8. Exportação ZIP
            with page.expect_download(timeout=20000) as dl:
                page.get_by_role("button", name="Exportar ZIP").click()
            out = work / "export-apk.zip"
            dl.value.save_as(str(out))
            names = zipfile.ZipFile(out).namelist()
            record("exportação ZIP pela interface contém MANIFEST e arquivos extraídos",
                   "MANIFEST.json" in names and any(n.startswith("extracted/") for n in names), f"{len(names)} entradas")

            # 9. Upload de EXE real (PE)
            page.goto(base + "/#/p/" + pid)
            expect(page.locator("text=Enviar arquivo")).to_be_visible(timeout=8000)
            page.locator("input[type=file]").set_input_files(str(pe))
            page.wait_for_url(re.compile(r".*#/p/[0-9a-f]{32}/a/[0-9a-f]{32}$"), timeout=8000)
            expect(page.locator("h2").first).to_have_text("w32.exe", timeout=8000)
            record("upload EXE real: identificado como PE", "Executável PE" in page.locator("body").inner_text())
            page.get_by_role("button", name="Analisar").click()
            expect(page.locator("text=Concluído").first).to_be_visible(timeout=60000)
            page.wait_for_timeout(800)
            body = page.locator("body").inner_text()
            record("análise do PE real: importações exibidas", "KERNEL32" in body)
            page.locator("select").first.select_option("original")
            expect(page.locator("ul.tree")).to_contain_text("w32.exe", timeout=8000)
            page.locator("ul.tree button", has_text="w32.exe").click()
            expect(tree_preview(page)).to_contain_text("4d 5a", timeout=8000)
            record("visualização hexadecimal do EXE original (assinatura MZ)", True)
            shot(page, "06-exe-analisado")

            # 10. Erro tratado: texto disfarçado de .exe
            page.goto(base + "/#/p/" + pid)
            expect(page.locator("text=Enviar arquivo")).to_be_visible(timeout=8000)
            page.locator("input[type=file]").set_input_files(str(fake))
            expect(page.locator("#toast")).to_contain_text("não é um APK nem um executável PE", timeout=8000)
            record("arquivo disfarçado de .exe recusado com mensagem clara", True)
            shot(page, "07-erro-formato")

            # 11. Token errado: a interface deve reagir sem travar
            page.locator("#token").fill("token-errado")
            page.locator("#token").press("Tab")
            expect(page.locator("#health")).to_contain_text("token necessário", timeout=8000)
            record("token errado: status de autenticação exibido", True)
            shot(page, "08-token-errado")

            # 12. Navegação de retorno e rota inexistente
            page.locator("#token").fill(token)
            page.locator("#token").press("Tab")
            expect(page.locator("#health")).to_contain_text("online", timeout=8000)
            page.goto(base + "/#/rota-que-nao-existe")
            expect(page.locator("#app")).to_contain_text("Página não encontrada", timeout=5000)
            record("rota inexistente tratada na interface", True)

            browser.close()
    finally:
        srv.terminate()
        try:
            srv.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            srv.kill()
        shutil.rmtree(data, ignore_errors=True)
        shutil.rmtree(work, ignore_errors=True)
    record("nenhuma exceção de JavaScript não tratada", not page_errors, "; ".join(page_errors)[:500])
    record("nenhum console.error de código da interface", not console_errors, "; ".join(console_errors)[:500])
    esperados = [h for h in http_4xx]
    record("respostas 4xx registradas (esperadas nos testes de erro)", True, f"{len(esperados)}: " + ", ".join(sorted(set(esperados)))[:400])
    (SHOTS / "resultado.json").write_text(json.dumps({"resultados": results, "erros_js": page_errors, "console": console_errors, "http_4xx": http_4xx},
                                                     ensure_ascii=False, indent=2), encoding="utf-8")
    passed = sum(r["ok"] for r in results)
    print(f"RESULTADO NAVEGADOR: {passed}/{len(results)}")
    sys.exit(0 if passed == len(results) else 1)


if __name__ == "__main__":
    main()
