# Aplicativo desktop (Windows) — Universal Reverse Engine

O aplicativo desktop é **uma nova forma de usar o mesmo motor**. Ele não substitui nada: inicia o
backend Python local (`ure.server`), espera o backend responder e abre a interface nele. A versão web
(`python3 -m ure.server` e o navegador) continua funcionando da mesma forma.

Toda a análise de APK, EXE e DLL é feita pelo backend, sem alteração: upload com SHA-256, extração
segura, árvore de arquivos, AndroidManifest, DEX, bibliotecas nativas, relatórios, decompilação via
JADX/apktool/ILSpy/Ghidra (quando instalados) e exportação. O aplicativo não executa o arquivo analisado.

## Como funciona

1. O lançador (`src-tauri/src/main.rs`) usa o runtime Python 3.12 embutido no instalador, uma porta livre no loopback e gera um
   **token novo a cada execução** (32 bytes aleatórios).
2. Inicia `python -m ure.server` com `URE_TOKEN`, `URE_DATA_DIR` e `URE_PORT`. Os dados ficam em
   `%APPDATA%\dev.ure.desktop\data` (projetos, arquivos, relatórios).
3. Aguarda `GET /api/v1/health` responder 200 (até 40 s). Se falhar, mostra o motivo em caixa de diálogo
   e aponta o log em `...\data\logs\backend.log`.
4. Abre a janela apontando para `http://127.0.0.1:<porta>/`. A janela só navega nessa origem.
5. Ao fechar, encerra o backend e seus filhos (`taskkill /T` no Windows).

### Segurança

- **Loopback apenas.** O backend escuta em `127.0.0.1`. Host e Origin são validados pelo backend.
- **Token por execução.** O lançador não grava o token em disco. O backend recebe pela variável de ambiente.
- **Exposição ao JavaScript reduzida.** O token é entregue por `initialization_script` somente no quadro
  principal da janela. A interface lê o valor uma vez, guarda-o no módulo `api.js` e remove
  `window.URE_DESKTOP`. O campo de token não é preenchido na tela.
- **Navegação restrita.** Links para outras origens (inclusive `accounts.google.com`) são bloqueados na
  própria janela. Não há comandos Tauri expostos ao conteúdo da página: nenhum arquivo de capacidades é
  criado, então a página do backend não consegue chamar APIs do sistema.
- **Sem o backend, sem a janela.** Se o backend não responder, a janela não abre.
- **Encerramento garantido.** Ao fechar a janela, o backend é finalizado. Se o aplicativo for morto à força
  (crash, Gerenciador de Tarefas), o backend percebe que o pipe de controle foi fechado e se encerra sozinho
  (`URE_PARENT_WATCH=1`). Verificado no Linux: o backend saiu cerca de 1 s após SIGKILL no aplicativo.

Não são necessários Docker, PostgreSQL nem Ollama. A IA (Ollama, provedor externo) continua desligada por
padrão (`URE_AI_ENABLED=0`).

## Requisitos para compilar (Windows)

| Item | Versão | Observação |
|---|---|---|
| Windows | 10 (1809+) ou 11 | WebView2 é embutido no instalador (não há download na instalação) |
| Rust | stable (testado com 1.97.0) | `rustup` com alvo `x86_64-pc-windows-msvc` |
| Visual Studio Build Tools | 2022, carga "Desenvolvimento para desktop com C++" | exigido pelo Tauri no Windows |
| Node.js | 18+ | só se for usar a CLI do Tauri via npm |
| Python | — | **não é necessário no computador do usuário.** O instalador traz o runtime Python 3.12 embutido. Para compilar, `scripts\fetch-python.ps1` baixa esse runtime |
| tauri-cli | 2.x | `cargo install tauri-cli --version "^2" --locked` |

## Executar a partir do código-fonte (Windows)

```powershell
cd apps\desktop\src-tauri
cargo test                # testes unitários do lançador
cargo tauri dev           # abre o aplicativo; usa apps\backend e apps\web
```

Variáveis úteis (opcionais):

- `URE_PYTHON` — caminho do `python.exe` a usar (deve ser 3.11+; sem fallback silencioso).
- `URE_BACKEND_ROOT` — pasta que contém o pacote `ure\`.

## Gerar o instalador Windows

```powershell
cd apps\desktop\src-tauri
cargo tauri build --bundles nsis,msi
```

Saída: `target\release\bundle\nsis\*.exe` e `target\release\bundle\msi\*.msi`.

O bundle copia `apps\backend\ure` para `backend\ure` e a interface para `backend\ure\web` (ver
`tauri.conf.json > bundle.resources`), incluindo o runtime Python embutido em `python\`.
Nenhuma instalação de Python é necessária no computador do usuário.

### Runtime Python embutido (já incluído)

O instalador inclui Python 3.12.10 (*embeddable package* oficial, `python-3.12.10-embed-amd64.zip`),
verificado por SHA-256 em `python-runtime.json`. O backend não tem dependências de terceiros, então
nenhum `pip` é necessário.

```powershell
pwsh apps\desktop\scripts\fetch-python.ps1     # baixa, verifica o sha256 e prepara src-tauri\python\
```

O arquivo `python312._pth` gerado aponta para `..\backend`, então o runtime encontra o pacote `ure`
instalado em `$INSTDIR\backend`. O launcher usa **somente** esse runtime em release: se ele não existir
ou não funcionar, o app mostra uma mensagem e não cai para outro Python.

## Estado da verificação

| Item | Situação |
|---|---|
| Testes unitários do lançador (Rust, 9) | Passam no Linux |
| Build do binário de depuração (Linux) | Compila sem avisos |
| Execução real no Linux (Xvfb): backend sobe, health 200, UI carrega com token, token aceito (“online”) | Verificado com captura de tela |
| Fechar a janela encerra app e backend, libera a porta | Verificado no Linux |
| Matar o app à força encerra o backend | Verificado no Linux |
| Erro de Python exibido em caixa de diálogo | Verificado no Linux |
| Testes de contrato do backend como processo (token, Host, persistência, encerramento) | Passam em qualquer plataforma |
| Build Tauri no Windows (MSVC, `windows-2022`) | Verificado no GitHub Actions: [run 45075953620](https://github.com/rat218578-cloud/universal-reverse-engine/actions/runs/45075953620) |
| Instalador NSIS (`.exe`) | Gerado no runner e instalado em silêncio no próprio teste |
| Instalador MSI (`.msi`) | Gerado; conteúdo conferido por extração administrativa (não instalado) |
| Teste de instalação Windows (`apps/desktop/scripts/smoke-windows.ps1`) | Passou: instalação, abertura, saúde do backend, janela, encerramento gracioso, morte forçada, análise de APK/EXE/DLL pelo backend instalado, persistência de projeto após reinício, desinstalação |
| WebView2 em Windows | Presente no runner; não testado em máquina do usuário |
| Python no computador do usuário | Não é necessário. O teste remove Python do PATH e confirma que o backend roda do runtime instalado |
| Ícones | Provisórios, gerados por script (`icons/`). Substitua pela marca oficial antes de distribuir |

## Limitações conhecidas

- O limite de memória dos motores externos (`URE_TOOL_MEMORY_MB`) depende de `RLIMIT_AS`, portanto só é
  aplicado em POSIX. No Windows o relatório registra `memory_limit_applied: false`. O timeout e o
  encerramento da árvore de processos funcionam nos dois.
- Assinatura digital do instalador: não configurada. O Windows SmartScreen vai alertar sobre o instalador
  não assinado.
- Atualização automática: não implementada.
- Ferramentas externas (JADX, apktool, ILSpy, Ghidra) não vêm no instalador. Sem elas, o relatório mostra o
  motor como `missing`, sem simular resultado.
