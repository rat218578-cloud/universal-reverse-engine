# Empacotamento e compatibilidade do Universal Reverse Engine

Este documento registra a auditoria de dependências, a estratégia de empacotamento do aplicativo
Windows (sem Python instalado no computador do usuário) e a avaliação para Android. Cada afirmação
sobre o comportamento foi conferida no código ou em execução real, indicada como tal.

## 1. Auditoria de dependências

| Componente | Dependência de terceiros | Observação (verificada) |
|---|---|---|
| Backend Python (`apps/backend/ure`) | **Nenhuma** | `pyproject.toml` tem `dependencies = []`. Varredura AST: só stdlib e o pacote `ure`. |
| Python exigido | ≥ 3.11 | `requires-python` do pacote. O runtime empacotado é 3.12.10. |
| Interface web (`apps/web`) | Nenhuma (ES modules, sem build) | servida pelo próprio backend (`ure/web`). |
| Launcher Windows (Tauri 2 / Rust) | crates `tauri`, `tauri-plugin-dialog`, `getrandom` | sem Python do sistema em release. |
| Ferramentas externas | apktool, JADX, Android `apkanalyzer`, ILSpy (`ilspycmd`), Ghidra `analyzeHeadless`, Java | **opcionais**. Quando ausentes, o motor aparece como `missing`, sem simular resultado. Nenhuma é necessária para abrir o app ou analisar com os motores locais. |
| `git` | opcional | só para a exportação Git; sem ele a exportação Git retorna erro explícito. |
| LIEF | opcional | biblioteca Python; detectada se instalada, nunca obrigatória. |
| Ollama / modelo de IA | opcional | `URE_AI_ENABLED=0` por padrão. A análise estática não depende de IA. |
| Docker, PostgreSQL | não usados | — |

Conclusão da auditoria: o backend precisa apenas de um interpretador Python 3.11+ com a stdlib
completa. Isso permite empacotar um runtime oficial sem `pip` nem pacotes adicionais.

## 2. Windows: runtime Python embutido

**Estratégia escolhida:** o *embeddable package* oficial do Python 3.12 (`python-3.12.10-embed-amd64.zip`),
incluído no instalador como recurso `python\`.

- `apps/desktop/python-runtime.json`: versão, URL oficial e SHA-256 fixado.
- `apps/desktop/scripts/fetch-python.ps1`: baixa, **verifica o SHA-256** (divergência interrompe o
  build), extrai, gera `python312._pth` com `..\backend` no `sys.path` e valida que
  `python -I -c "import ure.server, ..."` funciona. Modo isolado (`-I`) ignora variáveis e pacotes
  do sistema, então a validação prova que nada externo é necessário.
- `tauri.conf.json`: `bundle.resources` inclui `python` → `python\`; o WebView2 é embutido no
  instalador (`embedBootstrapper`), sem download durante a instalação.
- Launcher (`backend.rs`): em release, o runtime empacotado é **a única** opção. Se ele não existir
  ou falhar, o app mostra uma mensagem; não há fallback para um Python do sistema. Python do sistema
  só é considerado em builds de desenvolvimento.

**Como o critério foi verificado:** o teste de instalação do GitHub Actions (`smoke-windows.ps1`)
- remove do PATH qualquer diretório de Python e as variáveis `URE_PYTHON`/`PYTHON*`, e confirma que
  `python` não é encontrado;
- instala o NSIS em silêncio e confirma que `python\python.exe` foi instalado;
- confirma pelo processo (`Win32_Process`) que o backend roda `...\python\python.exe`;
- executa a análise de APK, EXE e DLL (incluindo binários reais) pelo backend instalado;
- fecha a janela, mata o app à força e confirma que o backend encerra em cada caso;
- confirma persistência de projeto após reinício do backend e desinstala.

**Limite honesto:** o runner do GitHub Actions é uma máquina virtual com muitas ferramentas
instaladas. Ele não é uma instalação Windows limpa. A remoção do Python do PATH e a verificação
pelo caminho do processo cobrem a dependência de Python, mas não substituem um teste em uma
instalação Windows sem nenhum outro software de desenvolvimento. Esse teste deve ser feito
manualmente antes de uma distribuição.

**Limitações:** o instalador não é assinado (SmartScreen alertará). O runtime é fixado em 3.12; a
atualização do Python exige atualizar `python-runtime.json` e repetir o teste.

## 3. Android: avaliação

O Python do Windows **não** pode ser copiado para o APK: o runtime do Windows é um binário PE
(`python.exe`, `python312.dll`) e não executa no Android. Foram avaliadas três alternativas:

| Opção | Descrição | Prós | Contras |
|---|---|---|---|
| **A. Python embutido no Android (Chaquopy)** | Runtime Python para Android empacotado no APK, executando o mesmo `ure` localmente. | Reutiliza o backend integral; processamento local. Licença e compatibilidade com AGP 9 **ainda não confirmadas na fonte oficial** (verificar antes de adotar). | Aumenta o APK por arquitetura; limitado às funções stdlib; subprocessos e ferramentas Java não funcionam. |
| **B. Reimplementação nativa (Kotlin)** | Reescrever análise de ZIP, DEX, PE e relatórios em Kotlin. | Sem runtime Python. | Duplica o motor, com risco de divergência; esforço grande; não reaproveita os testes. |
| **C. Backend remoto** | APK como cliente de um URE rodando em desktop ou servidor, com TLS e token. | Permite Ghidra, ILSpy, JADX e apktool. | Exige servidor e rede; superfície de ataque (TLS, autenticação, upload remoto). |

**Recomendação:** A para a análise local (o caminho que funciona sem servidor) e C como caminho
opcional para os motores que exigem JVM ou .NET desktop. B não é recomendada agora.

**Estado:** implementada no branch `feature/android-apk` com a opção A (Chaquopy). APK de depuração
gerado e testado no emulador pela CI. Detalhes, versões e pendências em `docs/ANDROID.md`.

### Matriz de recursos (baseada no código auditado)

| Recurso | Android local (opção A) | Exige servidor (opção C) | Observação |
|---|---|---|---|
| Criar e listar projetos, persistência | Sim | — | armazenamento em disco do app |
| Upload de arquivos com SHA-256 | Sim | — | validação de tamanho e formato no backend |
| Extração segura de ZIP/APK (limites, sem links) | Sim | — | `safezip.py` |
| Identificação de formato (APK, PE, ELF, Mach-O) | Sim | — | `identify.py` |
| Detecção de segredos com redação | Sim | — | `secrets.py` |
| Análise de APK: arquivos, DEX listados, bibliotecas nativas | Sim | — | análise Python sobre o ZIP |
| AndroidManifest em texto legível (AXML) | **Não decodificado** | — | limitação já documentada; apktool decodifica, mas não roda no Android |
| Análise de EXE/DLL: cabeçalhos, seções, importações | Sim | — | `pe.py`, puro Python |
| Decompilação .NET (ILSpy) | Não | Sim | JVM/.NET desktop |
| Análise nativa com Ghidra | Não | Sim | Java desktop |
| Decompilação DEX para Java (JADX) | Não | Sim | Java desktop |
| Decodificação completa com apktool | Não | Sim | Java desktop |
| Relatórios e exportação ZIP | Sim | — | |
| Exportação Git | Não | — | depende de `git` |
| IA (Ollama) | Não | — | desligada por padrão; nunca obrigatória |

**Regra de compatibilidade:** quando um motor exigido não está disponível localmente, o relatório
registra `missing` com o motivo, e a interface informa que o arquivo precisa do app Windows ou de
um servidor. Nenhum resultado é simulado.

## 4. Critério de aprovação

- Windows: instalação sem Python, pip, Docker, Ollama ou ferramentas de desenvolvimento — **coberto
  por automação no runner** (ver seção 2, com o limite declarado).
- Android: APK de depuração gerado pela CI e instalação/abertura testadas no emulador x86_64. Aparelho
  real e análise de APK dentro do app ainda pendentes (ver `docs/ANDROID.md`).
- Web e Windows existentes: a regressão do backend roda no workflow `windows-app.yml` (Windows) e na
  CI (Linux). Os resultados exatos estão nos logs das execuções, não neste documento.
