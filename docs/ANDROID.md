# URE no Android (Tauri 2 + Chaquopy)

Este documento descreve o que foi implementado no branch `feature/android-apk`, o que foi verificado
e o que ainda não foi. Cada afirmação de resultado aponta para uma execução de CI ou para o código.

## Estado

| Item | Situação |
|---|---|
| APK de depuração gerado pela CI (arm64-v8a + x86_64) | **Sim.** Execução [45280246456](https://github.com/rat218578-cloud/universal-reverse-engine/actions/runs/45280246456), commit `7d7df13`, passo "Verificar APK" OK |
| SHA-256 do APK | `32c5886aa300fbb3f7100686d731678d38d91946bf60a1eaaa095f2e70df5b9d` (279 187 319 bytes, debug, assinado com a chave de depuração) |
| Instalação e abertura no emulador x86_64 (API 34) | **Sim.** Mesma execução, passo "Teste de instalação no emulador": `interface online` |
| Testes do backend, incluindo o entrypoint Android | **158 testes, OK** (Linux, mesma execução) |
| Testes do desktop Windows (inclui o novo `test_android_entry`) | Passou no `windows-app` do commit `bb73157` |
| Aparelho físico ARM64 | **Não testado.** O APK arm64 foi compilado, não executado |
| Upload e análise de um APK dentro do app Android | **Não verificado** (ver "Pendências") |
| Ferramentas externas (apktool, JADX, Ghidra, ILSpy, apkanalyzer) | Não executam no Android (ver matriz) |
| Integração remota opcional | **Não implementada** (ver "Integração remota") |

## Arquitetura

O backend Python existente roda **dentro do processo do app**, com Chaquopy. Não há processo filho.
A interface web (`apps/web`) é a mesma do desktop e da versão web.

```
MainActivity (Kotlin)
 ├─ escolhe porta livre e gera token novo (32 bytes, a cada abertura; não é gravado em disco)
 ├─ copia apps/web (assets/ure-web) para filesDir/ure-web, uma vez por versão do app
 ├─ Python.start + ure_android.start(dataDir, webDir, porta, token)   (thread "ure-start")
 ├─ aguarda GET /api/v1/health = 200 (até 40 s)
 └─ WebView: addDocumentStartJavaScript("window.URE_DESKTOP = {token}") restrito a
    http://127.0.0.1:<porta>, e loadUrl("http://127.0.0.1:<porta>/")
```

- `apps/desktop/android/python/ure_android.py`: `start` e `stop`. Sobe `make_server` em uma thread
  do processo, escutando só em `127.0.0.1`. Valida token (mínimo 32 caracteres) e porta.
- `apps/desktop/src-tauri/src/lib.rs`: entrypoint compartilhado (`mobile_entry_point`). O lançador de
  processo do Windows ficou em `desktop.rs`, compilado só para desktop (`cfg(desktop)`). O comportamento
  desktop não mudou; os 12 testes Rust passam.
- `apps/desktop/src-tauri/tauri.android.conf.json`: declara a janela principal e usa a tela de
  abertura `apps/desktop/android/splash`. A janela precisa existir aqui: sem ela o Tauri não cria a
  WebView e o backend nunca inicia (causa da falha de `45243679892`, corrigida em `bb73157`).
- `tauri.windows.conf.json`: o runtime Python do instalador Windows foi movido para cá, para que
  Linux e Android não exijam `python/` no build.
- `apps/desktop/android/overlay/`: arquivos Gradle, `MainActivity.kt`, manifesto e
  `network_security_config.xml`. `apps/desktop/android/scripts/prepare-android.sh` gera o projeto com o
  CLI do Tauri e copia o overlay por cima. `gen/` é ignorado pelo git.
- `apps/desktop/android/overlay/app/chaquopy.gradle`: copia `apps/backend/ure` e `ure_android.py` para
  o módulo Python, e `apps/web` para os assets. Não altera nenhum arquivo do repositório.

### Segurança e dados

- Nenhuma rede externa: o WebView só navega dentro de `http://127.0.0.1:<porta>`. Outros destinos
  são bloqueados (`BackendOnlyClient`) e não são abertos.
- Texto puro só para `127.0.0.1` (`network_security_config.xml`). `allowBackup=false`.
- Permissão: apenas `INTERNET` (necessária para o socket de loopback). Nenhuma permissão de
  armazenamento: os arquivos são escolhidos pelo seletor do sistema e processados em `filesDir`.
- Os APKs enviados não saem do aparelho. O provedor de IA continua desligado (`URE_AI_ENABLED=0`).
- O token não é gravado em disco e vale só para a sessão do processo.

## Compatibilidade e dependências

| Componente | Versão usada na CI | Observação |
|---|---|---|
| Tauri (crate) / tauri-cli | 2.12.7 / 2.12.6 | |
| wry | 0.57.3 | seletor de arquivos (`<input type=file>`) já vem do wry |
| Android Gradle Plugin | 9.3.1 | o template Tauri usa esta versão; o plugin Rust do Tauri depende de uma tarefa que não existe no AGP 9.0.1 |
| Gradle | 9.6.1 | |
| Kotlin | 2.2.10 | |
| Chaquopy (plugin) | 17.0.0 | a documentação consultada só confirma AGP 9.0.0; a combinação com AGP 9.3.1 foi **verificada apenas pelo build da CI** |
| Python embutido (Chaquopy) | 3.12 | `buildPython python3` no runner (3.12.16) |
| JDK | 17 (Temurin) | |
| Android SDK | platform android-36, build-tools 36.0.0 | compileSdk/targetSdk 36 |
| NDK | 27.2.12479018 | |
| minSdk | 24 | |
| ABIs | arm64-v8a, x86_64 | variantes de 32 bits e x86 desabilitadas (`8e37a4b`): o Chaquopy 17 com Python 3.12 não as suporta |

Dependências Python: nenhuma além da stdlib (o backend já era assim).

## Matriz de funcionalidades no Android

| Recurso | Android | Motivo |
|---|---|---|
| Interface web completa (projetos, árvore, pré-visualização, relatórios) | Sim | mesma interface, servida localmente |
| Persistência de projetos e arquivos | Sim | `filesDir/ure-data` |
| Upload com SHA-256, extração segura, identificação de formato | Sim (código do backend) | ver pendências sobre o teste no aparelho |
| Análise de APK/EXE/DLL pelos motores Python (PE, ZIP, segredos, identificação) | Sim (código do backend) | puro Python |
| AndroidManifest legível (AXML) | **Não** | apktool não roda no aparelho (já documentado) |
| apktool, JADX, apkanalyzer, ILSpy, Ghidra | **Não** | exigem Java/.NET no processo ou no sistema; aparecem como indisponíveis |
| IA (Ollama ou provedor externo) | Não | desligada por padrão |
| Exportação Git | Não | depende do executável `git` |

Quando uma ferramenta não existe, o relatório mostra `missing` com o motivo. Nenhum resultado é simulado.

## Integração remota (opcional, não implementada)

Para EXE/DLL e para os motores Java/.NET, a opção prevista é um URE rodando em um computador ou
servidor, acessado pelo app com TLS e token. **Não há código para isso neste branch.** Antes de
implementar, é preciso definir: autenticação, transporte cifrado, confirmação explícita do usuário
antes de enviar qualquer APK, e retenção dos arquivos no servidor.

## Como instalar e validar em um aparelho real

1. Baixe o APK do workflow `android-apk` (artifact `universal-reverse-engine-android-debug`) e confira o
   SHA-256 com o valor acima.
2. Em um aparelho ARM64 com Android 7.0 ou superior (minSdk 24), permita a instalação de fontes
   desconhecidas e instale o APK. Ou, com depuração USB: `adb install -r universal-reverse-engine-debug.apk`.
3. Abra "Universal Reverse Engine". A tela inicial mostra "Iniciando o analisador…". Ao ficar pronta,
   a barra superior deve mostrar `online · v...`.
4. Crie um projeto, envie um APK de teste (use um APK de sua escolha, não um arquivo sensível) e
   confirme a árvore de arquivos, o relatório e a exportação.
5. Confirme que o app encerra o backend ao sair: `adb shell ps -A | grep dev.ure` não deve listar o
   processo após o encerramento.
6. Registre o modelo do aparelho, a versão do Android e o WebView usado.

## Pendências

- Teste de **upload e análise** dentro do app: não automatizado. O smoke test só confirma que a
  interface subiu com o token aceito.
- Teste em **aparelho ARM64 real**: pendente. O emulador é x86_64.
- **Build de release** não gerado (somente depuração). Assinatura e minificação ficam para a etapa de distribuição.
- O APK de depuração tem 279 MB (inclui os runtimes Python das duas ABIs e símbolos de depuração). Um
  build de release deve reduzir esse tamanho; isso não foi medido.
- Interface pensada para toque: não avaliada em tela pequena no emulador (o smoke test não captura o layout).
- Integração remota (ver seção acima).
- As evidências do emulador (captura de tela, logcat) estão no artifact `universal-reverse-engine-emulator-smoke`
  da execução. Só são baixáveis com login no GitHub.
- Nenhum merge em `main` nem release foi feito.
