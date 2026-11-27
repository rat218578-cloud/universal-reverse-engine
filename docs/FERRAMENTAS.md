# Ferramentas de engenharia reversa do URE

Este documento registra o estado **real** das ferramentas no servidor de desenvolvimento
(Ubuntu 24.04.5, x86_64, 2 vCPU, 8 GB RAM) e no CI (Ubuntu 26.04, Windows). Nada aqui é
simulado: cada versão foi lida de uma execução real.

## Instaladas e verificadas

| Ferramenta | Versão verificada | Caminho | Como foi instalada | Teste de execução |
|---|---|---|---|---|
| OpenJDK (Java) | 17.0.21 | `/usr/bin/java` | apt `openjdk-17-jre-headless`; `update-alternatives` fixa a 17 | `java -version` |
| Apktool | 2.7.0 | `/usr/bin/apktool` | apt `apktool` (2.7.0+dfsg-7) | `apktool --version`; decodificação real de APK de teste |
| .NET SDK | 8.0.134 | `/usr/bin/dotnet` | apt `dotnet-sdk-8.0` (não instalado no CI) | `dotnet --version` |
| LIEF | 1.0.0 | `/opt/ure-tools/venv/bin/python` | pip `lief==1.0.0` em venv próprio | `import lief` |
| aapt / aapt2 (Android SDK) | aapt 14~beta1; aapt2 2.19 | `/usr/bin/aapt`, `/usr/bin/aapt2` | apt `aapt`, `android-sdk` | usado pelo Apktool |

`/opt/ure-tools/tools.env` é gerado pelo instalador e lido pelo servidor na inicialização:

```
URE_LIEF_PYTHON=/opt/ure-tools/venv/bin/python
URE_JAVA=/usr/bin/java
URE_DOTNET=/usr/bin/dotnet
URE_APKTOOL=/usr/bin/apktool
```

## Não instaladas (bloqueio de fonte, não de configuração)

| Ferramenta | Motivo verificado | Como liberar |
|---|---|---|
| JADX | Releases do GitHub bloqueadas pela política de rede; não existe no apt do Ubuntu 24.04/26.04, no PyPI oficial nem no conda-forge. O pacote `pyjadx` do PyPI baixa os JARs do GitHub/Maven na primeira execução, então não é uma instalação real. | Informar `URE_JADX_URL` e `URE_JADX_SHA256` (ZIP oficial) para `scripts/install-tools.sh`. |
| Ghidra | Releases do GitHub bloqueadas; não há pacote apt nem conda. | `URE_GHIDRA_URL` e `URE_GHIDRA_SHA256`. Exige Java 17+. |
| ILSpy (`ilspycmd`) | Pacote NuGet e Maven bloqueados. | `URE_ILSPYCMD_NUPKG_URL`, `URE_ILSPYCMD_NUPKG_SHA256`, `URE_ILSPYCMD_VERSION`. Exige .NET SDK. |
| apkanalyzer (Android SDK cmdline-tools) | `dl.google.com` bloqueado; o apt `android-sdk` não traz apkanalyzer. | `URE_APKANALYZER_URL` e `URE_APKANALYZER_SHA256`. |

Enquanto faltarem, o relatório de análise marca cada motor como `missing` com o motivo. O
servidor não apresenta resultado simulado para essas ferramentas.

## Persistência

- **Servidor atual (sem systemd, PID 1 = process_api):** as ferramentas ficam em `/usr`
  e `/opt/ure-tools`, fora de qualquer diretório temporário. O servidor carrega
  `URE_TOOLS_ENV` (padrão `/opt/ure-tools/tools.env`) antes de sondar as ferramentas.
- **Docker:** o `Dockerfile` executa o mesmo `scripts/install-tools.sh` durante o build.
  **Não foi construído aqui**: o daemon Docker está inativo e o Docker Hub é inacessível.
- **Scripts:** `scripts/install-tools.sh` (instalação, root) e `scripts/diagnose-tools.sh`
  (diagnóstico). O diagnóstico roda `python -m ure.toolcheck`, que executa cada ferramenta
  de verdade e sai com código diferente de zero se Java, Apktool ou LIEF falharem.

## Limites de execução dos motores

Cada ferramenta limitada roda com teto de memória virtual (`URE_TOOL_MEMORY_MB`, padrão
3072 MB), tempo limite e captura de saída limitada. Para a JVM, o heap é limitado a metade
desse teto (`JAVA_TOOL_OPTIONS=-Xmx`) e `MALLOC_ARENA_MAX=2` evita que as arenas do glibc
esgotem o endereçamento. Esses ajustes foram necessários porque o CI Ubuntu falhava com
`insufficient memory for the Java Runtime Environment` sob o teto anterior.

## O que não foi testado

- Reinicialização real do host: o PID 1 não é systemd, então a persistência após reboot não
  pôde ser provada. O teste `RestartTests` reinicia apenas o servidor HTTP em processo.
- Construção da imagem Docker.
- Análise com JADX, Ghidra, ILSpy e apkanalyzer (ausentes).
- Análise de .NET (ILSpy) e de bibliotecas nativas com Ghidra.

## Ambientes de processamento (importante)

O URE roda em dois lugares diferentes, com ferramentas diferentes:

- **Servidor (Linux):** `ure/server.py` carrega `URE_TOOLS_ENV` (padrão `/opt/ure-tools/tools.env`).
  É aqui que Java, Apktool, .NET e LIEF estão instalados e são reconhecidos.
- **Aplicativo Android (Chaquopy):** `ure_android.py` sobe o backend em Python embutido, dentro do
  processo do app. Ele **não** lê `/opt/ure-tools/tools.env`, e o APK não contém Java, Apktool, JADX,
  apkanalyzer, ILSpy nem Ghidra. Por isso a tela do aparelho mostra essas ferramentas como ausentes.
  O LIEF também não é instalado: `chaquopy.gradle` não declara nenhum pacote Python, e o índice de
  pacotes do Chaquopy não é acessível daqui para confirmar se há um wheel do LIEF para Android.

Para analisar um APK com as ferramentas instaladas, o APK precisa ser processado pelo servidor.

## Regras de status (desde a última correção)

- Ferramenta `available` exige que o comando de versão execute com código 0. Arquivo que existe mas
  não executa aparece como `missing`, com o motivo.
- LIEF: quando o módulo não importa, o motor de análise reporta `missing` com o motivo (não `failed`).
  Erros do worker que não são módulo ausente continuam `failed`.

## Atualização: alternativas oficiais instaladas (2026-11-26)

Fontes verificadas: os repositórios do GitHub (releases e API) respondem 403 pela política do
proxy; `dl.google.com`, Maven e NuGet não respondem. Foram usados apenas apt oficial do Ubuntu e o
índice oficial do PyPI. Nenhum hash foi informado de memória: cada um foi conferido contra o índice.

| Motor | Papel | Versão | Origem | Verificação real |
|---|---|---|---|---|
| Androguard | manifesto, componentes, classes e decompilação DEX para Java (no lugar do JADX) | 4.1.4 | PyPI, venv do LIEF | importa; `androguard decompile` gera `Main.java` com o código do fixture |
| radare2 | funções e símbolos de bibliotecas nativas (no lugar do Ghidra) | 5.5.0 | apt (`/usr/bin/r2`) | encontra `sym.ure_fixture_add` no `libfixture.so` |
| apksigner | assinatura e certificados do APK (parte do apkanalyzer) | 0.9 (pacote 31.0.2) | apt (`/usr/bin/apksigner`) | APK assinado com chave de teste: verificado, DN e SHA-256 do certificado; APK sem assinatura: não verificado, com motivo |
| monodis | desmontagem IL de assemblies .NET (não gera C#; parte do ILSpy) | mono-utils 6.8.0 | apt | lê `Calc::Add` na assembly de teste; arquivo que não é .NET é `failed` com motivo |

Continuam ausentes, sem fonte acessível daqui: **JADX** (substituído pelo Androguard para Java),
**apkanalyzer** (substituído parcialmente por Androguard e apksigner), **ILSpy** (substituído
parcialmente pelo monodis em nível IL), **Ghidra** (substituído pelo radare2). `rizin` não existe no apt.

### Pacotes ZIP para instalação (`/opt/ure-tools/packages/`)

| Arquivo | SHA-256 do ZIP | Conteúdo e verificação |
|---|---|---|
| `ure-tool-androguard-4.1.4-cp313-linux-x86_64.zip` | `d7a4e41fd3c3c20e6c6e1eeebcf440d178159b29c1845eaf8c245ac6c20e4bed` | 37 wheels (Python 3.13, linux x86_64); cada hash confere com o índice JSON do PyPI; instalado offline em venv nova |
| `ure-tool-radare2-5.5.0-amd64.zip` | `0d68b26c1bb4043bf1ac6fe8d21e0a2cfbf91783fce1f5e56ca6e33b1b86af9d` | `.deb` oficial; SHA-256 confere com o índice do apt |
| `ure-tool-monodis-6.8.0-amd64.zip` | `593e474ad13cc8294c76c791317016277030ae36f4502faf84ad7cf8bd65ffec` | `.deb` oficial (mono-utils); confere com o apt |
| `ure-tool-apksigner-31.0.2-all.zip` | `ab732884b6b75b190e1091c7f3375dc5304cce320f12d6b62f7db86ecfde4e35` | `.deb` oficial; confere com o apt |

Cada ZIP traz `manifest.json` (origem de cada hash) e `SHA256SUMS.txt`. Os ZIPs não estão hospedados
em nenhuma URL: o gerenciador só consegue instalá-los a partir de uma URL pública ou de arquivo local.

### Aplicativo Android

`URE_RUNTIME=android` é definido pelo backend do aparelho e a tela mostra "onde roda: aparelho
(Android)". Nenhuma das ferramentas acima está no APK. Execução na nuvem para o aparelho exige que
o aplicativo aponte para um servidor; essa parte ainda não existe.
