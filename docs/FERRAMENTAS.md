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
