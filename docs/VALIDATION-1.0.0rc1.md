# Relatório de Validação — Universal Reverse Engine 1.0.0rc1

Base validada: `bd51013` (branch `release/1.0.0`, RC original, preservada e sem alterações).
Branch de validação: `validation/1.0.0rc1-bd51013`. Commits de correção: `afd426b`, `fc4a929`.

Este relatório separa o que foi **observado em execução** do que apenas foi verificado por inspeção.
Nada aqui foi declarado como testado sem execução.

## 1. Ambiente de validação

| Item | Situação |
|---|---|
| Sistema | Linux, 1 CPU, 3,9 GiB de RAM, Python 3.12.3, Node 22.23.5 |
| Navegador | Chromium 157.0.8103.78 headless, via Playwright 1.63.0 (`/opt/pw-browsers`) |
| Java | OpenJDK 21 (runtime). Sem `javac`. |
| Motores de análise | apktool, JADX, apkanalyzer, ilspycmd, Ghidra, aapt/aapt2, dotnet: **ausentes** |
| IA local | Ollama ausente; nada em `127.0.0.1:11434`; nenhum modelo (`.gguf`/`.safetensors`) no disco |
| Rede | Indisponível (GitHub e PyPI inacessíveis) |
| Arquivos reais | PE real: `w32.exe` (launcher do pip, PE32 x86). ELF real: `/usr/bin/ls`. APK e DEX reais: **nenhum** |

## 2. Aprovado (executado e observado)

| Verificação | Como foi executada | Resultado |
|---|---|---|
| Suíte Python | `unittest discover` no código validado | **137/137** |
| Suíte Node (parser SSE e formatação) | `node --test` | **4/4** |
| E2E de segurança, código-fonte | `scripts/e2e_security.py` | **22/22** |
| E2E de segurança, wheel final instalado do zero | mesmo script, `URE_E2E_PYTHON` do venv | **22/22** |
| Navegador real, wheel final instalado do zero | `scripts/browser_e2e.py` (Chromium) | **21/21** |
| Inicialização do servidor instalado | `ure-server` no venv limpo, fora do repositório | Sobe, usa a interface empacotada, responde em `/api/v1/health` |
| Autenticação | navegador (token vazio, correto, errado) e API (401/200) | Aprovado |
| Upload de APK | navegador (seletor de arquivo e arrastar-e-soltar) e HTTP | Identificado como APK pelo conteúdo |
| Upload de EXE real | navegador e HTTP | Identificado como PE; SHA-256 conferido |
| Recusa de formato | navegador e HTTP | Texto disfarçado de `.exe` recusado com HTTP 415 |
| Análise do APK | navegador | Concluída; integridade `ok`; progresso e relatório exibidos |
| Análise do EXE real | navegador e HTTP | Importações de KERNEL32, USER32 e SHLWAPI exibidas |
| Ferramentas ausentes | navegador | Exibidas como `missing` com motivo; nenhum resultado simulado |
| Extração do APK | navegador e HTTP | Concluída; árvore mostra `AndroidManifest.xml` extraído |
| Árvore de arquivos | navegador | Navegação por pastas e raízes (original, extracted) funciona |
| Visualização de texto | navegador | Conteúdo de `assets/notes.txt` exibido |
| Visualização hexadecimal | navegador | EXE original mostra `4d 5a` (assinatura MZ) |
| Exportação ZIP | navegador (download real) e HTTP | ZIP contém `MANIFEST.json` e `extracted/` |
| Bomba de ZIP forjada pela rede | HTTP | Rejeitada com 413; saída parcial removida do disco |
| DNS rebinding, Host e Origin | HTTP | Bloqueados com 403 |
| Cliente lento | HTTP | Desconectado pelo timeout de socket (~2 s) |
| Exclusão sem confirmação | HTTP | Recusada com 409 |
| Rota inexistente e token errado na interface | navegador | Tratados sem exceção |
| Exceções de JavaScript na página | navegador | Nenhuma |
| `console.error` de código da interface | navegador | Nenhum |
| Coerência interface × API | comparação automática das 18 chamadas do `app.js` com as rotas | 0 incompatíveis |
| Tracebacks no log do servidor | E2E e cenários de desconexão | 0 após as correções |

Capturas de tela das telas percorridas estão em `/home/claude/validation/shots-final/`.

## 3. Reprovado na RC original e corrigido nesta validação

Seis problemas foram **reproduzidos na RC `bd51013`** e corrigidos. Cada um tem teste de regressão que falha na RC e passa na correção.

| # | Problema observado | Evidência na RC | Correção |
|---|---|---|---|
| 1 | **Captura de saída de motores sem limite** (regressão introduzida na reescrita de segurança) | Log de 49 MiB gerado por um processo que escreve sem parar | Captura limitada a 4 MiB por fluxo, com marcador de truncamento; o processo continua sendo drenado |
| 2 | **Página do projeto mostrava `null`** quando não havia descrição | Captura de tela da RC; verificação de texto no navegador falhou na RC e passou na correção | Filtro de nulos em `show()` (`replaceChildren` convertia `null` em texto) |
| 3 | **Mensagem de formato recusado com termo técnico** (`formato não aceito: unknown. assinatura não reconhecida`) | Texto literal exibido na tela da RC | Mensagem em linguagem clara por tipo detectado |
| 4 | **Tracebacks falsos no log** quando o cliente desconecta antes da resposta | 8 tracebacks (`BrokenPipeError`) em três cenários de desconexão | Desconexão tratada como fim normal da conexão; o servidor não é afetado |
| 5 | **Versão do Java exibida como aviso da JVM** (`Picked up JAVA_TOOL_OPTIONS...`) | Captura da seção "Ferramentas detectadas" | Detecção ignora linhas de aviso e prefere a linha com "version" |
| 6 | **Porta ocupada gerava traceback** em vez de mensagem | `OSError: Address already in use` com traceback completo | Mensagem orientando `URE_PORT` e código de saída 1 |

Registro de processo: durante a validação, eu alterei por engano a árvore de trabalho da branch `release/1.0.0`
antes de perceber. As alterações não estavam commitadas e foram movidas para a branch de validação sem commit
intermediário. A conferência posterior confirmou que `release/1.0.0` permanece em `bd51013`, sem diferença de conteúdo.

## 4. Testes de regressão

- `apps/backend/tests/test_validation_regressions.py`: 7 casos. Na RC original, **6 falham** (os problemas 1, 3, 4, 5 e 6, e o cenário de captura de stdout separado); o 7º (saída pequena preservada inteira) passa nos dois códigos, como esperado, porque protege contra regressão da própria correção.
- Teste de navegador contra a RC original: reprova em `null` (problema 2) e no texto da mensagem (problema 3), com o texto exato registrado na saída.

## 5. Limites de segurança restantes: medições

| Limite | Como foi medido | Resultado | Situação |
|---|---|---|---|
| **CPU** | Latência de `/api/v1/health` durante extração de 180 MiB | Mediana 1 ms, p95 3 ms, máximo 3 ms. A extração levou 0,3 s, então é uma carga curta | **Não aplicado.** O limite é só de tempo. Não há teste de carga prolongada |
| **Disco** | Diretório de dados após um upload de 180 MiB e a extração | 361 MiB (o original e a cópia extraída coexistem) | **Sem cota global.** Limite apenas por artefato (2 GiB) |
| **Conexões** | 400 conexões ociosas abertas e health consultado | Health respondeu 200 em 0 ms; 358 threads; RSS 35 MB | **Sem limite.** Uma thread por conexão. Um teste com 1200 conexões não concluiu no tempo disponível |
| **Arquivos temporários** | Upload interrompido no meio do corpo | 0 arquivos `.upload.part` restantes; 0 artefatos parciais | **Aprovado** |
| **Logs de motores** | Processo que gera 15 MiB de saída | RC: 49 MiB gravados. Validação: teto de 4 MiB | **Corrigido** (teste de regressão) |
| **Varredura de logs por segredos** | Inspeção do código | Logs de motores não são varridos | **Não implementado** (já registrado na auditoria) |
| **Concorrência de extração** | 6 extrações simultâneas do mesmo artefato | 1 × HTTP 200 e 5 × HTTP 409 | **Aprovado** |
| **Concorrência de análise** | Teste unitário de lock ocupado | `BusyError` como esperado | **Aprovado no nível de unidade**; não medido sob carga HTTP nesta rodada |

## 6. Motores externos

**Nenhum motor de análise foi executado.** Apktool, JADX, apkanalyzer, ilspycmd, Ghidra e LIEF estão ausentes
e não há rede para instalá-los. O único motor relacionado disponível é o runtime Java, que foi detectado
corretamente (problema 5 corrigido). As etapas de motor aparecem no relatório como `missing`, com o motivo.

**Não validado:** qualquer saída de decompilação, decodificação de manifesto (AXML) ou execução de motor.

## 7. Integração com IA

**Não testado com modelo real.** Não há Ollama instalado, nenhum modelo local e nenhum provedor externo
configurado. O roteador foi testado somente com servidores falsos em loopback (test doubles), o que valida
o protocolo do roteador, não a qualidade ou o comportamento de um modelo. A defesa contra prompt injection
depende do modelo obedecer às instruções do papel de sistema; isso não foi observado.

## 8. Não testado (com ferramenta disponível no ambiente)

- Cancelamento de job pela interface: o botão existe, mas nenhuma análise dura o suficiente para acioná-lo no navegador. Coberto por teste de backend.
- Progresso em tempo real (SSE) observado na tela: as análises concluem em menos de um segundo.
- Exportação com a opção "incluir arquivo original" marcada, pela interface.
- Análise profunda (checkbox "Ghidra").
- Upload de arquivo maior que o limite pela interface.
- Dois usuários simultâneos pela interface.
- Layout em telas pequenas (apenas 1280 px foi usado).
- Firefox e WebKit: somente Chromium foi testado.
- Python 3.11 (declarado no pacote, não testado).
- Carga prolongada de CPU, memória e disco.

## 9. Dependente de infraestrutura externa

- apktool, JADX, apkanalyzer, ilspycmd, Ghidra e LIEF: instalação exige rede ou pacotes que não estão disponíveis.
- Ollama e modelos de IA locais: exigem download.
- Provedor de IA externo: exige chave, rede e autorização de envio de dados.
- Windows e macOS: exigem máquinas dessas plataformas. Os limites de memória dos motores só existem em POSIX.
- Docker: não disponível; Dockerfile não construído.
- Tauri e desktop: exigem toolchain Rust e Windows; não compilados.
- GitHub (remoto, CI, repositório privado): exige rede e autorização.

## 10. Artefatos de validação

Gerados a partir do commit `fc4a929`, em `dist-validation/` (não versionado):

| Arquivo | SHA-256 |
|---|---|
| `universal_reverse_engine-1.0.0rc1-py3-none-any.whl` | `0bfa8faa81b81af6510251db3871656a2a4c6f1c0ad5a1345fb6cff51731bf95` |
| `universal-reverse-engine-1.0.0rc1-source.tar.gz` | `a3e08beaee33ba5a5135b04e6354ffd045ac2572c4e79e7d4f44e3b258dde7ba` |
| `BUILDINFO.txt` | `c7e893396437b3f800dd2a56abaf95c7492ea29798004d2016e1dfcacd6a1851` |

Os fontes do wheel são idênticos aos do commit `afd426b`, que foi o validado; apenas `.gitignore` mudou depois.
Hashes de wheel podem variar entre builds de fontes idênticos por causa de carimbos de tempo dos arquivos.
O wheel final foi o instalado e testado.

Artefatos da RC original (`dist/`, intactos, verificados com `sha256sum -c`):
- wheel `461e6b62040ec4a000ab5507aced3dc4f0c53dfe93158e9d0031aad28826afa5`
- código-fonte `187632210088b10c9d7645ce6efedadefea985d8e2ba8f19d68306757e6fb072`

## 11. Veredito

**Não aprovado para lançamento público.** A versão validada corrige seis problemas reais e passa em todos
os testes que o ambiente permite executar. Mas o lançamento público exige, no mínimo:

1. Executar pelo menos um motor de análise real (apktool ou JADX) contra um APK real, e validar a saída.
2. Validar a IA com um modelo real, ou documentar explicitamente que a IA não será oferecida na versão.
3. Testar em Windows, que é a plataforma-alvo do desktop, ou restringir a declaração de suporte a Linux.
4. Definir a licença do projeto.
5. Decidir sobre limites de disco e de conexões antes de expor o servidor a múltiplos usuários.
6. Executar a interface em Firefox e em telas pequenas, se a interface for distribuída como produto.
