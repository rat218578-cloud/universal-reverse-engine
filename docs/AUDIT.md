# Auditoria Técnica Independente — Universal Reverse Engine

Data da verificação: 21/11/2026. Branch auditada: `develop` em `4aec285`. Escopo: somente leitura, sem
alterações de código, sem push e sem instalação de ferramentas. A única alteração desta etapa é este arquivo.

## Resumo executivo

O projeto tem um núcleo de backend real e bem testado para os casos previstos: upload com validação por
conteúdo, SHA-256, extração com bloqueio de traversal e links, jobs, exportação, rotas HTTP e análise de PE real.
A suíte atual passa: 86 testes Python e 4 testes Node.

O relatório anterior, porém, afirma mais do que o código comprova em alguns pontos, e a auditoria encontrou
lacunas de segurança que não estavam descritas:

- A proteção contra ZIP bomb é contornável por cabeçalhos forjados e não limita a razão agregada.
- A API não valida o cabeçalho `Host`, o que expõe o servidor local a DNS rebinding quando não há token (padrão).
- Não há cancelamento de jobs, não há timeout de socket e não há limite de CPU ou de tempo para o trabalho em processo.
- Manifest binário (AXML) e permissões Android não são decodificados. O DEX é apenas identificado pelo nome.
- Nenhum motor externo real (apktool, JADX, apkanalyzer, ILSpy, Ghidra) foi executado. Os adaptadores são código não validado.
- A interface nunca foi testada em navegador. Partes que o relatório anterior descreve como funcionais (exportação Git,
  licenças, cancelamento) não existem na interface.
- O desktop (Tauri) é um esqueleto que não compila no estado atual: faltam ícones, capabilities, sidecar e a origem da API.

Nenhuma dessas questões invalida o que foi testado. Mas o relatório deve ser lido com essa distinção.

## Legenda de classificação

- **IMPLEMENTADO E VALIDADO**: código existe e há teste automatizado ou verificação HTTP real que cobre o comportamento.
- **IMPLEMENTADO, MAS NÃO VALIDADO**: código existe, mas não há execução com a ferramenta, o arquivo ou o ambiente reais.
- **PARCIAL**: parte do comportamento existe; partes declaradas não existem ou são contornáveis.
- **NÃO IMPLEMENTADO**: não existe no código.
- **BLOQUEADO**: depende de rede ou ferramenta ausente neste ambiente.

---

## A. Git e integridade

### A1. Branch, status e histórico — IMPLEMENTADO E VALIDADO
- **Arquivos**: `.git/` (metadados do repositório).
- **Evidência**: branch atual `develop` (`4aec285`). `git status` limpo antes desta auditoria. `main` aponta para
  `1905f54` (`chore: início do repositório`), que é um commit vazio criado nesta sessão. Não havia histórico anterior.
- **Teste**: verificação direta com `git rev-parse` e `git log`.
- **Limitação**: a `main` não tem conteúdo; o histórico real do projeto está só na `develop`. Os commits e hashes das
  sessões anteriores descritas em conversas não existem neste repositório e não devem ser citados como histórico.
- **Próxima ação**: definir se a `main` receberá o conteúdo da `develop` em algum momento, sempre com aprovação.

### A2. Separação de commits por fase — PARCIAL
- **Evidência**: `d647dae` (fase 0), `f603c33` (fase 1), `faac769` (fases 2 e 3 juntas), `fb854cf` (fase 4),
  `b208abf` (fase 5), `6cf7e84` (fase 6). Os commits de correção e de documentação estão separados.
  As fases 2 e 3 foram agrupadas, o que foi declarado no commit.
- **Limitação**: a fase 0 (`d647dae`) inclui `README.md`, `.gitignore` e configuração, mas não há commit separado para o
  esqueleto de CI. O commit `99677c3` mistura IA externa, licenças, Git local, Dockerfile e Tauri, que são funcionalidades
  distintas e foram marcadas de forma parcial no próprio commit.
- **Próxima ação**: manter as próximas alterações em commits por funcionalidade; não reescrever histórico sem aprovação.

---

## B. Backend

### B1. Upload, identificação e SHA-256 — IMPLEMENTADO E VALIDADO
- **Arquivos**: `apps/backend/ure/app.py` (`upload_artifact`), `ure/identify.py`, `ure/files.py` (`sha256_file`).
- **Evidência**: o corpo é gravado em streaming em `original/.upload.part`, com SHA-256 calculado durante a escrita.
  O tipo é determinado pelo conteúdo. Formato recusado é removido do disco. Original fica com modo `0444`.
- **Teste**: `test_api.py` (PE real com hash conferido, texto disfarçado recusado, extensão falsa), `test_core.py`
  (identificação por assinatura), verificação HTTP com `w32.exe` real.
- **Limitação**: não há cota global de disco. Vários envios simultâneos podem encher o disco, porque o limite é por
  arquivo. Não há timeout de socket: um cliente lento pode manter uma thread presa (ver H).
- **Próxima ação**: cota por projeto e global; timeout de leitura no handler.

### B2. Extração segura (traversal, links, duplicatas, limites) — IMPLEMENTADO E VALIDADO
- **Arquivos**: `ure/safezip.py` (`clean_entry_name`, `safe_extract_zip`, `_write_entry`).
- **Evidência**: rejeita traversal, caminhos absolutos, byte nulo, barra invertida, duplicatas sem diferença de caixa.
  Ignora links simbólicos e entradas especiais (verificado pelos bits de tipo com `S_IFMT`). Gravação com `O_EXCL`
  e `O_NOFOLLOW`. Limites de número de entradas e de bytes totais.
- **Teste**: `test_core.py` (`SafeZipTests`), `test_regressions.py` (`UnixTypeTests`, FIFO/dispositivo/link), e
  verificação HTTP de traversal em extração.
- **Limitação**: o limite de bytes totais usa o tamanho declarado no cabeçalho para uma verificação prévia, mas o controle
  real é o contador durante a escrita. Não há verificação de TOCTOU completa entre `safe_join` e a abertura do arquivo;
  o risco é baixo porque o diretório é do próprio servidor.
- **Próxima ação**: manter; registrar o resíduo de TOCTOU na documentação.

### B3. ZIP bomb — PARCIAL (comportamento inseguro confirmado)
- **Arquivos**: `ure/safezip.py` (`_write_entry`, constantes `BOMB_MIN_SIZE`, `max_ratio`).
- **Evidência confirmada nesta auditoria** (experimentos isolados, sem alterar o repositório):
  - **H1 — cabeçalho forjado**: com `compress_size` declarado em 10¹² bytes e fluxo real de 8 MiB, a entrada foi
    aceita e 8.388.608 bytes foram gravados. A checagem medida divide pelo `compress_size` do cabeçalho, que é
    controlado pelo arquivo. Um atacante consegue zerar a razão medida.
  - **H2 — razão agregada**: 120 entradas de 900 KiB de zeros (120 KB comprimidos no total) foram extraídas para
    105 MiB, razão agregada 921:1. As verificações de razão só atuam em entradas acima de 1 MiB, então muitas entradas
    pequenas passam.
- **Teste**: `test_regressions.py` (`ZipBombTests`) cobre a razão declarada e a medida, mas com `compress_size` honesto.
  Não cobre H1 nem H2. Os testes passam porque testam o caminho esperado, não o adversarial.
- **Limitação**: o limite absoluto de 2 GiB por artefato (`max_extract_bytes`) impede crescimento ilimitado, mas não
  impede uso de até 2 GiB de disco por artefato, com vários artefatos sem cota global.
- **Próxima ação**: medir a razão pelo número real de bytes lidos do arquivo compactado (posição do fluxo) e não pelo
  cabeçalho; adicionar razão agregada por arquivo e teste H1/H2 como casos de regressão; cota global de disco.

### B4. Jobs, progresso e nova tentativa — IMPLEMENTADO E VALIDADO
- **Arquivos**: `ure/jobs.py`, `ure/db.py` (`create_job`, `update_job`), `ure/app.py` (`_sse`).
- **Evidência**: jobs persistidos no SQLite; progresso atualizado durante a análise; falhas capturadas na fronteira do job;
  nova tentativa aceita somente para `failed` e `interrupted`.
- **Teste**: `test_phase2.py` (`AnalysisFlowTests`, `RecoveryTests`), SSE verificado com HTTP real.
- **Limitação**: o pool padrão tem um worker (`URE_JOB_WORKERS=1`). Com mais de um, não há controle de concorrência
  sobre o mesmo artefato (ver B6).
- **Próxima ação**: lock por artefato antes de aumentar o número de workers.

### B5. Cancelamento de jobs — NÃO IMPLEMENTADO
- **Arquivos**: `ure/jobs.py` (só há `shutdown` com `cancel_futures`, usado na encerramento do processo).
- **Evidência**: busca por "cancel" no código retorna apenas `cancel_futures=True`. Não há rota de cancelamento nem
  sinal de interrupção para o trabalho em andamento.
- **Teste**: ausente.
- **Limitação**: um job de análise longo não pode ser interrompido pelo usuário. A recuperação marca jobs como
  `interrupted` após reinício, mas não os retoma.
- **Próxima ação**: rota `POST /jobs/{id}/cancel` com flag verificada nos laços de extração e de varredura, e
  encerramento do subprocesso do motor.

### B6. Recuperação de jobs após reinício — IMPLEMENTADO E VALIDADO (apenas marcação)
- **Arquivos**: `ure/db.py` (`recover_interrupted_jobs`), `ure/app.py` (`App.__init__`).
- **Evidência**: jobs `queued` e `running` viram `interrupted` na inicialização.
- **Teste**: `test_phase2.py::RecoveryTests`.
- **Limitação**: não há retomada. Análises interrompidas precisam ser refeitas do zero, e artefatos parcialmente extraídos
  podem permanecer no disco.
- **Próxima ação**: limpeza de diretórios parciais e, se desejado, retomada por etapa.

### B7. Condições de corrida — PARCIAL (não validado sob concorrência)
- **Arquivos**: `ure/app.py` (`extract_artifact`, linhas em que `rmtree(out)` ocorre), `ure/analysis.py`
  (`_analyze_container`), `ure/db.py` (`update_artifact`), `ure/ai.py` (orçamento).
- **Evidência**:
  - `POST /extract` apaga `extracted/` com `rmtree` enquanto um job de análise pode estar lendo o mesmo diretório.
  - `update_artifact` faz leitura-modificação-escrita de `details`: extração e análise concorrentes sobrescrevem as chaves
    uns dos outros.
  - O orçamento de IA faz `ai_calls_today` e depois `ai_increment` sem atomicidade. Com requisições concorrentes,
    o limite pode ser ultrapassado.
- **Teste**: ausente. Todos os testes são sequenciais.
- **Limitação**: estados inconsistentes e orçamento estourado são possíveis.
- **Próxima ação**: lock por artefato cobrindo extração e análise; atualização atômica de `details` (merge no SQL ou
  transação); incremento atômico do orçamento (`UPDATE ... WHERE calls < ?`); teste de concorrência com threads.

### B8. Limites de tamanho — IMPLEMENTADO E VALIDADO
- **Arquivos**: `ure/app.py` (`upload_artifact`), `ure/config.py`, `ure/safezip.py`.
- **Evidência**: `Content-Length` obrigatório; envio acima do limite recebe 413 antes de ler o corpo.
- **Teste**: `test_api.py::test_oversized_upload_rejected_before_reading_body`; limites de entradas e bytes em `test_core.py`.
- **Limitação**: o limite de upload não cobre o crescimento de disco na extração (ver B3) nem o crescimento dos
  diretórios de exportação, que não são limpos.
- **Próxima ação**: limpeza de `exports/` e cota.

### B9. Limites de memória, CPU e tempo — PARCIAL
- **Arquivos**: `ure/tools.py` (`run_tool`, `_LIMIT_STUB`), `ure/config.py`.
- **Evidência**:
  - **Memória**: RLIMIT_AS aplicado somente a motores externos e somente em POSIX. Testado com processo Python filho
    (`test_run_tool_enforces_memory_limit`). O trabalho em processo (parsing de PE, varredura de segredos com até 2 MiB
    por arquivo, leitura do diretório central do ZIP em `identify`) não tem limite.
  - **Tempo**: tempo limite validado apenas para motores externos (`test_run_tool_enforces_timeout`). Extração, PE e
    varredura não têm tempo limite.
  - **CPU**: não há limite de CPU (`RLIMIT_CPU`) em lugar nenhum. A verificação anterior disse "sem limite de CPU; o tempo
    limite cobre o caso", o que só vale para motores externos.
  - **Windows**: não há nenhum limite de memória aplicado. O relatório mostra `memory_limit_applied: false`, mas a
    documentação não deixa claro que isso vale para a plataforma desktop.
- **Limitação**: um ZIP com milhões de entradas faz `identify` alocar um conjunto com todos os nomes antes de qualquer limite.
- **Próxima ação**: limite de entradas na identificação; tempo limite e cancelamento para o trabalho em processo;
  documentar a ausência de limites no Windows.

### B10. Exportação ZIP — IMPLEMENTADO E VALIDADO
- **Arquivos**: `ure/files.py` (`export_project_zip`), `ure/app.py` (`export_artifact`).
- **Evidência**: MANIFEST com SHA-256 por arquivo; links não incluídos; original apenas com `include_original=1`.
- **Teste**: `test_api.py` e `test_regressions.py` (fluxo completo); verificação HTTP com ZIP de PE e APK.
- **Limitação**: a exportação é síncrona e os ZIPs gerados em `exports/` nunca são removidos.
- **Próxima ação**: limpeza de exportações antigas.

### B11. Segurança HTTP da API — PARCIAL (lacuna relevante)
- **Arquivos**: `ure/app.py` (`_dispatch`, `_check_auth`), `ure/config.py` (`check_bind`).
- **Evidência**:
  - Não há validação do cabeçalho `Host`. Com o token desativado (padrão), qualquer página web aberta no navegador pode
    usar DNS rebinding para ler `/api/v1/projects` e os relatórios de `127.0.0.1`. O bind em loopback não impede isso.
  - Não há timeout de socket (`BaseHTTPRequestHandler.timeout` não é definido). Um cliente que abre uma conexão e
    não envia o corpo mantém a thread ocupada indefinidamente.
  - O token é opcional e o padrão é sem autenticação.
- **Teste**: ausente para `Host` e para timeout.
- **Limitação**: a superfície de ataque local está aberta por padrão.
- **Próxima ação**: aceitar apenas `Host` de loopback; gerar token por sessão por padrão ou exigi-lo; timeout de leitura.

### B12. Exclusão de projeto com confirmação — IMPLEMENTADO E VALIDADO
- **Arquivos**: `ure/app.py` (`delete_project`).
- **Evidência**: exige `X-Confirm-Delete` igual ao nome.
- **Teste**: `test_api.py::test_delete_requires_explicit_confirmation`.
- **Limitação**: a confirmação é um nome conhecido pela pessoa que pode ter sido enviado por script. É uma proteção
  contra erro, não contra abuso.
- **Próxima ação**: nenhuma imediata.

---

## C. Android

### C1. Adaptador Apktool — IMPLEMENTADO, MAS NÃO VALIDADO
- **Arquivos**: `ure/engines.py` (`apktool_decode`, `_invoke`), `ure/tools.py` (`SPECS`, `probe`).
- **Evidência**: comando `apktool d -f -o <dir> <apk>`, sem shell. Saída validada só pela presença de
  `AndroidManifest.xml`, `res/`, `assets/` e `smali*`.
- **Teste**: apenas o caminho "ferramenta ausente" é exercitado (registro `missing`). O sucesso nunca foi executado,
  porque o apktool não está instalado.
- **Limitação**: não se sabe se os argumentos estão corretos para a versão real. Sem a ferramenta, não há como afirmar que
  o Smali e os recursos são produzidos.
- **Próxima ação**: instalar apktool (ou fornecer o `.jar`) e executar contra um APK real.

### C2. Adaptador JADX — IMPLEMENTADO, MAS NÃO VALIDADO
- **Arquivos**: `ure/engines.py` (`jadx_decompile`).
- **Evidência**: comando `jadx -d <dir> -j 2 <apk>`; saída validada pela contagem de `*.java`.
- **Teste**: caminho "ausente" apenas.
- **Limitação**: as opções de linha de comando não foram verificadas contra uma versão real. O JADX roda sobre a JVM, e
  o limite RLIMIT_AS pode impedir a inicialização da JVM dependendo do tamanho de heap (não testado).
- **Próxima ação**: instalar o JADX, validar as opções e testar o limite de memória com a JVM.

### C3. Manifest binário (AXML) — NÃO IMPLEMENTADO
- **Arquivos**: `ure/analysis.py` (linha 134: `has_android_manifest`).
- **Evidência**: busca por AXML, binary XML e pelo identificador 0x00080003 não encontra nada. O código só verifica se o
  arquivo `AndroidManifest.xml` existe na lista de entradas.
- **Teste**: a presença do arquivo é testada com um manifesto sintético de 4 bytes, que não é AXML válido.
- **Limitação**: nome de pacote, `minSdk`, `targetSdk`, componentes exportados e permissões não são extraídos sem o apktool.
  A seção "Manifest" da interface não tem conteúdo real.
- **Próxima ação**: parser de AXML (string pool, tabela de recursos e árvore de elementos) com testes contra
  AXML real; ou usar o apktool/apkanalyzer como fonte única e declarar a dependência.

### C4. Permissões e componentes Android — NÃO IMPLEMENTADO (depende de ferramenta)
- **Arquivos**: `ure/engines.py` (`apkanalyzer_manifest`), `ure/analysis.py`.
- **Evidência**: o único caminho para permissões é o apkanalyzer, que não está instalado. O relatório não tem campo de
  permissões calculado pelo URE.
- **Teste**: ausente.
- **Próxima ação**: depende de C3 ou da instalação do apkanalyzer.

### C5. Extração de DEX — PARCIAL
- **Arquivos**: `ure/analysis.py` (`DEX_TOP`, `dependencies.dex_files`), `ure/identify.py` (cabeçalho `dex\n`).
- **Evidência**: arquivos `classes*.dex` são listados por nome. O conteúdo do DEX (strings, classes, métodos) não é lido.
  A identificação usa só os 4 primeiros bytes.
- **Teste**: listagem com DEX sintético de 100 bytes.
- **Limitação**: nenhuma informação de classes ou métodos sai do URE sem o JADX.
- **Próxima ação**: parser de cabeçalho DEX (contagem de classes, strings e métodos) ou dependência explícita do JADX.

### C6. Recursos, assets e bibliotecas nativas — IMPLEMENTADO E VALIDADO (apenas com APK sintético)
- **Arquivos**: `ure/safezip.py`, `ure/analysis.py` (`_analyze_container`), `ure/app.py` (`tree_artifact`).
- **Evidência**: extração lista assets e recursos; `lib/<abi>/*.so` gera a lista de ABIs; `META-INF/*.RSA|DSA|EC|SF` é
  listado.
- **Teste**: `test_api.py`, `test_regressions.py::test_full_http_flow...` com APK sintético contendo `lib/arm64-v8a`.
- **Limitação**: nenhum APK real foi analisado. A assinatura é apenas detectada pelo nome, não verificada
  criptograficamente.
- **Próxima ação**: testar com APK real de terceiros de origem conhecida (não executar).

### C7. APK real — NÃO VALIDADO
- **Evidência**: nenhum APK real existe neste ambiente. Todos os APKs de teste são arquivos ZIP montados pelos testes.
- **Próxima ação**: obter APKs de teste de fontes que permitam a análise.

---

## D. Windows

### D1. Parser PE (cabeçalhos, seções, entropia, overlay, imports) — IMPLEMENTADO E VALIDADO para PE32; NÃO VALIDADO para PE32+
- **Arquivos**: `ure/pe.py` (`parse_pe`).
- **Evidência**: com `w32.exe` real (PE32, x86, 91.648 bytes), o parser retornou 84 importações de KERNEL32, 6 de USER32 e 3
  de SHLWAPI, confirmado por verificação HTTP. Também analisou um PE32 sintético montado byte a byte, com importação
  `KERNEL32!ExitProcess`, verificada exatamente.
- **Teste**: `test_core.py` (`test_real_pe_identified_and_parsed`, `test_synthetic_pe_parsed_exactly`), `test_api.py`,
  `test_phase2.py::test_real_pe_analysis_runs`.
- **Limitação**: nenhum PE32+ (64 bits) foi testado. O caminho de offsets de `ImageBase` e de importações com
  `ordinal` de 64 bits está implementado mas sem verificação. Overlay foi testado apenas com valor zero.
- **Próxima ação**: obter um PE32+ real (por exemplo, um executável de 64 bits do sistema) e testar overlay não zero.

### D2. Assinatura digital — PARCIAL
- **Arquivos**: `ure/pe.py` (`signed = sec_dir[1] > 0`).
- **Evidência**: apenas verifica se o diretório de segurança tem tamanho. Não valida certificado, cadeia nem hash
  Authenticode.
- **Limitação**: um arquivo pode declarar assinatura com dados inválidos e ser marcado como assinado.
- **Próxima ação**: parser de PKCS#7 e verificação do hash Authenticode, ou remover o rótulo "assinado" e chamá-lo de
  "tem diretório de certificado".

### D3. Timestamp de compilação — PARCIAL
- **Evidência**: o valor é lido e exibido com aviso de que pode ser forjado. Não há validação de plausibilidade.
- **Próxima ação**: manter o aviso; opcionalmente marcar valores futuros ou zero.

### D4. Runtime .NET (CLR) — IMPLEMENTADO, MAS NÃO VALIDADO
- **Arquivos**: `ure/pe.py` (`clr_runtime`, `dirs[14]`), `ure/analysis.py` (`_analyze_pe`).
- **Evidência**: a detecção usa o diretório de dados 14 (COM descriptor). A lógica está presente.
- **Teste**: nenhum assembly .NET de teste existe. O `w32.exe` não é .NET. Não há teste que ative o caminho CLR.
- **Limitação**: a detecção de CLR nunca foi verificada com um assembly real.
- **Próxima ação**: obter um assembly .NET de teste e validar `clr_runtime = true`.

### D5. ILSpy (ilspycmd) — IMPLEMENTADO, MAS NÃO VALIDADO (BLOQUEADO pela ausência da ferramenta)
- **Arquivos**: `ure/engines.py` (`ilspy_decompile`), `ure/tools.py`.
- **Evidência**: comando `ilspycmd -o <dir> <assembly>`; saída validada por contagem de `*.cs`.
- **Teste**: apenas o caminho "ausente". O `ilspycmd` não está instalado, e exige .NET SDK ausente.
- **Próxima ação**: instalar .NET SDK e ilspycmd, com verificação do impacto no disco antes.

### D6. Ghidra (analyzeHeadless) — IMPLEMENTADO, MAS NÃO VALIDADO (BLOQUEADO)
- **Arquivos**: `ure/engines.py` (`ghidra_analyze`).
- **Evidência**: importação e auto-análise. O projeto temporário é apagado por `-deleteProject`, então não há saída
  estruturada.
- **Teste**: apenas caminho "ausente" e `skipped` sem `deep`.
- **Limitação**: o Ghidra exige Java 17+ e é pesado. Com 4 GB e 1 CPU neste ambiente, o uso seria inviável. Não há
  exportação de decompilação; o URE não extrai código do Ghidra.
- **Próxima ação**: instalar em máquina com mais recursos e criar script de pós-análise que exporte funções e strings.

### D7. Extração de código real a partir de PE — NÃO IMPLEMENTADO
- **Evidência**: sem ILSpy ou Ghidra, o URE não gera código. O que existe é metadado (cabeçalhos, seções, nomes de DLLs
  e de funções importadas). Os relatórios descrevem metadados, não código.
- **Próxima ação**: depende de D5 e D6.

### D8. LIEF — NÃO IMPLEMENTADO (detecção apenas)
- **Arquivos**: `ure/tools.py` (`probe` para `lief`).
- **Evidência**: o módulo só verifica se `lief` pode ser importado. Nenhuma análise usa LIEF.
- **Próxima ação**: decidir se o analisador próprio substitui o LIEF (recomendado) e remover a menção ao LIEF como
  motor de análise.

### D9. ELF e Mach-O — PARCIAL
- **Evidência**: ELF tem classe, tipo e arquitetura lidos do cabeçalho (validado com `/usr/bin/ls`). Mach-O só é
  identificado pelo magic. Nenhum dos dois é analisado além disso. Não é possível fazer upload deles pela regra
  atual (somente APK e PE).
- **Próxima ação**: aceitar ELF/Mach-O como artefatos apenas se houver requisito; caso contrário, documentar.

### D10. Compatibilidade com Windows — NÃO VALIDADO
- **Arquivos**: `ure/tools.py` (`os.name == "posix"`), `ure/storage.py` (`safe_join` com separador `/`), `ure/safezip.py`
  (`O_NOFOLLOW` opcional).
- **Evidência**: o código tem ramos para POSIX e não há teste executado em Windows. Caminhos de arquivo usam `Path` e
  `/` em rótulos; links simbólicos no Windows têm semântica diferente.
- **Limitação**: o desktop Windows depende de tudo isso, sem validação.
- **Próxima ação**: rodar a suíte em Windows (BLOQUEADO neste ambiente).

---

## E. Inteligência artificial

### E1. Consentimento para provedor externo — IMPLEMENTADO E VALIDADO (com servidor falso)
- **Arquivos**: `ure/ai.py` (`ask`), `ure/app.py` (`ask_artifact`).
- **Evidência**: sem `consent=true` retorna 403 antes de qualquer envio. O servidor falso não recebeu nenhuma requisição.
- **Teste**: `test_extensions.py::test_consent_required`.
- **Limitação**: o consentimento é por requisição, sem registro persistente nem texto de aviso exibido ao usuário.
  A interface não oferece o provedor externo; só envia `provider` padrão (`ollama`).
- **Próxima ação**: UI com aviso explícito antes de qualquer envio externo; registrar consentimentos.

### E2. Proteção de segredos no contexto — IMPLEMENTADO E VALIDADO (parcialmente)
- **Arquivos**: `ure/ai.py` (`build_context`).
- **Evidência**: o contexto inclui apenas contagens por regra de segredo. O servidor falso recebeu corpo sem `AKIA...`.
- **Teste**: `test_phase4.py::test_context_never_contains_secret_values`, `test_extensions.py` (corpo enviado sem chave).
- **Limitação**: o contexto inclui nomes de arquivos, nomes de DLLs, nomes de classes DEX e indicadores. Se um nome de
  arquivo contiver um segredo, ele é enviado. Não há varredura desses nomes.
- **Próxima ação**: aplicar a mesma varredura de segredos aos nomes antes de montar o contexto.

### E3. Proteção de chave de API — IMPLEMENTADO E VALIDADO
- **Arquivos**: `ure/config.py` (`external_ai_key` com `repr=False`), `ure/ai.py` (`status`, `_post_external`).
- **Evidência**: a chave vem só de `URE_EXTERNAL_AI_KEY`. Não aparece em `status`, em respostas, em cache, nem em mensagens
  de erro (o corpo de erro do provedor não é repassado). Variáveis de ambiente dos motores são filtradas.
- **Teste**: `test_extensions.py` (`test_status_never_exposes_key`, `test_provider_http_error_does_not_leak_key`,
  `test_success_sends_bearer_no_secret_values_and_caches`).
- **Limitação**: a chave fica na memória do processo e aparece em `/proc/<pid>/environ` para usuários com acesso ao processo.
  Isso é um limite do modelo de processo local, não um defeito de código.
- **Próxima ação**: documentar a limitação.

### E4. Cache por hash e versão do modelo — IMPLEMENTADO E VALIDADO (com servidor falso)
- **Arquivos**: `ure/ai.py` (`ask`, chave `sha256` de provedor, modelo, versão, pergunta e contexto), `ure/db.py` (`ai_cache`).
- **Evidência**: segunda pergunta idêntica retorna `cached: true` sem nova chamada.
- **Teste**: `test_phase4.py::test_local_answer_cached_and_budget_enforced`, `test_extensions.py`.
- **Limitação**: o cache não expira. A versão do modelo local vem do `digest` do Ollama; para o provedor externo a versão é
  "não informada", então uma mudança de modelo do lado do provedor não invalida o cache.
- **Próxima ação**: expiração por tempo e invalidação manual.

### E5. Orçamento diário — PARCIAL (não atômico)
- **Arquivos**: `ure/ai.py`, `ure/db.py` (`ai_calls_today`, `ai_increment`).
- **Evidência**: verificação e incremento em operações separadas (ver B7).
- **Teste**: sequencial apenas (`test_local_answer_cached_and_budget_enforced`).
- **Próxima ação**: incremento atômico com verificação na mesma instrução SQL.

### E6. Ollama local — IMPLEMENTADO, MAS NÃO VALIDADO (testado somente com servidor falso)
- **Arquivos**: `ure/ai.py` (`_get_json`, `_post_ollama`, `_model_version`).
- **Evidência**: usa `/api/tags` e `/api/generate` com `stream: false`.
- **Teste**: `test_phase4.py::FakeOllama` (servidor falso que imita as rotas). Nenhum modelo real foi executado.
- **Limitação**: o formato real das respostas do Ollama pode diferir do imitado. Latência e memória com modelo real não
  foram medidas. O servidor falso valida o roteador, não o Ollama.
- **Próxima ação**: instalar Ollama e um modelo pequeno (com verificação de espaço e memória de 8 GB) e repetir os testes.

### E7. Provedor externo compatível com OpenAI — IMPLEMENTADO, MAS NÃO VALIDADO (somente servidor falso)
- **Arquivos**: `ure/ai.py` (`_post_external`), `ure/config.py`.
- **Evidência**: POST para a URL configurada com `Authorization: Bearer` e corpo no formato de chat completions.
- **Teste**: `test_extensions.py::ExternalAiTests`, com servidor falso em loopback que aceita só este formato.
- **Limitação**: nenhum provedor real foi chamado, por falta de rede e de chave. A compatibilidade real não está
  comprovada. A URL precisa ser https, ou http apenas em loopback, o que é verificado por `url_is_allowed`.
- **Próxima ação**: testar com um provedor real somente após autorização explícita, usando uma chave dedicada, e
  com conteúdo que não seja código privado.

### E8. Prompt injection por conteúdo analisado — NÃO TRATADO
- **Arquivos**: `ure/ai.py` (`build_context`, montagem de `prompt`).
- **Evidência**: nomes de arquivos, de classes, de DLLs e de funções importadas são colocados diretamente no prompt, em
  JSON, sem delimitação de dados não confiáveis. As instruções de sistema e os dados ficam no mesmo texto. Um arquivo
  analisado pode conter, em um nome de arquivo ou em uma string de importação, texto que tente alterar a resposta do
  modelo.
- **Teste**: ausente.
- **Limitação**: a instrução "não afirme que o arquivo é malicioso sem evidência" pode ser contornada. As referências
  [E1] a [E4] não são verificadas: o URE não confirma que o texto da resposta corresponde às evidências citadas.
- **Próxima ação**: delimitar dados não confiáveis com marcadores e limite de tamanho por campo; validar que as evidências
  citadas existem; testes com nomes de arquivo hostis.

### E9. Conversa com memória — NÃO IMPLEMENTADO
- **Evidência**: cada pergunta é independente. Não há histórico. O relatório anterior já declarava isso.
- **Próxima ação**: depende de decisão de produto.

---

## F. Interface

### F1. Interface como um todo — IMPLEMENTADO, MAS NÃO VALIDADO EM NAVEGADOR
- **Arquivos**: `apps/web/index.html`, `app.js`, `api.js`, `sse.js`, `format.js`, `style.css`.
- **Evidência**: sintaxe verificada com `node --check`. Módulos puros (`sse.js`, `format.js`) testados com `node --test`.
  A entrega dos arquivos é verificada com HTTP.
- **Teste**: `apps/web/test/*.test.mjs` (4 testes). Nenhum teste de interação, de DOM ou de navegador.
- **Limitação**: o relatório anterior não declara validação em navegador, mas o painel de status fala em "interface
  verificada". Não é verdade. Não há como afirmar que o layout, os cliques, o SSE ou os downloads funcionam.
- **Próxima ação**: teste com navegador headless (Playwright ou equivalente), quando houver ferramenta disponível.

### F2. Upload — IMPLEMENTADO, MAS NÃO VALIDADO EM NAVEGADOR
- **Arquivos**: `app.js` (`uploadZone`), `api.js`.
- **Evidência**: seleção e arrastar-e-soltar chamam o mesmo envio com `X-Filename` codificado.
- **Limitação**: não há barra de progresso do envio (só mensagem em toast). `fetch` não expõe progresso de upload.
- **Próxima ação**: `XMLHttpRequest` ou aviso de tamanho antes do envio.

### F3. Progresso em tempo real — IMPLEMENTADO, MAS NÃO VALIDADO EM NAVEGADOR
- **Arquivos**: `app.js` (`followJob`, `runJob`), `sse.js`.
- **Evidência**: o SSE é consumido por `fetch` com `ReadableStream`. O backend foi validado por HTTP com curl.
- **Teste**: parser SSE testado com node. Ciclo completo com navegador: ausente.
- **Limitação**: não há cancelamento (B5) e não há botão de interrupção.
- **Próxima ação**: depende de B5 e de teste de navegador.

### F4. Árvore de arquivos e visualização — IMPLEMENTADO, MAS NÃO VALIDADO EM NAVEGADOR
- **Arquivos**: `app.js` (`treeCard`), `ure/app.py` (`tree_artifact`, `preview_artifact`).
- **Evidência**: a API retorna as entradas e a prévia (texto ou hex) e foi validada por HTTP. A interface navega por
  `root` e `path`.
- **Limitação**: a árvore não distingue entradas de links e não é atualizada após extração em outra aba.
- **Próxima ação**: teste de navegação com navegador.

### F5. Relatório técnico — IMPLEMENTADO, MAS NÃO VALIDADO EM NAVEGADOR
- **Arquivos**: `app.js` (`reportCard`).
- **Evidência**: renderiza motores, ferramentas, dependências em JSON, indicadores e segredos mascarados.
- **Limitação**: não exibe licenças nem resumo de tamanho do bloco `compliance` gerado pelo backend. Não exibe
  permissões Android porque não existem (C4).
- **Próxima ação**: exibir `compliance` e marcar motores ausentes de forma visível.

### F6. Exportação ZIP pela interface — IMPLEMENTADO, MAS NÃO VALIDADO EM NAVEGADOR
- **Arquivos**: `app.js` (`download`).
- **Evidência**: baixa como Blob e aciona um link temporário. A opção "incluir original" é um checkbox.
- **Limitação**: o relatório anterior descrevia o fluxo como validado; não é.
- **Próxima ação**: teste de navegador.

### F7. Exportação Git local pela interface — NÃO IMPLEMENTADO (somente backend)
- **Arquivos**: `ure/gitexport.py`, `ure/app.py` (`git_export`).
- **Evidência**: busca por `git-export` em `app.js` não retorna nada. O endpoint existe e foi validado por HTTP.
- **Próxima ação**: botão e exibição do resultado.

### F8. Licenças e tamanho pela interface — NÃO IMPLEMENTADO
- **Evidência**: `compliance` é gerado no relatório, mas a interface não o lê.
- **Próxima ação**: exibir na seção de relatório.

### F9. Cancelamento pela interface — NÃO IMPLEMENTADO
- **Depende de B5.**

### F10. Navegação e integração — PARCIAL
- **Evidência**: roteamento por hash. Após extrair ou analisar, a view inteira é recarregada com `route()`, o que descarta
  a prévia aberta e o estado do campo de pergunta da IA. O cartão de IA aparece em todas as artefatos, mas fica
  desabilitado sem relatório (correto, mas sem explicação clara). Erros de carregamento de artefato mostram mensagem
  genérica.
- **Limitação**: não há indicação de carregamento entre trocas de tela.
- **Próxima ação**: atualizar só a seção afetada e exibir estados de carregamento.

### F11. Segurança na renderização — IMPLEMENTADO E VALIDADO por revisão (não por teste automatizado)
- **Arquivos**: `app.js` (`h`, uso de `textContent` e `setAttribute`), `index.html` (CSP).
- **Evidência**: conteúdo de arquivos, nomes e relatórios entra só como `textContent`. Nenhum `innerHTML`. A CSP proíbe
  scripts inline.
- **Teste**: `test_phase5.py` verifica CSP e ausência de `<script>` inline no HTML. Não há teste de XSS no JS.
- **Limitação**: a verificação é por leitura de código.
- **Próxima ação**: teste automatizado que injete nomes com HTML e verifique a árvore do DOM.

### F12. Token na interface — IMPLEMENTADO, MAS NÃO VALIDADO EM NAVEGADOR
- **Arquivos**: `api.js`, `app.js`.
- **Evidência**: o token fica em memória, não em `localStorage`. Cabeçalho `Authorization` em todas as requisições
  (incluindo SSE, por `fetch`).
- **Limitação**: o token é perdido ao recarregar a página.
- **Próxima ação**: decisão de produto.

---

## G. Desktop

### G1. Esqueleto Tauri — PARCIAL / BLOQUEADO (não compila)
- **Arquivos**: `apps/desktop/src-tauri/{Cargo.toml,build.rs,src/main.rs,tauri.conf.json}`, `apps/desktop/README.md`.
- **Evidência**: a estrutura existe, mas o projeto Tauri 2 exige ou depende de:
  - **Ícones**: `src-tauri/icons/` não existe. O build com bundle falha sem eles.
  - **Capabilities**: `src-tauri/capabilities/` não existe. O Tauri 2 usa arquivos de capacidades para permissões de janela
    e de IPC.
  - **Cargo.lock**: não existe; o build não é reproduzível.
  - **Origem da API**: `build.frontendDist` aponta para `../../web`. Ao empacotar, a interface é servida em
    `tauri://localhost` e chama `/api/...` relativo, que não existe nessa origem. Não há `url` configurada na janela.
  - **CSP**: `connect-src` tem a porta 8765 fixa, sem `url` correspondente.
  - **Sidecar**: o backend Python não é empacotado nem iniciado pelo aplicativo. O README admite isso.
- **Teste**: nenhum. Rust e Tauri CLI ausentes.
- **Limitação**: não existe aplicativo Windows funcional. O que existe é um executável de janela vazia.
- **Próxima ação**: decidir a arquitetura (backend como sidecar com porta dinâmica e token, ou Tauri apenas como
  invólucro de um servidor iniciado pelo usuário); criar ícones e capacidades; compilar em Windows.

### G2. Requisitos de compilação — BLOQUEADO
- **Requisitos**: Rust estável com target MSVC (Windows), Microsoft C++ Build Tools, WebView2 (já presente no Windows 10/11),
  Tauri CLI 2.x, e Python 3.11+ para o backend se for sidecar (ou PyInstaller/Nuitka para empacotá-lo).
- **Bloqueio neste ambiente**: sem Rust, sem rede, sem Windows.

### G3. Instalador e assinatura — NÃO IMPLEMENTADO
- **Evidência**: `bundle.active = false`. Não há assinatura de código.
- **Próxima ação**: depende de G1 e de certificado (ação do usuário).

---

## H. Segurança

### H1. Path traversal — IMPLEMENTADO E VALIDADO
- **Arquivos**: `ure/storage.py` (`safe_join`), `ure/safezip.py`, `ure/app.py`.
- **Evidência**: `..`, caminhos absolutos, barras invertidas, byte nulo e links em componentes são recusados. Testado também
  com codificação percentual (`%2e%2e`) e com entradas de ZIP. Estático: `safe_join` é usado por árvore, prévia e
  estáticos.
- **Teste**: `test_core.py::StorageTests`, `test_api.py::ApiSecurityTests`, `test_regressions.py`, HTTP.
- **Limitação**: resíduo de TOCTOU (ver B2).

### H2. Links simbólicos — IMPLEMENTADO E VALIDADO
- **Evidência**: links são ignorados na extração, recusados em `safe_join`, não listados como arquivo na árvore (aparecem
  como `link`), não incluídos na exportação, e não seguidos na varredura de segredos nem na de licenças.
- **Teste**: `test_core.py` (`test_symlink_entry_is_skipped_not_created`, `test_safe_join_blocks_symlink_component`),
  `test_extensions.py::test_size_summary_skips_symlinks`.

### H3. ZIP bomb — PARCIAL (ver B3)
- **Confirmado**: H1 (cabeçalho forjado contorna a razão medida) e H2 (razão agregada não limitada).

### H4. Arquivos malformados — PARCIAL
- **Evidência**: PE truncado, MZ sem PE, ZIP corrompido e assinatura desconhecida são tratados e retornam estado
  `corrupt` ou `unknown`. Verificado com testes e com truncamento de tabela de seções.
- **Limitação**: não há fuzzing. Um ZIP com muitas entradas faz `identify` construir o conjunto de nomes inteiro
  (ver B9). Um PE com `NumberOfSections` grande é limitado a 256, mas não há teste de seções sobrepostas ou de importações
  cíclicas além do limite de 20 mil.
- **Próxima ação**: fuzzing com entradas aleatórias e corpus pequeno; limite de entradas em `identify`.

### H5. Arquivos excessivamente grandes — PARCIAL
- **Evidência**: upload limitado (512 MiB por padrão); extração limitada (2 GiB); varredura de segredos limitada por
  arquivo (2 MiB) e total (200 MiB); exportação sem limite.
- **Limitação**: a exportação e os diretórios de análise não têm cota (ver B1, B8).

### H6. Execução acidental de binários — IMPLEMENTADO, MAS NÃO VALIDADO COMO PROPRIEDADE
- **Evidência**: o URE não chama `exec`, `subprocess` com o arquivo analisado como programa, nem `os.startfile`. Os
  motores recebem o arquivo como argumento de leitura. Verificado por leitura do código e por `grep`.
- **Teste**: nenhum teste verifica a propriedade. Não há teste de regressão que falharia se o código passasse a executar
  o arquivo.
- **Limitação**: os motores (apktool, JADX, ILSpy, Ghidra) são programas que leem entradas hostis. Uma vulnerabilidade no
  parser de um deles pode executar código do atacante com os privilégios do usuário. O limite de memória e o tempo não
  são uma sandbox.
- **Próxima ação**: teste que tente executar um PE de teste e verifique que nada rodou; executar os motores em sandbox
  (container, usuário sem privilégios ou Windows Sandbox).

### H7. Prompt injection por conteúdo analisado — NÃO TRATADO (ver E8)

### H8. Vazamento de chaves e segredos — IMPLEMENTADO E VALIDADO (com limites)
- **Evidência**: chave de IA só por ambiente, mascarada em `repr`, ausente de respostas e logs. Segredos encontrados são
  mascarados em relatório, interface e contexto. Os logs de motores (`reports/logs/*.log`) guardam a saída do motor,
  que pode conter caminhos, mas não foi verificado se contém conteúdo de segredos do arquivo analisado.
- **Teste**: `test_api.py`, `test_phase2.py::test_apk_analysis_end_to_end` (segredo completo não aparece no relatório),
  `test_extensions.py`.
- **Limitação**: a verificação de logs de motores não existe. Um motor pode imprimir trechos do arquivo em erro.
- **Próxima ação**: varredura de segredos também nos logs dos motores, antes de exibir ou exportar.

### H9. Host header e DNS rebinding — NÃO TRATADO (ver B11)

### H10. Timeouts de conexão (slowloris) — NÃO TRATADO (ver B11)

---

## Testes: o que existe e o que falta

| Área | Testes atuais | Falta |
|---|---|---|
| Identificação | 9 casos, incluindo PE e ELF reais | PE32+ real, arquivos fuzzados |
| Extração | Traversal, links, duplicatas, limites, tipos Unix | ZIP bomb adversarial (H1, H2), concorrência |
| PE | PE32 real e sintético | PE32+, .NET, overlay não zero, assinatura |
| Android | APK sintético | APK real, AXML, DEX real, apktool/JADX reais |
| Motores | Limite de tempo e memória com processo Python | Execução real de qualquer motor |
| Jobs | Sucesso, falha, retry, recuperação | Cancelamento, concorrência |
| HTTP | Rotas, 405, 404, 400, traversal, auth | Host, timeout de socket, rebinding |
| IA | Consentimento, cache, orçamento sequencial, servidores falsos | Ollama real, provedor real, concorrência, prompt injection |
| Interface | Parser SSE e formatação (node) | Qualquer teste de DOM ou navegador |
| Segurança de execução | Nenhum | Verificar que o arquivo analisado nunca roda |

Os skips existentes (`skipTest`) só ocorrem quando o recurso real não existe. Neste ambiente, nenhum teste de PE real é
pulado. Não há skip que esconda falha de código.

---

## Lista priorizada dos dez problemas mais importantes

1. **Superfície local exposta por padrão (B11, H9).** Sem validação de `Host` e sem token por padrão, DNS rebinding
   permite que uma página maliciosa leia projetos, relatórios e arquivos extraídos. *Ação*: validar `Host` para loopback
   e exigir token por sessão.

2. **Proteção contra ZIP bomb contornável (B3, H1, H2).** Cabeçalho forjado zera a razão medida; razão agregada não é
   limitada. *Ação*: medir bytes reais lidos do compactado pela posição do fluxo; razão agregada; testes adversariais.

3. **Nenhum motor real foi executado (C1, C2, D5, D6).** Apktool, JADX, ILSpy e Ghidra são adaptadores não validados. As
   afirmações de extração de código e de decompilação não têm evidência. *Ação*: instalar as ferramentas com verificação
   de impacto e de recursos, e executar contra amostras.

4. **Manifest binário e permissões não são decodificados (C3, C4).** O relatório Android não tem informação de manifesto
   sem ferramenta externa. *Ação*: parser de AXML com testes contra arquivo real.

5. **Sem cancelamento, timeout de conexão nem limite de tempo para o trabalho em processo (B5, B9, H10).** Uma análise ou
   uma conexão lenta pode prender recursos indefinidamente. *Ação*: flag de cancelamento, `timeout` no handler,
   limite de tempo nas etapas em processo.

6. **Condições de corrida (B7, E5).** Extração e análise concorrentes podem apagar diretórios em uso e sobrescrever
   `details`; o orçamento de IA pode ser ultrapassado. *Ação*: lock por artefato, atualização atômica, teste de
   concorrência.

7. **Prompt injection por conteúdo analisado (E8, H7).** Nomes de arquivos e de funções vão ao prompt sem delimitação, e
   as referências de evidência não são verificadas. *Ação*: delimitação, limite de tamanho, validação das citações e
   testes com nomes hostis.

8. **Interface nunca validada em navegador e funções ausentes na UI (F1, F7, F8, F9).** O relatório anterior sugeria
   validação que não existe. Exportação Git, licenças e cancelamento não estão na interface. *Ação*: teste com navegador
   headless e inclusão das funções que o backend já oferece.

9. **Desktop não compila e não é uma aplicação funcional (G1, G2, G3).** Faltam ícones, capacidades, lock, sidecar e a
   origem correta da API. *Ação*: decidir a arquitetura e compilar em Windows antes de qualquer afirmação de
   aplicativo Windows.

10. **Cobertura de testes insuficiente nos caminhos de maior risco (seção de testes).** PE32+, .NET, DEX real, fuzzing,
    concorrência, propriedade de não execução e XSS no DOM não têm teste. Os testes atuais são corretos para o que
    cobrem, mas não para o que o relatório anterior sugere. *Ação*: testes de regressão para cada item acima, sem
    enfraquecer os critérios existentes.

---

## Correções necessárias na documentação atual

Os documentos `docs/STATUS.md` e `docs/ARCHITECTURE.md` precisam ser revisados para refletir esta auditoria. Em particular:

- `STATUS.md` lista "Interface web... testes" como implementado e testado; o teste cobre apenas os módulos puros.
- `STATUS.md` lista o Git local e a verificação de licenças como implementados e testados. Os testes existem, mas a
  interface não os expõe.
- `ARCHITECTURE.md` descreve o modelo de segurança com "token opcional" sem mencionar que o padrão é sem autenticação e
  sem validação de `Host`.
- `ARCHITECTURE.md` diz que a varredura tem "limite de 2 MiB por arquivo e 200 MiB no total"; isso é verdade, mas a
  análise não tem limite de tempo nem de CPU.

Essas correções não foram feitas, porque esta etapa é somente de auditoria.

---

## Verificação registrada nesta auditoria

- `git status`: limpo antes da auditoria.
- `main` = `1905f54`, inalterada.
- Suíte Python: 86 testes, todos passando (`OK`).
- Suíte Node: 4 testes, todos passando.
- Experimentos H1 e H2: executados em diretório temporário que foi apagado. Nenhum arquivo do repositório foi alterado.
- Nenhuma ferramenta foi instalada. Nenhuma rede foi usada. Nada foi publicado.
- Este arquivo (`docs/AUDIT.md`) é a única alteração. Ele não foi commitado, para que você decida se deve entrar na `develop`.


---

## Atualização pós-correção (branch `security/correcao-auditoria`)

Esta seção registra o estado após a correção. O diagnóstico acima é mantido como registro histórico.

### Vulnerabilidades corrigidas

| Item | Situação | Evidência de teste |
|---|---|---|
| B3/H1: cabeçalho forjado contorna razão | **Corrigido** na lógica. Razão medida pelos bytes consumidos pelo zlib, sem usar `compress_size` do cabeçalho | `test_security.ZipBombTests` (ZIPs reais forjados); E2E com bomba forjada pela rede (HTTP 413) |
| B3/H2: razão agregada não limitada | **Corrigido**: razão agregada a partir de 8 MiB de saída | `test_aggregate_ratio_across_many_small_entries_is_refused` |
| B11/H9: DNS rebinding e Host não validado | **Corrigido**: Host restrito a loopback e à porta real; Origin restrita | `HostAndOriginTests`; E2E (DNS rebinding em health, projetos e estáticos) |
| B11: token opcional (sem autenticação por padrão) | **Corrigido**: token de sessão aleatório (32 bytes), gravado 0600, obrigatório em /api | `AuthTokenTests`; E2E (sem token, token errado, token na query) |
| B11/H10: sem timeout de socket | **Corrigido**: `socket_timeout_s` (30 s) em cada conexão | `SocketTimeoutTests`; E2E (cliente lento desconectado em ~2 s) |
| H8/erros: detalhes internos em erros | **Corrigido**: 500 genérico; falhas de job com mensagem genérica (exceções não previstas) | `ErrorExposureTests` |
| B7: extração apaga diretório usado por análise | **Corrigido**: lock por artefato; extração/exportação/git/análise são exclusivos | `ConcurrencyTests` |
| B7: exclusão de projeto com trabalho ativo | **Corrigido**: recusada com jobs ativos ou artefato travado | `test_delete_refused_with_active_job_and_with_locked_artifact` |
| B7: merge de `details` sobrescrevia chaves | **Corrigido**: leitura-merge-escrita em seção crítica | `test_details_merge_is_atomic_under_concurrency` |
| E5: orçamento de IA não atômico | **Corrigido**: reserva atômica no SQL | `test_atomic_budget_under_real_thread_contention` (60 threads, exatamente 10 concedidos) |
| B5: sem cancelamento | **Corrigido**: cancelamento cooperativo, encerramento do subprocesso do motor, job na fila nunca executa | `test_cancel_running_job_stops_quickly`, `test_cancel_queued_job_never_runs_it`, `test_external_tool_is_killed_on_cancel` |
| B9: limites de tempo só em motores | **Corrigido** para etapas em processo: Guard em extração, varredura e passos da análise | `TimeLimitTests` |
| E8: prompt injection | **Corrigido na estrutura**: instruções só no papel de sistema; dados em blocos com marcador aleatório por requisição; controles removidos; nomes com padrão de segredo omitidos | `PromptInjectionTests` |
| E8: citações [E1]–[E4] não verificadas | **Corrigido**: citações inexistentes são listadas em `unverified_citations` | `test_citations_are_validated` |
| BUG novo: laço infinito na descompressão (DoS) | **Corrigido**: fim do fluxo tem precedência; limite de iterações | `test_zip_termination` (e suíte completa, que antes travava) |
| BUG novo: fluxo corrompido gerava erro interno | **Corrigido**: `zlib.error` vira rejeição do arquivo | `test_corrupted_deflate_stream_is_rejected_not_crashing` |

### Vulnerabilidades parcialmente corrigidas

- **ZIP bomb (B3/H1)**: a correção elimina a dependência do cabeçalho na razão medida. A exploração com arquivo real **não foi reproduzida** contra a versão antiga: a biblioteca `zipfile` barrou as variantes testadas (sobreposição de entradas e CRC). A demonstração contra a versão antiga existe apenas no nível da lógica (fluxo injetado). Os testes novos falham contra a versão antiga, mas por motivo diferente (`BadZipFile` em vez de `ArchiveLimitError`), o que deve ser lembrado ao interpretá-los.
- **Limites de tempo (B9)**: aplicados a extração, varredura e passos da análise. **Limite de CPU não é aplicado** em trabalho em processo: o Python não oferece cota de CPU por thread sem recursos do SO.
- **Prompt injection (E8)**: a estrutura impede que o conteúdo do arquivo entre no papel de sistema e torna a delimitação verificável. **Se o modelo obedece ou não às instruções de sistema não é garantido pelo URE**, e não foi validado com nenhum modelo real.
- **Erros (H8)**: tracebacks continuam indo para o log do servidor (intencional, para diagnóstico). Mensagens de validação de ZIP ainda citam nomes de entradas do próprio arquivo analisado.

### Vulnerabilidades que continuam abertas

1. **Motores externos não validados**: apktool, JADX, apkanalyzer, ILSpy e Ghidra continuam sem execução real. A sandbox desses motores é só limite de memória e tempo (POSIX), sem isolamento de usuário ou contêiner.
2. **Cota global de disco inexistente**: o limite é por artefato (2 GiB). Exportações em `exports/` não são removidas.
3. **Concorrência de threads não limitada**: `ThreadingHTTPServer` cria uma thread por conexão. Conexões SSE mantêm uma thread por até 30 minutos. Não há limite de conexões nem de taxa.
4. **Envio lento contínuo**: o timeout é por operação de leitura. Um cliente que envia um byte a cada 29 s mantém a conexão aberta durante um upload grande.
5. **Logs de motores não varridos por segredos** (H8). Os logs ficam em `reports/logs/`.
6. **Token em texto simples** em `session.token` (0600 no POSIX). No Windows a permissão não se aplica e não foi verificada.
7. **Processo único**: o lock é em memória. Dois processos servidores sobre o mesmo diretório de dados não são suportados.
8. **Nomes de arquivos e funções ainda aparecem nos relatórios** (não no prompt, que os sanitiza). Isso é o comportamento esperado de um relatório técnico.
9. **Interface não testada em navegador**. As mudanças de token e cancelamento foram verificadas apenas por sintaxe e pelo backend.
10. **Windows não validado**: nenhum teste foi executado nessa plataforma, e os limites de memória não se aplicam nela.

### Testes executados após a correção

- Suíte Python: 130 testes, todos passando.
- Suíte Node: 4 testes, todos passando.
- Teste HTTP ponta a ponta (`apps/backend/scripts/e2e_security.py`): 22 verificações, todas passando, sem tracebacks no log do servidor.
- Reprodução contra a versão antiga (`ca53871`): DNS rebinding e acesso sem token **permitidos** (vulnerável); H2 **aceito** (105 MiB extraídos de 117 KiB); H1 não reproduzido com arquivo real (ver acima).
- Contra a versão corrigida: H2 bloqueado, H1 (lógica e arquivo real) bloqueado, DNS rebinding bloqueado, token obrigatório.
