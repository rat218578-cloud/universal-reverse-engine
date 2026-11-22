# Status do Universal Reverse Engine

Última verificação local: 59 testes Python (unittest) e 4 testes Node (node --test), todos passando.
O servidor foi executado em HTTP real com um PE real e o fluxo completo foi verificado com curl.

## Fases

| Fase | Escopo | Situação |
|---|---|---|
| 0 | Estrutura do monorepo, configuração, documentação inicial, CI | Concluída (CI configurado, não executado no GitHub) |
| 1 | Projetos, upload, identificação real, SHA-256, extração segura, árvore, prévia, exportação ZIP | Concluída e testada |
| 2 | Jobs persistidos, progresso SSE, registro de ferramentas, adaptadores, limites de tempo e memória | Concluída; motores externos não instalados neste ambiente |
| 3 | Análise PE/APK/JAR, dependências, indicadores, varredura de segredos, relatórios | Concluída e testada |
| 4 | IA opcional: Ollama local, consentimento, cache, orçamento | Concluída; Ollama real não testado (ver limitações) |
| 5 | Interface web (HTML/CSS/JS sem build) servida pelo backend | Concluída; testes unitários do JS e checagem de sintaxe, sem navegador |
| 6 | Documentação, CI, verificação final | Concluída |

Desktop (Tauri), Docker, criação de repositório privado no GitHub e commits automatizados
**não foram concluídos**, pelos motivos listados em "Limitações".

## Funcionalidades realmente implementadas e testadas
- Upload de APK e EXE/DLL com limite de tamanho (413) e identificação pelo conteúdo (415 para formato não aceito).
- Original gravado somente leitura; SHA-256 calculado durante a escrita e reverificado antes de cada análise.
- Identificação real por assinatura: APK, JAR, ZIP, PE, ELF, Mach-O, DEX, corrompidos.
- Analisador PE próprio (biblioteca padrão): arquitetura, subsistema, seções com entropia, importações (lidas do arquivo real), overlay, assinatura, runtime CLR.
- Extração segura: traversal, caminhos absolutos, byte nulo, nomes duplicados, links simbólicos (ignorados), ZIP bomb (razão declarada e medida), limites de entradas e de bytes.
- Árvore e prévia de arquivos sem seguir links; bloqueio de traversal em todas as rotas.
- Exportação ZIP com MANIFEST.json (SHA-256 por arquivo); original incluído somente com `include_original=1`.
- Jobs em thread pool com progresso persistido; falhas capturadas na fronteira do job; nova tentativa só para jobs falhos ou interrompidos; jobs interrompidos por reinício são marcados como `interrupted`.
- Progresso em tempo real via Server-Sent Events.
- Registro de ferramentas com detecção real (PATH ou variável `URE_<FERRAMENTA>`), versão e status `available`/`missing`.
- Execução de motores com tempo limite e limite de memória virtual (RLIMIT_AS, POSIX), sem shell.
- Varredura de segredos com regras conhecidas; valores sempre mascarados, inclusive no relatório e no contexto da IA.
- Autenticação por token opcional (`URE_TOKEN`); bind fora de loopback recusado sem token.
- Exclusão de projeto exige digitar o nome (`X-Confirm-Delete`).
- IA opcional, desligada por padrão; consentimento obrigatório para provedores externos; cache por hash de (modelo, versão, pergunta, contexto); orçamento diário.

## Ferramentas e versões neste ambiente
| Ferramenta | Situação | Observação |
|---|---|---|
| Python | 3.12.3 | sem dependências externas |
| Node.js | 22.23.5 | só para testes da interface |
| Java | 21.0.13 (detectado) | requisito de JADX, apktool e ILSpy |
| apktool | ausente | sem rede para instalar; adaptador pronto |
| JADX | ausente | sem rede; adaptador pronto |
| apkanalyzer (Android SDK) | ausente | adaptador pronto |
| ILSpy (ilspycmd) | ausente | adaptador pronto |
| Ghidra (analyzeHeadless) | ausente | adaptador pronto |
| LIEF | ausente | não usado: o analisador PE próprio cobre a triagem |
| Docker, Ollama, GitHub CLI, Rust/Tauri | ausentes | |

Quando uma ferramenta está ausente, o relatório registra `"status": "missing"` com o motivo.
Nenhum resultado de ferramenta ausente é simulado.

## Testes
- `apps/backend`: `python3 -m unittest discover -s tests -t . -v`
  - identificação (PE real `w32.exe`, ELF real `/usr/bin/ls`, PE sintético, ZIP, JAR, corrompidos)
  - extração segura (traversal, symlink, duplicata, limites, bomba com razão declarada e medida)
  - caminhos e identificadores (traversal, symlink em componente, ids inválidos)
  - API HTTP: fluxo completo, upload recusado (415/413), exclusão com confirmação, autenticação por token
  - motores e jobs: limite real de tempo, limite real de memória, análise de APK e PE, SSE, integridade adulterada, nova tentativa, recuperação após reinício
  - IA: desligada por padrão, consentimento, Ollama indisponível, cache, orçamento, modelo ausente
  - entrega estática da interface, CSP e traversal estático
- `apps/web`: `npm test` (parser SSE e formatação)

Os testes que usam arquivos sintéticos (APK, PE sintético) validam a lógica, não a compatibilidade
com ferramentas reais. O único PE real testado é `w32.exe` (launcher do pip). Não há APK nem DEX reais
disponíveis neste ambiente.

## Como executar
```
cd apps/backend
python3 -m ure.server                 # http://127.0.0.1:8765
python3 -m unittest discover -s tests -t . -v

# opcionais
URE_TOKEN=um-segredo-longo python3 -m ure.server     # exige token nas rotas /api
URE_AI_ENABLED=1 URE_OLLAMA_MODEL=llama3.2 python3 -m ure.server   # requer Ollama em 127.0.0.1:11434
URE_APKTOOL=/caminho/apktool URE_JADX=/caminho/jadx python3 -m ure.server
```
Abra `http://127.0.0.1:8765` no navegador.

## Limitações conhecidas
1. **Motores externos não validados contra as ferramentas reais.** Apktool, JADX, apkanalyzer, ILSpy e Ghidra não estão instalados aqui e não há rede para baixá-los. Os adaptadores e o registro de status estão implementados, mas o caminho de sucesso (decompilação real) não foi executado.
2. **Sem APK ou DEX reais para teste.** A validação de APK usa estruturas sintéticas. O manifesto binário (AXML) não é decodificado pelo URE; sem apktool ou apkanalyzer, as permissões não são extraídas.
3. **Ghidra** é executado apenas em análise profunda (`deep=true`); a saída detalhada fica no log, sem exportação de decompilação.
4. **Limite de memória** via RLIMIT_AS só existe em POSIX. No Windows não há limite aplicado, e o relatório informa `memory_limit_applied: false`. Não há limite de CPU separado; o tempo limite cobre o caso.
5. **Ollama real não testado.** O roteador foi testado contra um servidor falso em loopback que imita as rotas `/api/tags` e `/api/generate`. Provedores externos **não estão implementados** (retornam 501).
6. **Interface não exercitada em navegador.** Foram verificados sintaxe, módulos puros e a entrega dos arquivos. Não houve teste de interação real.
7. **Desktop (Tauri) não construído.** Não há Rust nem rede. A interface web é a única superfície entregue.
8. **Docker não entregue.** Sem Docker disponível neste ambiente, não há Dockerfile testado.
9. **CI configurado, não executado.** `.github/workflows/ci.yml` existe, mas só roda após push para um remoto.
10. **Sem repositório no GitHub.** Não há `gh` nem rede. O projeto é local.
11. **Autenticação é um único token**, sem usuários nem sessões. Adequado para uso local.
12. **Sem criação de repositórios, commits automatizados ou publicação**, conforme a política de não publicar sem confirmação.
13. **Varredura de segredos** usa regras de padrão conhecido; não substitui ferramenta dedicada e pode ter falsos positivos e negativos.
14. **Indicadores de importação** (ex.: `CreateRemoteThread`) são indicadores estáticos e não comprovam comportamento malicioso.

## Próximos passos
1. Instalar apktool, JADX e apkanalyzer (ou fornecer os binários) e rodar a análise de um APK real.
2. Testar a interface em navegador real (ex.: Playwright) com um fluxo de envio, análise e exportação.
3. Validar o servidor Ollama real com um modelo local e medir latência e uso de memória.
4. Criar um remoto privado no GitHub e executar o CI.
5. Empacotar o desktop com Tauri 2 apontando para o backend local, com verificação de integridade do binário.
6. Adicionar Dockerfile e testá-lo em uma máquina com Docker.
