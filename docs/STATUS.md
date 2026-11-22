# Status do Universal Reverse Engine

Verificação local mais recente: **86 testes Python** (unittest) e **4 testes Node** (node --test), todos passando.
Teste HTTP completo executado contra o servidor real, com o PE real `w32.exe` e um APK sintético.

## 1. Implementado e testado
- Upload de APK e EXE/DLL: limite de tamanho (413), formato validado pelo conteúdo (415), SHA-256 em streaming, original somente leitura.
- Identificação por assinatura: APK, JAR, ZIP, PE, ELF, Mach-O, DEX, corrompidos.
- Tipos Unix de ZIP (`S_IFMT`): regular aceito; FIFO, dispositivo e link ignorados.
- Extração segura: traversal, caminhos absolutos, byte nulo, duplicatas, links, limites de entradas e bytes.
- ZIP bomb: checagem da razão **declarada** e da razão **medida** durante a escrita (testadas com fluxo injetado).
- Árvore, prévia (texto e hex), bloqueio de traversal e de links em todas as rotas de arquivo.
- Exportação ZIP com MANIFEST.json; original só com `include_original=1`.
- Rotas HTTP: página inicial em GET e HEAD (200); 405 em JSON para métodos errados, inclusive em rotas conhecidas e OPTIONS; 404 para rotas inexistentes; 400 para IDs inválidos.
- Analisador PE próprio (biblioteca padrão), validado com `w32.exe` real: 84 importações de KERNEL32, 6 de USER32, 3 de SHLWAPI.
- Jobs persistidos com progresso (SSE), nova tentativa só para falhos/interrompidos, recuperação após reinício.
- Varredura de segredos com valores mascarados (nenhum valor completo em relatório, interface ou contexto de IA).
- Autenticação por token opcional; bind fora de loopback exige token.
- Exclusão de projeto exige digitar o nome.
- Verificação de licenças por texto e resumo de tamanho (indicativo, não é parecer jurídico).
- Exportação para repositório Git **local** com um commit por fonte; sem remoto, nenhum push.
- Interface web sem build: painel, projetos, envio, progresso, relatório, árvore, prévia, extração, exportação. Módulos puros testados com node.
- Medição real: servidor com análise de PE em **26,6 MB** de pico de RSS.

## 2. Implementado, mas não testado com ferramenta real
- **apktool**: adaptador e parsing de saída. Ferramenta ausente; registrada como `missing`.
- **JADX**: adaptador e contagem de `.java`. Ausente.
- **apkanalyzer**: adaptador, saída em `reports/`. Ausente.
- **ILSpy (ilspycmd)**: adaptador para assemblies .NET, acionado quando o PE tem runtime CLR. Ausente.
- **Ghidra analyzeHeadless**: adaptador em análise profunda (`deep=true`); saída só em log. Ausente.
- **LIEF**: apenas detecção. O analisador PE próprio é o que está em uso.
- **Adaptador de IA externa (OpenAI-compatível)**: testado contra servidor falso em loopback, não contra um provedor real.
- **Ollama**: testado contra servidor falso que imita `/api/tags` e `/api/generate`. Sem modelo real.
- **Dockerfile**: escrito, **não construído**. Docker ausente.
- **Esqueleto Tauri (apps/desktop)**: escrito, **não compilado**. Rust ausente.
- **CI (.github/workflows/ci.yml)**: escrito, **não executado**. Não há remoto.

## 3. Parcial
- **Dependências**: DEX, bibliotecas nativas, ABIs, assinaturas e JARs embutidos para APK; DLLs importadas para PE. Permissões do manifesto não são extraídas, porque o AXML binário não é decodificado pelo URE.
- **Análise de código e arquitetura**: só indicadores estáticos e contagens. Não há grafo de chamadas nem análise de arquitetura.
- **Ghidra**: executa importação e auto-análise, sem exportar resultados estruturados.
- **Interface**: sem teste em navegador real; só sintaxe, módulos puros e entrega dos arquivos.
- **Limite de memória**: RLIMIT_AS só em POSIX. Sem limite de CPU separado; o tempo limite cobre o caso.
- **Repositório Git**: local apenas. Não há criação de repositório no GitHub nem commits automatizados em remoto.

## 4. Não implementado
- Chat com memória entre perguntas. Cada pergunta é independente, com evidências E1–E4.
- Criação de repositórios privados no GitHub, push e publicação.
- Gerenciamento de usuários e sessões. Só há um token.
- Suporte a Mach-O e ELF na análise (são identificados, não analisados).
- Desktop empacotado para Windows.
- Auto-atualização, assinatura de binários e instaladores.

## 5. Bloqueado por falta de rede ou ferramentas
- Instalação de apktool, JADX, apkanalyzer, ILSpy, Ghidra, LIEF, Ollama e modelos locais.
- Docker (build e execução do Dockerfile).
- Rust e Tauri (build do desktop).
- GitHub CLI e acesso ao GitHub (repositório privado e CI remoto).
- Navegador headless para testes de interface.
- APK e DEX reais: nenhum existe neste ambiente. Os testes de APK usam estruturas sintéticas.

## Testes sintéticos vs. reais
| Teste | Tipo de arquivo |
|---|---|
| PE `w32.exe` (análise, upload, export, HTTP) | **real** (launcher do pip, presente no sistema) |
| ELF `/usr/bin/ls` (identificação) | **real** |
| PE mínimo com importação de `KERNEL32!ExitProcess` | sintético, montado byte a byte |
| APK, JAR, ZIPs com traversal, symlink, duplicata, bomba | sintéticos |
| Fluxo HTTP de APK (upload, extração, árvore, prévia, export, git) | sintético |
| Servidor Ollama e provedor OpenAI-compatível | **test doubles** em loopback |

Os `skipTest` existentes só disparam quando o recurso real não existe. Neste ambiente, o PE real está presente e
nenhum teste de PE é pulado.

## Como executar
```
cd apps/backend
python3 -m ure.server                                  # http://127.0.0.1:8765
python3 -m unittest discover -s tests -t . -v
cd ../web && npm test
```
Variáveis úteis: `URE_TOKEN`, `URE_AI_ENABLED=1`, `URE_OLLAMA_MODEL`, `URE_EXTERNAL_AI_URL` + `URE_EXTERNAL_AI_KEY`
(só com `consent=true` por requisição), `URE_APKTOOL`, `URE_JADX`, `URE_APKANALYZER`, `URE_ILSPYCMD`, `URE_GHIDRA`.

## Próximos passos
1. Instalar apktool, JADX e apkanalyzer e validar a análise de um APK real.
2. Validar Ollama com um modelo local real e medir latência e memória.
3. Testar a interface em navegador real.
4. Construir o Dockerfile e o desktop em máquina com as ferramentas.
5. Criar remoto privado e executar o CI, somente após confirmação.
