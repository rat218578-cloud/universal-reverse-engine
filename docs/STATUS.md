# Status do Universal Reverse Engine — 1.0.0rc1 (Release Candidate)

Branch: `release/1.0.0` (a partir de `security/correcao-auditoria`). `main` intacta em `1905f54`. `develop` em `92cf9c1`.
Instalação e execução: `INSTALL.md`. Histórico de mudanças: `CHANGELOG.md`.

Verificação do candidato: **130 testes Python**, **4 testes Node**, **22 verificações E2E** com servidor real (fonte e wheel
instalado), **18 chamadas da interface** coerentes com as rotas da API. Testado apenas em Linux, Python 3.12.3.

**Status de lançamento:** é um candidato, não uma versão de produção. Motores externos não foram executados com ferramenta
real; a interface não foi testada em navegador; Windows e macOS não foram testados. A lista completa está em "Limitações
conhecidas" no `CHANGELOG.md` e em `docs/AUDIT.md`.

## Segurança após a correção da auditoria

Corrigido e testado: validação de Host e Origin (DNS rebinding); token de sessão obrigatório em /api; timeout de socket;
erros genéricos; medição real de bytes em ZIP, com razão por entrada e agregada, limite de profundidade e limpeza após
falha; lock por artefato; exclusão recusada com trabalho ativo; orçamento de IA atômico; cancelamento cooperativo; limite
de tempo nas etapas em processo; delimitação de dados não confiáveis no prompt; validação das citações [E1]–[E4].

Parcial: limite de CPU não aplicado em trabalho em processo; efeito da separação de instruções sobre o modelo não garantido.

Aberto: motores externos sem execução real; sem cota global de disco; sem limite de conexões; logs de motores sem varredura
de segredos; Windows não testado; interface não testada em navegador. Detalhes em `docs/AUDIT.md`.

## Implementado e testado
- Upload de APK e EXE/DLL com limite de tamanho (413), formato validado pelo conteúdo (415), SHA-256 em streaming, original somente leitura.
- Identificação por assinatura: APK, JAR, ZIP, PE, ELF, Mach-O, DEX, corrompidos.
- Extração segura com medição real de bytes, traversal, links, duplicatas, tipos Unix, criptografia, métodos não suportados, CRC.
- Árvore, prévia (texto e hex) e exportação ZIP com MANIFEST.json.
- Analisador PE próprio validado com `w32.exe` real (PE32): 84 importações de KERNEL32, 6 de USER32, 3 de SHLWAPI.
- Jobs com progresso (SSE), cancelamento, limite de tempo, nova tentativa para falhos/cancelados/interrompidos, recuperação após reinício.
- Varredura de segredos com valores mascarados.
- Exportação para repositório Git local, sem remoto.
- Verificação de licenças e tamanho (indicativa).
- Medição: servidor com análise de PE real, 26,6 MB de pico de RSS (medição anterior à correção; não refeita).

## Implementado, não validado com ferramenta real
- apktool, JADX, apkanalyzer, ILSpy, Ghidra: adaptadores com status `missing`. Nenhum foi executado com sucesso.
- LIEF: apenas detecção; não é usado.
- Ollama: testado contra servidor falso em loopback.
- Provedor OpenAI-compatível: testado contra servidor falso em loopback.
- Dockerfile: não construído (Docker ausente).
- Esqueleto Tauri em `apps/desktop`: não compilado (Rust ausente).
- CI em `.github/workflows/ci.yml`: não executado (sem remoto).

## Parcial
- Dependências Android: DEX, bibliotecas nativas, ABIs, assinaturas e JARs embutidos. Sem permissões: o AXML binário não é decodificado.
- PE: PE32+ não testado com amostra real; assinatura apenas por existência de diretório de certificado.
- ELF e Mach-O: só identificação.
- Ghidra: importação e auto-análise, sem saída estruturada.

## Não implementado
- Chat com memória entre perguntas.
- Repositório no GitHub, push, publicação e commits automatizados em remoto.
- Usuários e sessões (só token único).
- Análise de Mach-O e ELF.
- Desktop empacotado e assinado.

## Bloqueado por falta de rede ou ferramentas
- Instalação de apktool, JADX, apkanalyzer, ILSpy, Ghidra, LIEF, Ollama e modelos.
- Docker, Rust/Tauri, GitHub CLI, navegador headless, APK e DEX reais.

## Como executar
```
cd apps/backend
python3 -m ure.server            # http://127.0.0.1:8765; token em data/session.token
python3 -m unittest discover -s tests -t . -v
python3 scripts/e2e_security.py  # ponta a ponta com servidor real
cd ../web && npm test
```
O token deve ser enviado no cabeçalho `Authorization: Bearer <token>` nas rotas /api (exceto /api/v1/health).
A interface pede o token no campo do topo.
