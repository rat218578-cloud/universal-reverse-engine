# Changelog

## 1.0.0 — 2026-11-22

Primeira versão pública. Integra a RC 1.0.0rc1 e as correções da validação.

### Adicionado
- Arquivo de configuração `ure.env` (modelo em `ure.env.example`), lido a partir do diretório de execução ou de `URE_CONFIG`. Variáveis do ambiente têm precedência.
- Instalador para Linux `scripts/install-linux.sh` (sem root, sem rede, a partir do wheel).
- Guias: `INSTALL.md`, `docs/PRIMEIROS-PASSOS.md`, `docs/SOLUCAO-DE-PROBLEMAS.md`.
- Licença MIT.
- Versão exposta em `/api/v1/health`.

### Corrigido na validação
- Captura de saída de motores limitada a 4 MiB por fluxo (um motor que escrevia sem parar gerava 49 MiB de log).
- Página do projeto sem descrição não mostra mais `null`.
- Mensagem de formato recusado em linguagem clara, sem o termo técnico `unknown`.
- Cliente que desconecta no meio de uma requisição não gera mais traceback no log.
- Porta ocupada gera mensagem orientando `URE_PORT`, sem traceback.
- Versão do Java ignora avisos da JVM.

### Limitações conhecidas
- Nenhum motor de análise externo (apktool, JADX, apkanalyzer, ILSpy, Ghidra) foi executado com ferramenta real. Ausentes são registrados como `missing`.
- Manifesto Android binário (AXML) e permissões não são decodificados. DEX é identificado, não analisado.
- IA: testada apenas com servidores falsos. Não há validação com modelo real.
- Limite de CPU não é aplicado ao trabalho em processo; o limite é de tempo.
- Sem cota global de disco; exportações não são removidas automaticamente.
- Sem limite de conexões simultâneas.
- Logs de motores não são varridos por segredos.
- Um processo servidor por diretório de dados.
- Testado apenas em Linux (Ubuntu, Python 3.12.3). Windows e macOS não foram testados. Python 3.11 não foi testado.
- Interface testada em Chromium; Firefox e WebKit não foram testados.
- Sem aplicativo desktop empacotado e sem imagem Docker.

## 1.0.0rc1 — Release Candidate (2026-11-22)

Primeira versão candidata para lançamento. Base: branch `security/correcao-auditoria`.

### Adicionado
- Pacote instalável (`pip install dist/universal_reverse_engine-1.0.0rc1-py3-none-any.whl`) com o comando `ure-server`.
- Interface web empacotada no wheel. Pode ser apontada para outra pasta com `URE_WEB_DIR`.
- Script `scripts/build_release.py` para gerar wheel, código-fonte e somas SHA-256.
- Teste E2E de segurança que pode apontar para um interpretador externo (`URE_E2E_PYTHON`), permitindo testar o pacote instalado.

### Segurança (correção da auditoria)
- Validação de `Host` e `Origin` em toda requisição (bloqueia DNS rebinding).
- Token de sessão obrigatório em `/api`, gravado em `data/session.token` com permissão 0600.
- Timeout de socket por conexão (30 s por padrão).
- Erros internos com mensagem genérica.
- Razão de compressão medida pelos bytes consumidos, não pelo cabeçalho do ZIP; limite agregado; limite de profundidade.
- Lock por artefato; exclusão de projeto recusada com trabalho ativo; orçamento de IA atômico.
- Cancelamento de jobs (incluindo subprocessos de motores) e limite de tempo em etapas no processo.
- Prompt injection: instruções só no papel de sistema; dados do arquivo em blocos com marcador aleatório; citações validadas.

### Corrigido
- Laço infinito na descompressão de ZIP com bytes após o fim do fluxo (negação de serviço).
- Fluxo DEFLATE corrompido agora é rejeitado como arquivo inválido, em vez de gerar erro interno.
- `HEAD` e `OPTIONS` tratados corretamente; método errado em rota conhecida retorna 405.

### Limitações conhecidas
- Motores externos (apktool, JADX, apkanalyzer, ILSpy, Ghidra) não foram executados com ferramenta real. São adaptadores com status `missing` quando ausentes.
- Manifesto Android binário (AXML) e permissões não são decodificados. DEX não é analisado além do nome e da identificação.
- Limite de CPU não é aplicado ao trabalho executado no processo.
- Sem cota global de disco; exportações não são removidas automaticamente.
- Sem limite de conexões simultâneas nem de taxa de requisições.
- Logs de motores não são varridos por segredos.
- Um processo servidor por diretório de dados.
- Eficácia da defesa contra prompt injection depende do modelo; não validada com modelo real.
- Interface testada apenas por sintaxe e módulos puros; não testada em navegador.
- Testado apenas em Linux com Python 3.12.3. Windows e macOS não foram testados. Python 3.11 declarado mas não testado.
- Sem instaladores de desktop, Docker não construído, Tauri não compilado.

