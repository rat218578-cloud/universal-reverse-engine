# Arquitetura

## Camadas (apps/backend/ure)
- `config.py`: configuração por variáveis `URE_*`; token de sessão aleatório (`load_or_create_token`, 0600).
- `app.py`: API HTTP em `/api/v1`, interface estática e servidor. Ponto de entrada: `server.py`.
- `db.py`: SQLite com lock. Operações atômicas: `patch_artifact` (merge de detalhes) e `reserve_ai_call` (orçamento).
- `storage.py`: layout do artefato e resolução segura de caminhos (`safe_join`).
- `identify.py` e `pe.py`: identificação por assinatura; analisador PE próprio.
- `safezip.py`: extração segura com medição real de bytes (ver abaixo).
- `limits.py`: `Guard` (tempo limite e cancelamento) usado em extração, varredura e análise.
- `jobs.py`: executor de jobs com progresso, cancelamento, limite de tempo e erros sanitizados.
- `tools.py` e `engines.py`: registro e adaptadores de motores externos, com subprocesso cancelável.
- `analysis.py` e `secrets.py`: pipeline de análise com lock por artefato; varredura de segredos.
- `ai.py`: roteador de IA com separação de papéis e validação de citações.
- `compliance.py`, `files.py`, `gitexport.py`: licenças e tamanho, árvore/prévia/exportação ZIP, repositório Git local.

## Controles HTTP (aplicados a toda requisição, nesta ordem)
1. **Host**: somente `127.0.0.1:<porta>`, `localhost:<porta>`, `[::1]:<porta>` e `URE_ALLOWED_HOSTS`. Ausente ou diferente: 403.
   Isso bloqueia DNS rebinding, porque o navegador envia o nome do atacante no cabeçalho Host.
2. **Origin** (quando presente): somente origens locais e `tauri://localhost`. Outras: 403.
3. **Token**: obrigatório em `/api`, exceto `/api/v1/health`. Comparação em tempo constante. Não aceito na query string.
4. **Timeout de socket** (`URE_SOCKET_TIMEOUT_S`, padrão 30 s) em cada conexão.
5. **Erros**: 500 retorna `{"error": "erro interno"}`; traceback só no log do servidor.

Cabeçalhos de resposta: CSP estrita (`default-src 'self'`, `frame-ancestors 'none'`), `X-Frame-Options: DENY`,
`nosniff`, `no-store`.

## Extração segura de ZIP (`safezip.py`)
- Os tamanhos declarados no cabeçalho não são usados para a razão de compressão.
- O arquivo é lido diretamente pelo offset do cabeçalho local; o `zlib` descompacta; os bytes **consumidos** de cada
  entrada (comprimidos) e os **produzidos** (descompactados) são medidos.
- Limites: entradas, bytes totais medidos, razão por entrada (a partir de 1 MiB de saída), razão agregada (a partir de 8 MiB),
  profundidade de caminho (32), nome longo, CRC, fluxo truncado ou corrompido, criptografia, métodos além de STORED e DEFLATE.
- Links e entradas especiais são ignorados. Gravação com `O_EXCL` e `O_NOFOLLOW`.
- Em qualquer falha, o diretório de destino é removido.
- Entradas aninhadas (ZIP dentro de ZIP) não são extraídas recursivamente.

## Concorrência
- Lock por artefato (`App.artifact_lock`). Extração, exportação, exportação Git e análise são exclusivas.
  Rotas HTTP recusam com 409 quando o artefato está ocupado; a análise espera até o limite de tempo.
- Exclusão de projeto: recusada com jobs ativos ou artefatos travados. Um conjunto `_deleting` impede novos jobs
  para o projeto durante a exclusão.
- Orçamento de IA: incremento condicional atômico no SQL. Reserva feita antes da chamada; falha da chamada não devolve a reserva
  (contagem conservadora).
- Escopo: um processo servidor por diretório de dados.

## Jobs e cancelamento
- Cada job tem um `threading.Event`. `cancel` marca jobs na fila como cancelados antes da execução.
- Jobs em execução verificam o evento em cada `Guard.step` e em cada laço de extração e varredura.
- Subprocessos de motores são encerrados quando o evento é acionado ou o tempo acaba.
- Estados: `queued`, `running`, `done`, `failed`, `cancelled`, `interrupted`.

## Inteligência artificial (`ai.py`)
- Instruções só na mensagem de sistema (`system` no Ollama; role `system` no provedor externo).
- Dados do arquivo na mensagem de usuário, em blocos `<<DADOS-NAO-CONFIAVEIS nonce>>...<<FIM-DADOS nonce>>`.
  O nonce tem 64 bits, muda a cada requisição e é desconhecido pelo arquivo analisado.
- Sanitização: caracteres de controle viram espaço; strings limitadas a 300 caracteres; strings com padrão de segredo são omitidas.
- Citações: `[E1]`–`[E4]` válidas em `citations`; outras em `unverified_citations`. Eco do nonce é sinalizado.
- Provedor externo: exige `consent=true`, URL `https` (ou `http` só em loopback), chave somente por variável de ambiente.
- Cache por hash de versão do prompt, provedor, modelo, versão do modelo, pergunta e evidências (sem o nonce).

## Modelo de segurança do arquivo analisado
- O arquivo nunca é executado. Motores apenas leem o arquivo e rodam com limite de memória (POSIX) e de tempo.
- Não há sandbox de sistema para os motores. Vulnerabilidades nos próprios motores não são contidas.
- Segredos são mascarados em relatório, interface e contexto de IA. Logs de motores não são varridos.

## Limites de recurso
- Upload: 512 MiB (configurável), com recusa antecipada por `Content-Length`.
- Extração: 2 GiB medidos por artefato. Sem cota global de disco.
- Análise: tempo limite de 900 s por job (`URE_JOB_TIMEOUT_S`), verificado em etapas em processo e em subprocessos.
- CPU: não limitada em trabalho em processo.
- Varredura de segredos: 2 MiB por arquivo, 200 MiB no total.
- Conexões: sem limite de quantidade nem de taxa.
