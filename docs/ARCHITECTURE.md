# Arquitetura

## Camadas (apps/backend/ure)
- `config.py`: configuração por variáveis `URE_*`; recusa bind externo sem token.
- `db.py`: SQLite (biblioteca padrão), uma conexão com lock, WAL, chaves estrangeiras.
- `storage.py`: layout do artefato (`original`, `extracted`, `decompiled`, `reports`, `exports`) e resolução segura de caminhos.
- `identify.py` e `pe.py`: identificação por assinatura; analisador PE próprio.
- `safezip.py`: extração segura de ZIP/APK/JAR.
- `files.py`: árvore, prévia e exportação ZIP com manifesto.
- `tools.py` e `engines.py`: registro e adaptadores dos motores externos; execução com limites.
- `jobs.py`: executor de jobs persistidos (progresso, falhas, nova tentativa, recuperação).
- `analysis.py` e `secrets.py`: pipeline de análise e varredura de segredos.
- `ai.py`: roteador de IA opcional.
- `app.py` e `server.py`: API HTTP (`/api/v1`), interface estática e servidor.

## Fluxo de um artefato
1. Upload: o corpo é gravado em streaming em `original/.upload.part`, com SHA-256 calculado durante a escrita. A identificação ocorre no arquivo gravado. Formato não aceito é removido.
2. Aceito: o arquivo é renomeado para `original/<nome>`, marcado como somente leitura e registrado no SQLite.
3. Análise (job): verifica o SHA-256 contra o registro; PE é analisado diretamente; APK/JAR/ZIP é extraído com segurança; motores disponíveis rodam como processos separados com tempo e memória limitados; segredos são varridos; `reports/analysis.json` é gravado.
4. Interface e API leem apenas o que está em disco dentro do diretório do artefato.

## Modelo de segurança
- O arquivo analisado **nunca é executado**. Ferramentas apenas leem ou decompilam.
- Nenhum dado sai da máquina sem consentimento explícito; a IA externa não está implementada.
- Traversal, links simbólicos e ZIP bomb são bloqueados em extração, leitura e exportação.
- Segredos são mascarados em relatórios, interface e contexto de IA.
- Token opcional; a API recusa o bind fora de loopback sem token.
- Respostas trazem `Content-Security-Policy` estrita, `nosniff` e `Cache-Control: no-store`.
- Exclusão de projeto exige confirmação digitando o nome.
- Nenhum cabeçalho de erro expõe traceback; erros internos são registrados apenas no log do servidor.

## Consumo de memória
- Upload e hash em streaming (1 MiB por vez).
- Análise de PE com `mmap`, sem carregar o arquivo inteiro.
- Entropia calculada sobre no máximo 1 MiB por seção.
- Varredura de segredos limitada a 2 MiB por arquivo e 200 MiB no total.
- Um worker de job por padrão (`URE_JOB_WORKERS=1`) para caber em 8 GB.
