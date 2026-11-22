# Instalação e execução — Universal Reverse Engine 1.0.0rc1

## Requisitos
- Linux (testado em Ubuntu 24.04 com Python 3.12.3). Outros sistemas não foram testados.
- Python 3.11 ou superior (declarado; testado apenas em 3.12).
- Git, somente se você quiser exportar para repositório Git local.
- Node.js 22+, somente para executar os testes da interface.
- Nenhuma dependência externa para o modo básico.
- Opcional: apktool, JADX, apkanalyzer, ILSpy, Ghidra e Ollama. Sem eles, as etapas correspondentes ficam como "ausentes" no relatório.

## Instalar a partir do wheel
```
python3 -m venv ~/ure-venv
~/ure-venv/bin/pip install dist/universal_reverse_engine-1.0.0rc1-py3-none-any.whl
~/ure-venv/bin/ure-server
```

## Executar a partir do código-fonte
```
cd apps/backend
python3 -m ure.server
```

## Acessar
1. Abra `http://127.0.0.1:8765` no navegador.
2. Leia o token em `data/session.token` (ou no caminho de `URE_DATA_DIR`). Em modo instalado, o diretório de dados é o diretório em que o comando foi executado, salvo `URE_DATA_DIR`.
3. Cole o token no campo "Token" do topo da página.

Para usar a API diretamente:
```
curl -H "Authorization: Bearer $(cat data/session.token)" http://127.0.0.1:8765/api/v1/projects
```

## Variáveis de ambiente principais
| Variável | Padrão | Função |
|---|---|---|
| `URE_DATA_DIR` | `./data` | Banco, artefatos e token |
| `URE_HOST` / `URE_PORT` | `127.0.0.1` / `8765` | Endereço de escuta |
| `URE_TOKEN` | gerado | Token fixo (substitui o arquivo) |
| `URE_ALLOWED_HOSTS` | vazio | Nomes de Host adicionais, separados por vírgula |
| `URE_WEB_DIR` | empacotada | Pasta alternativa da interface |
| `URE_MAX_UPLOAD_MB` | 512 | Tamanho máximo de upload |
| `URE_MAX_EXTRACT_MB` | 2048 | Tamanho máximo extraído por artefato |
| `URE_JOB_TIMEOUT_S` | 900 | Tempo limite por job |
| `URE_SOCKET_TIMEOUT_S` | 30 | Timeout de socket |
| `URE_AI_ENABLED` | 0 | `1` liga a IA opcional |
| `URE_OLLAMA_MODEL` | `llama3.2` | Modelo local (Ollama em 127.0.0.1:11434) |
| `URE_EXTERNAL_AI_URL` / `URE_EXTERNAL_AI_KEY` | vazio | Provedor externo (exige `consent=true` em cada requisição) |

Ferramentas externas podem ser apontadas com `URE_APKTOOL`, `URE_JADX`, `URE_APKANALYZER`, `URE_ILSPYCMD`, `URE_GHIDRA`.

## Testes
```
cd apps/backend
python3 -m unittest discover -s tests -t . -v      # 130 testes
python3 scripts/e2e_security.py                    # 22 verificações com servidor real
cd ../web && npm test                              # 4 testes
```

## Gerar os artefatos
```
python3 scripts/build_release.py
```
Gera em `dist/`: o wheel, o código-fonte (`*-source.tar.gz`, a partir do HEAD), `SHA256SUMS` e `BUILDINFO.txt`.

## Limitações
Consulte `CHANGELOG.md` e `docs/AUDIT.md`. Em particular: os motores externos não foram executados com ferramenta real,
e a plataforma testada é apenas Linux.
