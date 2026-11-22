# Instalação — Universal Reverse Engine 1.0.0

Análise local de APK e EXE/DLL: upload, identificação, análise estática, extração, visualização e exportação em ZIP.
A interface roda no navegador, servida pelo próprio programa, somente na sua máquina.

## Plataformas

| Plataforma | Situação |
|---|---|
| Linux (Ubuntu 24.04, Python 3.12.3) | **Testado**: instalação, execução, interface e fluxos completos |
| Windows 10/11 | **Não testado.** Os passos abaixo são os padrões do Python; não foram executados |
| macOS | **Não testado** |

## Requisitos
- Python 3.11 ou superior.
- Nenhuma dependência de runtime. O programa usa apenas a biblioteca padrão do Python.
- Opcional: ferramentas externas (apktool, JADX, apkanalyzer, ILSpy, Ghidra) e Ollama. Sem elas, as etapas correspondentes aparecem como `missing` no relatório, com o motivo.
- Opcional, para testes da interface: Node.js 22 ou superior.

## Obter o pacote
Baixe da página de releases do repositório (quando publicado):
- `universal_reverse_engine-1.0.0-py3-none-any.whl` (pacote instalável)
- `universal-reverse-engine-1.0.0-source.tar.gz` (código-fonte)
- `SHA256SUMS` (conferência de integridade)

Confira a integridade antes de instalar:
```
sha256sum -c SHA256SUMS
```

## Linux

Instalação com o script (cria um ambiente virtual em `~/.local/share/universal-reverse-engine` e um link em `~/.local/bin`):
```
chmod +x install-linux.sh
./install-linux.sh universal_reverse_engine-1.0.0-py3-none-any.whl
```

Ou manualmente:
```
python3 -m venv ~/ure-venv
~/ure-venv/bin/pip install universal_reverse_engine-1.0.0-py3-none-any.whl
~/ure-venv/bin/ure-server
```

Execução:
```
ure-server
```
Abra `http://127.0.0.1:8765` no navegador. Veja `docs/PRIMEIROS-PASSOS.md`.

## Windows (NÃO TESTADO)

Os comandos abaixo seguem a documentação padrão do Python. **Não foram executados neste projeto.**
```
py -3.12 -m venv %USERPROFILE%\ure-venv
%USERPROFILE%\ure-venv\Scripts\pip install universal_reverse_engine-1.0.0-py3-none-any.whl
%USERPROFILE%\ure-venv\Scripts\ure-server
```
Limitações conhecidas no Windows: o limite de memória dos motores externos não é aplicado (depende de POSIX);
permissões do arquivo de token não se aplicam da mesma forma.

### Aplicativo desktop para Windows (em desenvolvimento)
O aplicativo desktop inicia este mesmo backend e abre a interface nele. Compilação, requisitos e
limitações estão em `apps/desktop/README.md`. Neste repositório **não há instalador Windows gerado**: o
build Windows depende de Windows com Rust, Visual Studio Build Tools e tauri-cli, e não foi executado aqui.

## Configuração

O servidor lê `ure.env` do diretório onde é executado (ou o arquivo indicado em `URE_CONFIG`). Copie o modelo:
```
cp ure.env.example ure.env
```
Variáveis já definidas no ambiente têm precedência. Tabela completa em `ure.env.example`.

## Token de acesso

Na primeira execução, o servidor cria `data/session.token` (permissão 0600 em Linux). A interface pede esse token.
Use-o também na API:
```
curl -H "Authorization: Bearer $(cat data/session.token)" http://127.0.0.1:8765/api/v1/projects
```
Para usar um token fixo, defina `URE_TOKEN` no ambiente. Não compartilhe o token.

## Testes (para quem instala a partir do código-fonte)
```
cd apps/backend
python3 -m unittest discover -s tests -t . -v      # 144 testes
python3 scripts/e2e_security.py                    # 22 verificações com servidor real
cd ../web && npm test                              # 4 testes
```
Teste de navegador (requer Playwright e Chromium): `python3 scripts/browser_e2e.py`.

## Desinstalação
Linux: `rm -rf ~/.local/share/universal-reverse-engine ~/.local/bin/ure-server`.
Os dados analisados ficam em `data/` do diretório de execução; apague-os separadamente se quiser.

## Problemas
Veja `docs/SOLUCAO-DE-PROBLEMAS.md`.
