# Universal Reverse Engine (URE)

Universal Reverse Engine — AI-assisted reverse engineering for APK and EXE files.

Plataforma local para análise de APK e EXE/DLL: upload com validação pelo conteúdo, identificação de formato,
análise estática, extração segura, visualização de arquivos, relatórios técnicos e exportação em ZIP.
Roda no seu computador e é acessada pelo navegador.

**Versão 1.0.0.** Testada em Linux. Leia as limitações antes de usar: `CHANGELOG.md` (seção 1.0.0) e `docs/VALIDATION-1.0.0rc1.md`.

## Instalação rápida (Linux)
```
./scripts/install-linux.sh dist/universal_reverse_engine-1.0.0-py3-none-any.whl
ure-server
```
Abra `http://127.0.0.1:8765`. Detalhes: `INSTALL.md`. Primeiros passos: `docs/PRIMEIROS-PASSOS.md`. Problemas: `docs/SOLUCAO-DE-PROBLEMAS.md`.

## Documentação
- `INSTALL.md`: instalação, configuração, token, testes.
- `docs/PRIMEIROS-PASSOS.md`: uso passo a passo.
- `docs/SOLUCAO-DE-PROBLEMAS.md`: erros comuns.
- `docs/ARCHITECTURE.md`: arquitetura e modelo de segurança.
- `docs/STATUS.md`: o que é implementado, testado e não testado.
- `docs/AUDIT.md` e `docs/VALIDATION-1.0.0rc1.md`: auditoria e validação.
- `CHANGELOG.md`: histórico de versões.

## Licença
MIT (`LICENSE`). Nenhuma dependência de runtime; ferramentas externas têm suas próprias licenças e não são distribuídas aqui.

## Estrutura
- `apps/backend`: servidor (Python, biblioteca padrão), testes e scripts de validação.
- `apps/web`: interface (HTML, CSS, JavaScript sem build).
- `scripts/`: geração de artefatos e instalador.
- `.github/workflows/ci.yml`: CI (configurado; não executado em remoto).

## Aviso
Analise somente arquivos sobre os quais você tem direito. O programa não executa o arquivo enviado, mas as ferramentas externas leem conteúdo potencialmente hostil.
