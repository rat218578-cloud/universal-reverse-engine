# Universal Reverse Engine (URE)

Plataforma local de engenharia reversa para APK e EXE/DLL: upload seguro, identificação real de
formato, extração segura, análise estática, relatórios e exportação. Backend em Python (biblioteca
padrão) e interface web sem build. Sem dependências externas para o modo local básico.

- Status detalhado, testes e limitações: [`docs/STATUS.md`](docs/STATUS.md)
- Arquitetura e modelo de segurança: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

## Execução rápida
```
cd apps/backend
python3 -m ure.server          # http://127.0.0.1:8765
python3 -m unittest discover -s tests -t . -v
cd ../web && npm test          # testes puros da interface (Node 22+)
```

## Estrutura
- `apps/backend/ure`: núcleo do backend
- `apps/backend/tests`: testes unitários, de integração e de segurança
- `apps/web`: interface web estática (HTML/CSS/JS)
- `docs/`: status e arquitetura
- `.github/workflows/ci.yml`: CI (configurado, ainda não executado em remoto)

## Aviso
O uso destina-se a análise de software de que você tem direito de analisar. O sistema nunca executa
os arquivos enviados, mas as ferramentas que ele chama leem conteúdo potencialmente hostil; use
em ambiente isolado quando analisar amostras desconhecidas.
