# Universal Reverse Engine (URE)

Plataforma local de engenharia reversa para APK e EXE/DLL: upload seguro, identificação real
de formato, extração segura, análise estática, exportação e relatórios.

## Status
Consulte `docs/STATUS.md` para o que está implementado, testado, parcial ou ausente.

## Execução (modo local básico, sem Docker, sem banco externo, sem IA)
    cd apps/backend
    python3 -m ure.server          # http://127.0.0.1:8765
    python3 -m unittest discover -s tests -v

Requisitos: Python 3.11+. Nenhuma dependência externa é necessária.

## Estrutura
- `apps/backend/ure`  núcleo (config, db, identify, pe, safezip, storage, jobs, tools, analysis, api)
- `apps/web`          interface web estática servida pelo backend
- `apps/backend/tests` testes unitários, de integração e de segurança
- `docs/`             status e arquitetura
