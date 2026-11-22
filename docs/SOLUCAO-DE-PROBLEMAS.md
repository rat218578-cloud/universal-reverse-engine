# Solução de problemas

## "Não foi possível abrir 127.0.0.1:8765 ... Address already in use"
Outra aplicação usa a porta. Escolha outra: `URE_PORT=8766 ure-server`, ou em `ure.env`. Para descobrir quem usa a porta, use `ss -ltnp | grep 8765` (Linux).

## A página mostra "token necessário"
O token está errado ou não foi informado. Leia `data/session.token` no diretório de execução (ou em `URE_DATA_DIR`) e cole-o no campo Token. Se você mudou `URE_DATA_DIR`, o arquivo está no novo diretório.

## A página mostra "offline"
O servidor não está rodando, ou o navegador acessa outro endereço. Confirme que o terminal do `ure-server` está aberto e use exatamente o endereço informado por ele.

## "Host não permitido" (HTTP 403)
Você acessou o servidor por um nome que não é `127.0.0.1`, `localhost` ou `[::1]`. Isso é uma proteção contra DNS rebinding. Se precisar de outro nome (ex.: em contêiner), adicione-o em `URE_ALLOWED_HOSTS`.

## "formato não aceito" ao enviar um arquivo
O conteúdo não é um APK nem um executável PE. Confira o arquivo. Um arquivo renomeado para `.exe` é recusado de propósito. Formatos ELF, Mach-O, JAR e DEX isolado não são aceitos nesta versão.

## "arquivo excede o limite de 512 MB"
Aumente `URE_MAX_UPLOAD_MB`. O servidor recusa antes de ler o arquivo inteiro.

## Extração recusada: "razão de compressão" ou "limite"
O arquivo parece uma bomba de ZIP (muito pequeno compactado, muito grande descompactado) ou excede o limite de entradas, tamanho ou profundidade. É uma proteção: o artefato fica marcado como `rejected`.

## "artefato em uso por outro processamento" (HTTP 409)
Outra extração, exportação ou análise do mesmo arquivo está rodando. Aguarde terminar e tente de novo.

## "há processamentos ativos neste projeto" ao excluir
Cancele os jobs ativos (botão Cancelar) ou aguarde o fim, e então exclua.

## Análise demora ou termina com "tempo limite excedido"
O limite padrão é 900 s por job. Aumente `URE_JOB_TIMEOUT_S` se o arquivo for grande. Análises são feitas uma por vez por padrão.

## Relatório mostra motores como `missing`
A ferramenta não está instalada ou não está no PATH. É esperado se você não instalou o motor. Para apontá-la: `URE_APKTOOL=/caminho/apktool`, e assim por diante. Nenhum resultado é simulado para ferramenta ausente.

## Relatório mostra `failed` ou `timeout` num motor
Veja o log em `reports/logs/<motor>.log` dentro da pasta do artefato (em `data/projects/...`). O log é limitado a 4 MiB por fluxo.

## "Ollama indisponível" na pergunta à IA
A IA é opcional e vem desligada. Para ligar: `URE_AI_ENABLED=1` e um servidor Ollama em `127.0.0.1:11434` com o modelo indicado em `URE_OLLAMA_MODEL`. Sem isso, o restante do programa funciona normalmente.

## Pergunta à IA responde "execute a análise antes"
A pergunta usa o relatório. Analise o arquivo primeiro.

## Instalação falha com "Python 3.11 ou superior"
Use `PYTHON=/caminho/python3.12 ./install-linux.sh ...`.

## Ver os logs do servidor
A saída do `ure-server` no terminal mostra erros internos (sem detalhes sensíveis na página). Mantenha o terminal aberto ao reproduzir o problema.

## Reportar um problema
Inclua: versão (`ure-server` mostra o endereço; `/api/v1/health` mostra a versão), sistema operacional, o passo que falhou e o texto da mensagem. Não envie `data/session.token` nem arquivos analisados privados.
