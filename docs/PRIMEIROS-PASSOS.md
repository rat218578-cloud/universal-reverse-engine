# Primeiros passos

1. **Inicie o servidor** no diretório onde quer guardar os dados:
   ```
   ure-server
   ```
   Ele informa o endereço (padrão `http://127.0.0.1:8765`) e onde está o token.

2. **Abra o endereço no navegador.** A página pedirá o token.

3. **Copie o token** de `data/session.token` e cole no campo **Token**, no canto superior direito. Pressione Tab. O indicador deve mostrar `online`.

4. **Crie um projeto** com um nome. Um projeto agrupa os arquivos de uma análise.

5. **Envie um arquivo**: clique na área tracejada ou arraste um APK, EXE ou DLL para ela. O programa identifica o tipo pelo conteúdo, não pela extensão. Arquivos que não são APK nem PE são recusados.

6. **Analise**: na página do arquivo, clique em **Analisar**. A barra mostra o progresso. Ao final, o **Relatório técnico** aparece com:
   - integridade (SHA-256 conferido);
   - motores externos e seu status (`ok`, `missing`, `failed`, `timeout`);
   - dependências (classes DEX, bibliotecas nativas, DLLs importadas);
   - indicadores estáticos (não são prova de malícia);
   - segredos encontrados, sempre mascarados.

7. **Extraia** um APK com **Extrair com segurança** (somente APK, JAR e ZIP). Depois use a **Árvore de arquivos** para navegar. Clique em um arquivo para ver a prévia (texto, ou hexadecimal para binários).

8. **Exporte** com **Exportar ZIP**. O arquivo contém `MANIFEST.json` com o SHA-256 de cada item. O arquivo original só entra se você marcar **incluir arquivo original**.

Dica: o botão **Cancelar** aparece durante um processamento.

**Aviso:** analise somente arquivos que você tem direito de analisar. O programa não executa o arquivo enviado,
mas as ferramentas externas leem conteúdo potencialmente hostil. Em amostras desconhecidas, use uma máquina isolada.
