// Parser puro de Server-Sent Events (sem dependências). Aceita chunks parciais e CRLF.
export function createSSEParser(onEvent) {
  let buffer = "";
  return {
    push(chunk) {
      buffer += chunk.replace(/\r\n/g, "\n");
      let sep;
      while ((sep = buffer.indexOf("\n\n")) !== -1) {
        const block = buffer.slice(0, sep);
        buffer = buffer.slice(sep + 2);
        let event = "message";
        const data = [];
        for (const line of block.split("\n")) {
          if (line.startsWith("event:")) event = line.slice(6).trim();
          else if (line.startsWith("data:")) data.push(line.slice(5).replace(/^ /, ""));
        }
        if (data.length) onEvent({ event, data: data.join("\n") });
      }
    },
  };
}
