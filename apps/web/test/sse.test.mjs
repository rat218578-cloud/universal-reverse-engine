import { test } from "node:test";
import assert from "node:assert/strict";
import { createSSEParser } from "../sse.js";

test("parser junta eventos quebrados em chunks arbitrários", () => {
  const events = [];
  const p = createSSEParser((e) => events.push(e));
  p.push("event: progress\ndata: {\"sta");
  p.push("tus\":\"running\"}\n\nevent: end\nda");
  p.push("ta: {}\n\n");
  assert.deepEqual(events, [
    { event: "progress", data: "{\"status\":\"running\"}" },
    { event: "end", data: "{}" },
  ]);
});

test("aceita CRLF e ignora blocos sem dados", () => {
  const events = [];
  const p = createSSEParser((e) => events.push(e));
  p.push("event: progress\r\ndata: 1\r\n\r\n: comentário\n\n");
  assert.deepEqual(events, [{ event: "progress", data: "1" }]);
});
