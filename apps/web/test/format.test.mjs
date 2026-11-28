import { test } from "node:test";
import assert from "node:assert/strict";
import { formatBytes, kindLabel, parentPath, joinPath } from "../format.js";

test("formatBytes escala unidades", () => {
  assert.equal(formatBytes(0), "0 B");
  assert.equal(formatBytes(1536), "1.5 KB");
  assert.equal(formatBytes(5 * 1024 * 1024), "5.0 MB");
  assert.equal(formatBytes(-1), "—");
});

test("rótulos de tipo e caminhos", () => {
  assert.equal(kindLabel("pe"), "Executável PE (EXE/DLL)");
  assert.equal(kindLabel("xyz"), "xyz");
  assert.equal(joinPath("a/b", "c"), "a/b/c");
  assert.equal(parentPath("a/b/c"), "a/b");
  assert.equal(parentPath("a"), "");
});

test("andamento do envio remoto mostra estado e motivo sem segredos", async () => {
  const { remoteJobLabel } = await import("../format.js");
  assert.equal(remoteJobLabel({ status: "queued" }), "na fila");
  assert.equal(remoteJobLabel({ status: "running", message: "servidor: analisando" }),
    "enviando e analisando no servidor (servidor: analisando)");
  assert.equal(remoteJobLabel({ status: "done", error: null }), "concluído");
  assert.equal(remoteJobLabel({ status: "done", error: "relatório indisponível" }),
    "concluído com avisos: relatório indisponível");
  assert.equal(remoteJobLabel({ status: "failed", error: "servidor recusou a operação (401)" }),
    "falhou: servidor recusou a operação (401)");
});
