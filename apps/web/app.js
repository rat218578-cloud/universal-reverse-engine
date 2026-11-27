import { api, setToken, ApiErr } from "./api.js";
import { createSSEParser } from "./sse.js";
import { formatBytes, kindLabel, shortHash, joinPath, parentPath } from "./format.js";

const view = document.querySelector("#app");
const EXTRACTABLE = ["apk", "jar", "zip"];
const ROOTS = ["original", "extracted", "decompiled", "reports"];

function h(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (value === undefined || value === null || value === false) continue;
    if (key === "class") node.className = value;
    else if (key.startsWith("on") && typeof value === "function") node.addEventListener(key.slice(2), value);
    else node.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

function toast(message, isError = false) {
  const t = document.querySelector("#toast");
  t.textContent = message;
  t.className = isError ? "show err" : "show";
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => (t.className = ""), 4500);
}

const errText = (e) => (e instanceof ApiErr ? `${e.message} (HTTP ${e.status})` : e.message || String(e));
const fail = (e) => toast(errText(e), true);
const show = (...nodes) => view.replaceChildren(...nodes.filter((n) => n !== null && n !== undefined && n !== false));

// ----- saúde e token -----------------------------------------------------
async function refreshHealth() {
  // /api/v1/health é público; a verificação de token usa uma rota autenticada.
  const pill = document.querySelector("#health");
  try {
    const info = await api("GET", "/api/v1/health");
    await api("GET", "/api/v1/projects");
    pill.textContent = `online · v${info.version}`;
    pill.className = "pill ok";
  } catch (e) {
    pill.textContent = e.status === 401 ? "token necessário" : "offline";
    pill.className = "pill err";
  }
}
document.querySelector("#token").addEventListener("change", (e) => {
  setToken(e.target.value.trim());
  refreshHealth();
  route();
});

// ----- projetos ----------------------------------------------------------
async function homeView() {
  const { projects } = await api("GET", "/api/v1/projects");
  const name = h("input", { type: "text", placeholder: "Nome do projeto", maxlength: "120", required: true });
  const desc = h("input", { type: "text", placeholder: "Descrição (opcional)", maxlength: "2000" });
  const create = h("form", {
    class: "row",
    onsubmit: async (e) => {
      e.preventDefault();
      try {
        const p = await api("POST", "/api/v1/projects", { body: { name: name.value, description: desc.value } });
        location.hash = `#/p/${p.id}`;
      } catch (err) {
        fail(err);
      }
    },
  }, name, desc, h("button", { type: "submit" }, "Criar projeto"));
  const rows = projects.map((p) =>
    h("tr", {},
      h("td", {}, h("a", { href: `#/p/${p.id}` }, p.name), h("div", { class: "muted" }, p.description)),
      h("td", { class: "muted" }, p.created_at),
      h("td", {}, h("button", { class: "danger", onclick: () => removeProject(p) }, "Excluir")),
    ),
  );
  show(
    h("h2", {}, "Projetos"),
    h("div", { class: "card" }, h("h3", {}, "Novo projeto"), create),
    h("div", { class: "card" },
      projects.length
        ? h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Nome"), h("th", {}, "Criado em"), h("th", {}, ""))),
            h("tbody", {}, rows))
        : h("p", { class: "muted" }, "Nenhum projeto ainda. Crie um para enviar um APK ou EXE.")),
  );
}

async function removeProject(p) {
  const typed = window.prompt(`Exclusão permanente de "${p.name}" e de todos os seus artefatos.\nDigite o nome do projeto para confirmar:`);
  if (typed === null) return;
  try {
    await api("DELETE", `/api/v1/projects/${p.id}`, { headers: { "X-Confirm-Delete": encodeURIComponent(typed) } });
    toast("Projeto excluído.");
    route();
  } catch (e) {
    fail(e);
  }
}

async function projectView(pid) {
  const project = await api("GET", `/api/v1/projects/${pid}`);
  const { artifacts } = await api("GET", `/api/v1/projects/${pid}/artifacts`);
  const rows = artifacts.map((a) =>
    h("tr", {},
      h("td", {}, h("a", { href: `#/p/${pid}/a/${a.id}` }, a.filename)),
      h("td", {}, kindLabel(a.kind)),
      h("td", {}, a.status),
      h("td", { class: "mono" }, shortHash(a.sha256)),
      h("td", {}, formatBytes(a.size)),
    ),
  );
  show(
    h("p", {}, h("a", { href: "#/" }, "← Projetos")),
    h("h2", {}, project.name),
    project.description ? h("p", { class: "muted" }, project.description) : null,
    h("div", { class: "card" }, h("h3", {}, "Enviar arquivo"), uploadZone(pid)),
    h("div", { class: "card" }, h("h3", {}, "Artefatos"),
      artifacts.length
        ? h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Arquivo"), h("th", {}, "Tipo"),
            h("th", {}, "Status"), h("th", {}, "SHA-256"), h("th", {}, "Tamanho"))), h("tbody", {}, rows))
        : h("p", { class: "muted" }, "Nenhum artefato enviado.")),
  );
}

function uploadZone(pid) {
  const input = h("input", { type: "file", accept: ".apk,.exe,.dll,.sys,.scr", class: "hidden" });
  const zone = h("div", { class: "drop", tabindex: "0", role: "button" },
    "Arraste um APK ou EXE/DLL aqui, ou clique para escolher.", input);
  const send = async (file) => {
    toast(`Enviando ${file.name} (${formatBytes(file.size)})…`);
    try {
      const art = await api("POST", `/api/v1/projects/${pid}/artifacts`, {
        body: file,
        headers: { "X-Filename": encodeURIComponent(file.name) },
      });
      toast("Arquivo aceito e identificado pelo conteúdo.");
      location.hash = `#/p/${pid}/a/${art.id}`;
    } catch (e) {
      fail(e);
    }
  };
  zone.addEventListener("click", () => input.click());
  zone.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") input.click(); });
  zone.addEventListener("dragover", (e) => { e.preventDefault(); zone.classList.add("over"); });
  zone.addEventListener("dragleave", () => zone.classList.remove("over"));
  zone.addEventListener("drop", (e) => {
    e.preventDefault();
    zone.classList.remove("over");
    if (e.dataTransfer.files[0]) send(e.dataTransfer.files[0]);
  });
  input.addEventListener("change", () => { if (input.files[0]) send(input.files[0]); });
  return zone;
}

// ----- artefato ----------------------------------------------------------
async function artifactView(pid, aid) {
  const art = await api("GET", `/api/v1/projects/${pid}/artifacts/${aid}`);
  let report = null;
  try {
    report = await api("GET", `/api/v1/projects/${pid}/artifacts/${aid}/report`);
  } catch {
    report = null;
  }
  const jobBox = h("div", { class: "card" }, h("h3", {}, "Processamento"), h("p", { class: "muted" }, "Nenhum processamento em andamento."));
  const details = h("div", { class: "card" }, h("h3", {}, "Identificação"),
    h("table", {},
      h("tr", {}, h("th", {}, "Tipo real"), h("td", {}, kindLabel(art.kind))),
      h("tr", {}, h("th", {}, "Status"), h("td", {}, art.status)),
      h("tr", {}, h("th", {}, "Tamanho"), h("td", {}, formatBytes(art.size))),
      h("tr", {}, h("th", {}, "SHA-256"), h("td", { class: "mono" }, art.sha256)),
      h("tr", {}, h("th", {}, "Extensão"),
        h("td", {}, art.details.extension_mismatch ? h("span", { class: "pill warn" }, "não confere com o conteúdo") : "compatível")),
    ),
  );
  show(
    h("p", {}, h("a", { href: `#/p/${pid}` }, "← Projeto")),
    h("h2", {}, art.filename),
    details,
    actionsCard(pid, art, jobBox),
    jobBox,
    report ? reportCard(report) : h("div", { class: "card" }, h("p", { class: "muted" }, "Relatório ainda não gerado. Execute a análise.")),
    treeCard(pid, aid),
    await aiCard(pid, aid, report),
  );
}

function actionsCard(pid, art, jobBox) {
  const deep = h("input", { type: "checkbox", id: "deep" });
  const withOriginal = h("input", { type: "checkbox", id: "withOriginal" });
  const run = (label, path, body) => runJob(jobBox, label, path, body, pid, art.id);
  return h("div", { class: "card" }, h("h3", {}, "Ações"),
    h("div", { class: "row" },
      EXTRACTABLE.includes(art.kind)
        ? h("button", { class: "secondary", onclick: () => extract(pid, art.id) }, "Extrair com segurança")
        : null,
      h("button", { onclick: () => run("Analisando", `/api/v1/projects/${pid}/artifacts/${art.id}/analyze`, { deep: deep.checked }) }, "Analisar"),
      h("label", { class: "muted" }, deep, " análise profunda (Ghidra, se instalado)"),
    ),
    h("div", { class: "row", style: "margin-top:10px" },
      h("button", { class: "secondary", onclick: () => download(pid, art, withOriginal.checked) }, "Exportar ZIP"),
      h("label", { class: "muted" }, withOriginal, " incluir arquivo original")),
  );
}

async function extract(pid, aid) {
  try {
    await api("POST", `/api/v1/projects/${pid}/artifacts/${aid}/extract`);
    toast("Extração concluída.");
    route();
  } catch (e) {
    fail(e);
  }
}

async function download(pid, art, includeOriginal) {
  try {
    const res = await api("GET", `/api/v1/projects/${pid}/artifacts/${art.id}/export?include_original=${includeOriginal ? 1 : 0}`, { raw: true });
    const url = URL.createObjectURL(await res.blob());
    const a = h("a", { href: url, download: `${art.filename.replace(/\.[^.]+$/, "")}-export.zip` });
    document.body.append(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
  } catch (e) {
    fail(e);
  }
}

async function runJob(box, label, path, body, pid, aid) {
  const bar = h("span", { style: "width:0%" });
  const msg = h("p", { class: "muted" }, `${label}…`);
  let jobId = null;
  const cancel = h("button", { class: "danger", onclick: async () => {
    if (!jobId) return;
    cancel.disabled = true;
    try { await api("POST", `/api/v1/jobs/${jobId}/cancel`); msg.textContent = "Cancelamento solicitado…"; }
    catch (e) { fail(e); cancel.disabled = false; }
  } }, "Cancelar");
  box.replaceChildren(h("h3", {}, "Processamento"), msg, h("div", { class: "bar" }, bar), h("div", { class: "row" }, cancel));
  try {
    const job = await api("POST", path, { body });
    jobId = job.id;
    const final = await followJob(job.id, (state) => {
      bar.style.width = `${Math.round((state.progress || 0) * 100)}%`;
      msg.textContent = state.message || label;
    });
    if (final?.status === "done") {
      toast("Concluído.");
      route();
    } else if (final?.status === "cancelled") {
      msg.textContent = "Processamento cancelado.";
    } else {
      msg.textContent = `Falhou: ${final?.error || "erro desconhecido"}`;
      msg.className = "err";
    }
  } catch (e) {
    msg.textContent = errText(e);
    msg.className = "err";
  }
}

async function followJob(jid, onState) {
  const res = await api("GET", `/api/v1/jobs/${jid}/events`, { raw: true });
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let last = null;
  const parser = createSSEParser((ev) => {
    if (ev.event === "progress") {
      last = JSON.parse(ev.data);
      onState(last);
    }
  });
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    parser.push(decoder.decode(value, { stream: true }));
  }
  return last;
}

function reportCard(r) {
  const engines = Object.entries(r.engines || {}).map(([key, e]) =>
    h("tr", {}, h("td", {}, key),
      h("td", {}, h("span", { class: `pill ${e.status === "ok" ? "ok" : e.status === "missing" ? "warn" : e.status === "skipped" ? "" : "err"}` }, e.status)),
      h("td", { class: "muted" }, e.reason || e.log || "")));
  const tools = (r.tools || []).map((t) =>
    h("tr", {}, h("td", {}, t.key), h("td", {}, t.status), h("td", { class: "muted" }, t.version || "")));
  const findings = (r.secrets?.findings || []).map((f) =>
    h("tr", {}, h("td", { class: "mono" }, f.file), h("td", {}, f.rule), h("td", { class: "mono" }, f.preview)));
  const indicators = (r.indicators || []).map((i) => h("li", {}, `${i.value} — ${i.note}`));
  return h("div", { class: "card" }, h("h3", {}, "Relatório técnico"),
    h("p", {}, "Integridade: ", h("span", { class: r.integrity === "ok" ? "pill ok" : "pill err" }, r.integrity)),
    h("h3", { style: "margin-top:14px" }, "Motores"),
    h("table", {}, h("tbody", {}, engines.length ? engines : h("tr", {}, h("td", {}, "Nenhum motor executado")))),
    h("h3", { style: "margin-top:14px" }, "Ferramentas detectadas"),
    h("table", {}, h("tbody", {}, tools)),
    h("h3", { style: "margin-top:14px" }, "Dependências"),
    h("pre", { class: "preview" }, JSON.stringify(r.dependencies || {}, null, 2)),
    h("h3", { style: "margin-top:14px" }, "Indicadores estáticos"),
    indicators.length ? h("ul", {}, indicators) : h("p", { class: "muted" }, "Nenhum indicador."),
    h("h3", { style: "margin-top:14px" }, `Segredos (${(r.secrets?.findings || []).length}, valores mascarados)`),
    findings.length ? h("table", {}, h("tbody", {}, findings)) : h("p", { class: "muted" }, "Nenhum achado."),
  );
}

function treeCard(pid, aid) {
  let root = "original";
  let path = "";
  const crumb = h("p", { class: "mono muted" });
  const list = h("ul", { class: "tree" });
  const preview = h("pre", { class: "preview hidden" });
  const select = h("select", { onchange: (e) => { root = e.target.value; path = ""; load().catch(fail); } },
    ...ROOTS.map((r) => h("option", { value: r }, r)));
  async function load() {
    preview.className = "preview hidden";
    crumb.textContent = `${root}/${path}`;
    const data = await api("GET", `/api/v1/projects/${pid}/artifacts/${aid}/tree?root=${root}&path=${encodeURIComponent(path)}`);
    const items = [];
    if (path) items.push(h("li", {}, h("button", { class: "link", onclick: () => { path = parentPath(path); load().catch(fail); } }, "..")));
    for (const entry of data.entries) {
      const label = entry.type === "dir" ? `📁 ${entry.name}` : `${entry.name} · ${formatBytes(entry.size)}`;
      items.push(h("li", {}, h("button", { class: "link", onclick: () => open(entry) }, label)));
    }
    list.replaceChildren(...items);
    if (!items.length) list.replaceChildren(h("li", { class: "muted" }, "Vazio ou não extraído ainda."));
  }
  async function open(entry) {
    if (entry.type === "dir") {
      path = joinPath(path, entry.name);
      return load().catch(fail);
    }
    const rel = joinPath(path, entry.name);
    const p = await api("GET", `/api/v1/projects/${pid}/artifacts/${aid}/file?root=${root}&path=${encodeURIComponent(rel)}`);
    preview.textContent = (p.truncated ? "[prévia truncada]\n" : "") + p.content;
    preview.className = "preview";
  }
  load().catch(fail);
  return h("div", { class: "card" }, h("h3", {}, "Árvore de arquivos"), select, crumb, list, preview);
}

async function aiCard(pid, aid, report) {
  const status = await api("GET", "/api/v1/ai/status").catch(() => null);
  const head = h("h3", {}, "Pergunte sobre o relatório (IA opcional)");
  if (!status || !status.enabled) {
    return h("div", { class: "card" }, head,
      h("p", { class: "muted" }, "Desativada. Para usar, inicie o servidor com URE_AI_ENABLED=1 e um modelo local no Ollama. Nenhum dado sai da máquina."));
  }
  if (!status.ollama_reachable) {
    return h("div", { class: "card" }, head, h("p", { class: "muted" }, "Ollama não alcançável em loopback."));
  }
  const q = h("input", { type: "text", placeholder: "Ex.: quais dependências chamam atenção?", maxlength: "2000" });
  const out = h("pre", { class: "preview hidden" });
  const askBtn = h("button", {
    disabled: !report,
    onclick: async () => {
      askBtn.disabled = true;
      out.className = "preview";
      out.textContent = "Consultando o modelo local…";
      try {
        const r = await api("POST", `/api/v1/projects/${pid}/artifacts/${aid}/ask`, { body: { question: q.value } });
        out.textContent = `${r.answer.text}\n\n— modelo ${r.answer.model} · ${r.cached ? "resposta em cache" : "nova resposta"} · evidências ${r.answer.evidence.join(", ")}`;
      } catch (e) {
        out.textContent = errText(e);
      } finally {
        askBtn.disabled = !report;
      }
    },
  }, "Perguntar");
  return h("div", { class: "card" }, head, h("div", { class: "row" }, q, askBtn), out,
    report ? null : h("p", { class: "muted" }, "Execute a análise antes de perguntar."));
}

// ----- ferramentas -------------------------------------------------------
// Estado vindo do servidor (sondagem real e teste de execução). Nada é exibido como disponível sem isso.
async function toolsView() {
  const [{ tools }, ai] = await Promise.all([api("GET", "/api/v1/tools"), api("GET", "/api/v1/ai/status")]);
  const pill = (ok, text) => h("span", { class: `pill ${ok ? "ok" : "warn"}` }, text);
  const rowFor = (t) => {
    const result = h("div", { class: "muted" });
    const testBtn = h("button", {
      class: "secondary",
      onclick: async () => {
        testBtn.disabled = true;
        result.textContent = "executando o teste...";
        try {
          const r = await api("POST", `/api/v1/tools/${t.key}/test`, { body: {} });
          result.replaceChildren(
            pill(r.ok, r.ok ? "teste ok" : "teste falhou"),
            h("div", { class: "mono" }, (r.detail || "").slice(0, 300) || "(sem saída)"),
          );
        } catch (err) {
          result.textContent = `erro ao testar: ${err.message}`;
        } finally {
          testBtn.disabled = false;
        }
      },
    }, "Testar");
    const observation = t.status === "available"
      ? (t.pending && t.pending.length ? `dependências ausentes: ${t.pending.join(", ")}` : (t.note || "pronta"))
      : t.note;
    return h("tr", {},
      h("td", {}, t.name, h("div", { class: "muted" }, t.purpose), h("div", { class: "muted" }, `onde roda: ${t.where || "servidor"}`)),
      h("td", {}, pill(t.status === "available", t.status === "available" ? "disponível" : "ausente")),
      h("td", {}, t.status === "available" ? t.version : "—"),
      h("td", {}, h("span", { class: "mono" }, t.path || "—")),
      h("td", { class: "muted" }, observation),
      h("td", {}, t.status === "available" ? testBtn : h("span", { class: "muted" }, "indisponível"), result));
  };
  show(
    h("h2", {}, "Ferramentas de engenharia reversa"),
    h("p", { class: "muted" }, "Status real detectado no servidor. Ferramenta ausente aparece como ausente, com o motivo, e não é simulada."),
    h("div", { class: "card" }, h("table", {},
      h("thead", {}, h("tr", {},
        h("th", {}, "Ferramenta"), h("th", {}, "Status"), h("th", {}, "Versão"),
        h("th", {}, "Caminho"), h("th", {}, "Observação"), h("th", {}, "Teste de execução"))),
      h("tbody", {}, tools.map(rowFor)))),
    h("div", { class: "card" }, h("h3", {}, "IA (opcional)"),
      h("p", {}, `Ligada: ${ai.enabled ? "sim" : "não"} · Ollama local: ${ai.ollama_reachable ? "alcançável" : "indisponível"} · Orçamento diário: ${ai.calls_today}/${ai.daily_budget}`),
      h("p", { class: "muted" }, "Provedores externos não estão implementados nesta versão e exigem consentimento explícito.")),
  );
}

// ----- roteamento --------------------------------------------------------
const ROUTES = [
  [/^#?\/?$/, () => homeView()],
  [/^#\/tools$/, () => toolsView()],
  [/^#\/p\/([0-9a-f]{32})$/, (m) => projectView(m[1])],
  [/^#\/p\/([0-9a-f]{32})\/a\/([0-9a-f]{32})$/, (m) => artifactView(m[1], m[2])],
];

async function route() {
  const hash = location.hash || "#/";
  for (const [rx, fn] of ROUTES) {
    const m = hash.match(rx);
    if (m) {
      try {
        await fn(m);
      } catch (e) {
        show(h("div", { class: "card err" }, errText(e)));
      }
      return;
    }
  }
  show(h("p", {}, "Página não encontrada."));
}

// Modo desktop: o lançador (Tauri) injeta o token local antes da página carregar.
// Lido uma vez, guardado só no módulo api.js e removido do objeto global. Na versão web
// a variável não existe e este bloco não faz nada.
const desktopConfig = window.URE_DESKTOP;
if (desktopConfig) {
  const desktopToken = typeof desktopConfig.token === "string" ? desktopConfig.token.trim() : "";
  delete window.URE_DESKTOP;
  if (desktopToken) setToken(desktopToken);
}

window.addEventListener("hashchange", route);
refreshHealth();
route();
