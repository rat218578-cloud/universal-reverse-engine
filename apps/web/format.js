// Funções puras de formatação usadas pela interface (testadas com node --test).
export function formatBytes(n) {
  if (!Number.isFinite(n) || n < 0) return "—";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let value = n;
  let i = 0;
  while (value >= 1024 && i < units.length - 1) {
    value /= 1024;
    i += 1;
  }
  return `${i === 0 ? value : value.toFixed(1)} ${units[i]}`;
}

const KINDS = {
  apk: "APK", pe: "Executável PE (EXE/DLL)", jar: "JAR", zip: "ZIP", elf: "ELF",
  macho: "Mach-O", dex: "DEX", corrupt: "Corrompido", unknown: "Desconhecido", empty: "Vazio",
};
export function kindLabel(kind) {
  return KINDS[kind] ?? kind;
}

export function shortHash(hash) {
  return hash ? `${hash.slice(0, 12)}…` : "—";
}

export function joinPath(base, name) {
  return base ? `${base}/${name}` : name;
}

export function parentPath(path) {
  const i = path.lastIndexOf("/");
  return i === -1 ? "" : path.slice(0, i);
}

/** Texto de andamento do envio ao servidor remoto (função pura, testada). */
export function remoteJobLabel(job) {
  const names = { queued: "na fila", running: "enviando e analisando no servidor", done: "concluído", failed: "falhou" };
  const base = names[job.status] || String(job.status || "desconhecido");
  if (job.status === "failed") return `${base}: ${job.error || job.message || "sem detalhes"}`;
  if (job.status === "done" && job.error) return `concluído com avisos: ${job.error}`;
  return job.message ? `${base} (${job.message})` : base;
}
