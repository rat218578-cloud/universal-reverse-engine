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
