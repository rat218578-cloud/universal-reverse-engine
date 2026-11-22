// Cliente HTTP mínimo. O token (se configurado) fica apenas em memória desta aba.
let token = null;
export function setToken(value) {
  token = value || null;
}
export class ApiErr extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}
export async function api(method, path, { body, headers = {}, raw = false } = {}) {
  const h = { ...headers };
  if (token) h.Authorization = `Bearer ${token}`;
  let payload;
  if (body instanceof Blob) {
    payload = body;
  } else if (body !== undefined) {
    h["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }
  const res = await fetch(path, { method, headers: h, body: payload });
  if (!res.ok) {
    let message = res.statusText || "erro";
    try {
      message = (await res.json()).error || message;
    } catch {
      /* corpo não é JSON */
    }
    throw new ApiErr(res.status, message);
  }
  if (raw) return res;
  return res.status === 204 ? null : res.json();
}
