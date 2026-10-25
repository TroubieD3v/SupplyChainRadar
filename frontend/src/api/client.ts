export class ApiError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

const TOKEN_KEY = "scradar-token";
export const getToken = () => localStorage.getItem(TOKEN_KEY) ?? "";
export const setToken = (v: string) => (v ? localStorage.setItem(TOKEN_KEY, v) : localStorage.removeItem(TOKEN_KEY));

function headers(extra: Record<string, string> = {}, mutating = false): Record<string, string> {
  const h: Record<string, string> = { ...extra };
  if (mutating) {
    h["X-Scradar-Request"] = "1";
    const t = getToken();
    if (t) h["Authorization"] = `Bearer ${t}`;
  }
  return h;
}

async function parse(res: Response) {
  if (res.ok) {
    if (res.status === 204) return null;
    const ct = res.headers.get("content-type") ?? "";
    return ct.includes("json") ? res.json() : res.text();
  }
  let code = "http_error";
  let message = `${res.status} ${res.statusText}`;
  try {
    const body = await res.json();
    const e = body.error ?? body.detail;
    if (e?.code) code = e.code;
    if (e?.message) message = e.message;
    else if (typeof e === "string") message = e;
    else if (Array.isArray(e)) message = e.map((x: any) => x.msg).join("; ");
  } catch {
    /* non-JSON error body */
  }
  throw new ApiError(res.status, code, message);
}

export async function get<T = any>(path: string, params?: Record<string, any>): Promise<T> {
  const qs = params
    ? "?" +
      Object.entries(params)
        .filter(([, v]) => v !== undefined && v !== null && v !== "")
        .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
        .join("&")
    : "";
  return parse(await fetch(`/api/v1${path}${qs}`, { headers: headers() }));
}

export async function send<T = any>(method: string, path: string, body?: unknown): Promise<T> {
  return parse(
    await fetch(`/api/v1${path}`, {
      method,
      headers: headers(body !== undefined ? { "Content-Type": "application/json" } : {}, true),
      body: body !== undefined ? JSON.stringify(body) : undefined,
    }),
  );
}

export async function upload<T = any>(path: string, form: FormData): Promise<T> {
  return parse(await fetch(`/api/v1${path}`, { method: "POST", headers: headers({}, true), body: form }));
}

export async function download(path: string, params: Record<string, string>, filename: string) {
  const qs = "?" + new URLSearchParams(params).toString();
  const res = await fetch(`/api/v1${path}${qs}`, { headers: headers() });
  if (!res.ok) await parse(res);
  const blob = await res.blob();
  saveBlob(blob, filename);
}

export function saveBlob(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}
