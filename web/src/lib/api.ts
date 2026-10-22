import type { z } from "zod";

export class ApiError extends Error {
  readonly status: number;

  constructor(status: number, message: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

let csrfToken: string | null = null;

/** The CSRF token accompanies every cookie-authenticated write. */
export function setCsrfToken(token: string | null): void {
  csrfToken = token;
}

interface RequestOptions {
  method?: "GET" | "POST" | "DELETE";
  json?: unknown;
  signal?: AbortSignal;
}

async function errorDetail(response: Response): Promise<string> {
  try {
    const body: unknown = await response.json();
    if (body && typeof body === "object" && "detail" in body && typeof body.detail === "string") {
      return body.detail;
    }
  } catch {
    // Non-JSON error pages (proxies, gateways) fall through to a generic message.
  }
  return `Request failed (${response.status})`;
}

export async function apiFetch<T>(path: string, schema: z.ZodType<T>, options: RequestOptions = {}): Promise<T> {
  const method = options.method ?? "GET";
  const headers = new Headers({ Accept: "application/json" });
  if (method !== "GET") {
    if (csrfToken) headers.set("X-CSRF-Token", csrfToken);
    if (options.json !== undefined) headers.set("Content-Type", "application/json");
  }
  let response: Response;
  try {
    response = await fetch(path, {
      method,
      headers,
      credentials: "same-origin",
      body: options.json === undefined ? undefined : JSON.stringify(options.json),
      signal: options.signal,
    });
  } catch {
    throw new ApiError(0, "Server unreachable");
  }
  if (!response.ok) throw new ApiError(response.status, await errorDetail(response));
  const parsed = schema.safeParse(await response.json().catch(() => undefined));
  if (!parsed.success) throw new ApiError(0, "Unexpected server response");
  return parsed.data;
}
