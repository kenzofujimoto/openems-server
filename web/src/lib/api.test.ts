import { http, HttpResponse } from "msw";
import { z } from "zod";
import { server } from "@/mocks/node";
import { ApiError, apiFetch, setCsrfToken } from "./api";

const okSchema = z.object({ ok: z.boolean() });

describe("apiFetch", () => {
  afterEach(() => setCsrfToken(null));

  it("parses successful responses with the given schema", async () => {
    server.use(http.get("*/api/v1/ping", () => HttpResponse.json({ ok: true })));
    await expect(apiFetch("/api/v1/ping", okSchema)).resolves.toEqual({ ok: true });
  });

  it("sends the CSRF token and JSON body only on writes", async () => {
    const seen: Array<{ method: string; csrf: string | null; type: string | null }> = [];
    server.use(
      http.all("*/api/v1/write", ({ request }) => {
        seen.push({ method: request.method, csrf: request.headers.get("x-csrf-token"), type: request.headers.get("content-type") });
        return HttpResponse.json({ ok: true });
      }),
    );
    setCsrfToken("csrf-123");
    await apiFetch("/api/v1/write", okSchema);
    await apiFetch("/api/v1/write", okSchema, { method: "POST", json: { a: 1 } });
    expect(seen).toEqual([
      { method: "GET", csrf: null, type: null },
      { method: "POST", csrf: "csrf-123", type: "application/json" },
    ]);
  });

  it("raises ApiError with the server status and detail", async () => {
    server.use(http.get("*/api/v1/denied", () => HttpResponse.json({ detail: "insufficient permission" }, { status: 403 })));
    const error = await apiFetch("/api/v1/denied", okSchema).catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ status: 403, message: "insufficient permission" });
  });

  it("uses a generic message when the error body is not JSON", async () => {
    server.use(http.get("*/api/v1/broken", () => new HttpResponse("<html>", { status: 502 })));
    await expect(apiFetch("/api/v1/broken", okSchema)).rejects.toMatchObject({ status: 502, message: "Request failed (502)" });
  });

  it("rejects responses that do not match the contract", async () => {
    server.use(http.get("*/api/v1/odd", () => HttpResponse.json({ ok: "yes" })));
    await expect(apiFetch("/api/v1/odd", okSchema)).rejects.toMatchObject({ status: 0, message: "Unexpected server response" });
  });

  it("reports network failures without leaking internals", async () => {
    server.use(http.get("*/api/v1/offline", () => HttpResponse.error()));
    await expect(apiFetch("/api/v1/offline", okSchema)).rejects.toMatchObject({ status: 0, message: "Server unreachable" });
  });

  it("rejects malformed success JSON and ignores non-string error details", async () => {
    server.use(
      http.get("*/api/v1/malformed", () => new HttpResponse("<html>proxy</html>")),
      http.delete("*/api/v1/no-detail", ({ request }) => {
        expect(request.headers.get("x-csrf-token")).toBeNull();
        expect(request.headers.get("content-type")).toBeNull();
        return HttpResponse.json({ detail: { internal: "private" } }, { status: 500 });
      }),
    );
    await expect(apiFetch("/api/v1/malformed", okSchema)).rejects.toMatchObject({ status: 0, message: "Unexpected server response" });
    await expect(apiFetch("/api/v1/no-detail", okSchema, { method: "DELETE" })).rejects.toMatchObject({ status: 500, message: "Request failed (500)" });
  });
});
