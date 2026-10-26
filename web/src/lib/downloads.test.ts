import { http, HttpResponse } from "msw";
import { server } from "@/mocks/node";
import { apiDownload, ApiError, setCsrfToken } from "./api";
import { downloadCsv } from "./management";

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); setCsrfToken(null); });

function downloads() {
  const create = vi.fn().mockReturnValue("blob:test-download");
  const revoke = vi.fn();
  Object.defineProperty(URL, "createObjectURL", { configurable: true, value: create });
  Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: revoke });
  const click = vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
  return { create, revoke, click };
}

describe("authenticated and spreadsheet-safe downloads", () => {
  it("authenticates a bundle download with CSRF and releases the object URL", async () => {
    const { create, revoke, click } = downloads();
    setCsrfToken("download-csrf");
    let requestHeaders: Headers | undefined;
    let payload: unknown;
    server.use(http.post("*/bundle", async ({ request }) => { requestHeaders = request.headers; payload = await request.json(); return new HttpResponse("binary data"); }));
    await apiDownload("/bundle", "bundle.zip", { vdom: "Default" });
    expect(payload).toEqual({ vdom: "Default" });
    expect(requestHeaders?.get("x-csrf-token")).toBe("download-csrf");
    expect(create).toHaveBeenCalledOnce(); expect(click).toHaveBeenCalledOnce();
    expect(revoke).toHaveBeenCalledWith("blob:test-download");
  });

  it("reports transport errors and non-JSON server failures without creating a download", async () => {
    const { create } = downloads();
    server.use(http.post("*/bundle", () => HttpResponse.error()));
    await expect(apiDownload("/bundle", "bundle.zip", {})).rejects.toThrow("Server unreachable");
    server.use(http.post("*/bundle", () => new HttpResponse("proxy failure", { status: 503 })));
    await expect(apiDownload("/bundle", "bundle.zip", {})).rejects.toThrow("Request failed (503)");
    expect(create).not.toHaveBeenCalled();
  });

  it("keeps structured authorization errors and releases a URL when browser saving fails", async () => {
    const { revoke, click } = downloads();
    server.use(http.post("*/bundle", () => HttpResponse.json({ detail: "permission denied" }, { status: 403 })));
    await expect(apiDownload("/bundle", "bundle.zip", {})).rejects.toMatchObject({ status: 403, message: "permission denied" } satisfies Partial<ApiError>);
    server.use(http.post("*/bundle", () => new HttpResponse("ok")));
    click.mockImplementation(() => { throw new Error("save blocked"); });
    await expect(apiDownload("/bundle", "bundle.zip", {})).rejects.toThrow("save blocked");
    expect(revoke).toHaveBeenCalledWith("blob:test-download");
  });

  it("quotes CSV values and neutralizes formulas rather than executing spreadsheet input", async () => {
    const { create, click, revoke } = downloads();
    downloadCsv("audit.csv", [["=cmd()", '+formula', "@SUM(A1)", "-1", '\tformula', null, 'quoted"value', "normal"]]);
    const blob = create.mock.calls[0]?.[0] as Blob;
    const csv = await blob.text();
    expect(csv).toContain('"\'=cmd()"'); expect(csv).toContain('"\'+formula"');
    expect(csv).toContain('"\'@SUM(A1)"'); expect(csv).toContain('"quoted""value"');
    expect(csv).toContain('""'); expect(csv).toContain('"normal"');
    expect(click).toHaveBeenCalledOnce(); expect(revoke).toHaveBeenCalledOnce();
  });
});
