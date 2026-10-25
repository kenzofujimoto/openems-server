import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { server } from "@/mocks/node";
import { renderApp } from "@/test/render";

const body = { web_filter: { blocked: ["old.example"], allowed: ["safe.example"] }, app_control: { blocked: ["old.exe"] }, usb_control: { default_action: "allow", rules: [] } };
const profile = { vdom: "Default", version: 4, digest: "a".repeat(64), body };

function backend() {
  const writes: Array<{ body: unknown; match: string | null; csrf: string | null }> = [];
  server.use(
    http.get("*/api/v1/profiles", () => HttpResponse.json([profile])),
    http.post("*/api/v1/profiles/:vdom", async ({ request }) => {
      writes.push({ body: await request.json(), match: request.headers.get("if-match"), csrf: request.headers.get("x-csrf-token") });
      return HttpResponse.json({ vdom: "Default", version: 5, digest: "b".repeat(64), warnings: [] });
    }),
  );
  return writes;
}

describe("policy editors", () => {
  it("publishes web rules and categories while preserving apps and USB with a digest precondition", async () => {
    const writes = backend();
    const user = userEvent.setup();
    renderApp("/policies/web");
    const blocked = await screen.findByLabelText("Domínios bloqueados");
    await user.clear(blocked);
    await user.click(blocked); await user.paste("*.games.example");
    await user.click(screen.getByRole("checkbox", { name: "Bloquear Jogos" }));
    await user.click(screen.getByRole("checkbox", { name: "Google" }));
    await user.click(screen.getByRole("button", { name: "Publicar política" }));
    expect(await screen.findByRole("status")).toHaveTextContent("v5");
    expect(writes).toEqual([{ body: { ...body, web_filter: { blocked: ["*.games.example"], allowed: ["safe.example"], blocked_categories: ["games"], safe_search: { engines: ["google"], youtube: "strict" } } }, match: profile.digest, csrf: "mock-csrf-token" }]);
  });

  it("creates a schedule with an IANA timezone and keeps category windows", async () => {
    const writes = backend();
    const user = userEvent.setup();
    renderApp("/policies/web");
    await user.click(await screen.findByRole("button", { name: "Adicionar horário" }));
    await user.click(screen.getByLabelText("Domínios no horário 1")); await user.paste("scheduled.example");
    await user.click(screen.getByRole("button", { name: "Publicar política" }));
    await waitFor(() => expect(writes).toHaveLength(1));
    expect(writes[0]?.body).toMatchObject({ web_filter: { timezone: "America/Sao_Paulo", scheduled: [{ days: ["mon", "tue", "wed", "thu", "fri"], from: "08:00", to: "18:00", blocked: ["scheduled.example"] }] } });
  });

  it("rejects a URL locally and exposes a retry after a concurrent publication", async () => {
    const writes = backend();
    const user = userEvent.setup();
    renderApp("/policies/web");
    const blocked = await screen.findByLabelText("Domínios bloqueados");
    await user.clear(blocked); await user.click(blocked); await user.paste("https://bad.example/path");
    await user.click(screen.getByRole("button", { name: "Publicar política" }));
    expect(screen.getByRole("alert")).toHaveTextContent("domínio");
    expect(writes).toEqual([]);
    await user.clear(blocked); await user.click(blocked); await user.paste("valid.example");
    server.use(http.post("*/api/v1/profiles/:vdom", () => HttpResponse.json({ detail: "changed" }, { status: 412 })));
    await user.click(screen.getByRole("button", { name: "Publicar política" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("alterada por outro administrador");
    expect(screen.getByRole("button", { name: "Recarregar política" })).toBeInTheDocument();
  });

  it("uses application inventory to build a hash rule with its sample path", async () => {
    const writes = backend();
    server.use(http.get("*/api/v1/endpoints/inventory", () => HttpResponse.json({ devid: "RSM-SP-001", collected_at: "2026-10-25T10:00:00Z", applications: [{ name: "Test App", path: "C:\\Tools\\test.exe", sha256: "c".repeat(64), publisher: "Trusted Publisher", version: "1", running: true }], usb_devices: [] })));
    const user = userEvent.setup();
    renderApp("/policies/apps");
    await user.click(await screen.findByRole("button", { name: "Bloquear hash de Test App" }));
    await user.click(screen.getByRole("button", { name: "Publicar política" }));
    await waitFor(() => expect(writes).toHaveLength(1));
    expect(writes[0]?.body).toMatchObject({ web_filter: body.web_filter, usb_control: body.usb_control, app_control: { blocked: ["old.exe"], execution_rules: [{ kind: "hash", value: "c".repeat(64), sample_path: "C:\\Tools\\test.exe" }] } });
  });

  it("builds an allow exception from USB inventory while retaining the outside sections", async () => {
    const writes = backend();
    server.use(http.get("*/api/v1/endpoints/inventory", () => HttpResponse.json({ devid: "RSM-SP-001", collected_at: "2026-10-25T10:00:00Z", applications: [], usb_devices: [{ instance_id: "USBSTOR\\TEST", vid: "0781", pid: "5581", manufacturer: "Test", product: "Test Drive", serial: "SN123", class: "storage", drive_letters: ["E:"], present: true, first_seen: "2026-10-25T10:00:00Z", last_seen: "2026-10-25T10:00:00Z" }] })));
    const user = userEvent.setup();
    renderApp("/policies/usb");
    await user.selectOptions(await screen.findByLabelText("Ação padrão para armazenamento"), "block");
    await user.click(await screen.findByRole("button", { name: "Permitir Test Drive" }));
    await user.click(screen.getByRole("button", { name: "Publicar política" }));
    await waitFor(() => expect(writes).toHaveLength(1));
    expect(writes[0]?.body).toMatchObject({ web_filter: body.web_filter, app_control: body.app_control, usb_control: { default_action: "block", rules: [{ action: "allow", vid: "0781", pid: "5581", serial: "SN123" }] } });
  });

  it("keeps editors readable for viewers without publication controls", async () => {
    backend();
    server.use(http.get("*/api/v1/auth/session", () => HttpResponse.json({ username: "reader", role: "viewer", csrf_token: "reader" })));
    renderApp("/policies/web");
    expect(await screen.findByLabelText("Domínios bloqueados")).toBeDisabled();
    expect(screen.queryByRole("button", { name: "Publicar política" })).toBeNull();
  });

  it("shows publication capability warnings without claiming that endpoints applied the profile", async () => {
    backend();
    server.use(http.post("*/api/v1/profiles/:vdom", () => HttpResponse.json({ vdom: "Default", version: 5, digest: "b".repeat(64), warnings: [{ devid: "legacy-pc", missing: ["web-filter:dns"] }] })));
    const user = userEvent.setup();
    renderApp("/policies/web");
    await user.click(await screen.findByRole("button", { name: "Publicar política" }));
    expect(await screen.findByText(/legacy-pc/)).toHaveTextContent("web-filter:dns");
    expect(screen.getByRole("status")).toHaveTextContent("aguardando confirmação");
  });
});
