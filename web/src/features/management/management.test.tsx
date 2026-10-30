import { cleanup, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { server } from "@/mocks/node";
import { renderApp } from "@/test/render";

function settingsBackend() {
  server.use(
    http.get("*/api/v1/settings", () => HttpResponse.json({ event_retention_days: 30, installer_available: false, installer_configuration: "operator", server_version: "0.2.0" })),
    http.get("*/api/v1/admins", () => HttpResponse.json([{ username: "operator", role: "admin" }])),
    http.get("*/api/v1/enrollment/invitations", () => HttpResponse.json([{ id: "a".repeat(64), vdom: "Default", remaining: 1, expires_at: "2026-10-26T00:00:00Z" }])),
    http.get("*/api/v1/installers/windows", () => HttpResponse.json({ available: false })),
  );
}

describe("management pages", () => {
  it("filters real events by type and endpoint", async () => {
    const user = userEvent.setup();
    renderApp("/events");
    const filter = await screen.findByLabelText("Tipo de evento");
    await screen.findByRole("cell", { name: "utorrent.exe" });
    await user.selectOptions(filter, "app_block");
    expect(screen.getAllByRole("row")).toHaveLength(2);
    await user.click(screen.getByRole("searchbox", { name: "Buscar eventos" })); await user.paste("missing-pc");
    expect(screen.getByText("Nenhum evento corresponde aos filtros.")).toBeInTheDocument();
  });

  it("edits assignment rule priority without changing typed conditions and sends CSRF", async () => {
    let saved: unknown;
    let csrf: string | null = null;
    server.use(http.post("*/api/v1/assignment_rules", async ({ request }) => { saved = await request.json(); csrf = request.headers.get("x-csrf-token"); return HttpResponse.json({ ok: true }); }));
    const user = userEvent.setup();
    renderApp("/groups");
    await user.click(await screen.findByRole("button", { name: "Editar regra auditoria-strict" }));
    const priority = screen.getByLabelText("Prioridade");
    await user.clear(priority); await user.type(priority, "20");
    await user.click(screen.getByRole("button", { name: "Salvar regra" }));
    await waitFor(() => expect(saved).toEqual({ id: "auditoria-strict", target_vdom: "Strict", priority: 20, enabled: true, conditions: [{ field: "hostname", op: "contains", value: "AUDITORIA" }] }));
    expect(csrf).toBe("mock-csrf-token");
  });

  it("creates an in condition as a list and previews matching endpoints", async () => {
    let saved: unknown;
    server.use(http.post("*/api/v1/assignment_rules", async ({ request }) => { saved = await request.json(); return HttpResponse.json({ ok: true }); }));
    const user = userEvent.setup();
    renderApp("/groups");
    await screen.findByRole("button", { name: "Salvar regra" });
    await user.click(screen.getByLabelText("Identificador da regra")); await user.paste("systems");
    await screen.findByRole("option", { name: "Strict" });
    await user.selectOptions(screen.getByLabelText("Grupo de destino"), "Strict");
    await user.click(screen.getByRole("button", { name: "Adicionar condição" }));
    await user.selectOptions(screen.getByLabelText("Operador da condição 1"), "in");
    await user.click(screen.getByLabelText("Valor da condição 1")); await user.paste("win32\nlinux");
    await user.click(screen.getByRole("button", { name: "Salvar regra" }));
    await waitFor(() => expect(saved).toMatchObject({ conditions: [{ field: "os", op: "in", value: ["win32", "linux"] }] }));
  });

  it("deletes rules only after an explicit confirmation", async () => {
    let removed = false;
    server.use(http.delete("*/api/v1/assignment_rules/:id", () => { removed = true; return HttpResponse.json({ ok: true }); }));
    const user = userEvent.setup();
    renderApp("/groups");
    await user.click(await screen.findByRole("button", { name: "Excluir regra auditoria-strict" }));
    expect(removed).toBe(false);
    await user.click(screen.getByRole("button", { name: "Confirmar exclusão da regra" }));
    await waitFor(() => expect(removed).toBe(true));
  });

  it("renders audit metadata as plain text and filters by actor", async () => {
    server.use(http.get("*/api/v1/audit", () => HttpResponse.json([{ ts: "2026-10-25T12:00:00Z", actor: "<b>operator</b>", action: "profile.publish", target: "Default", metadata: { payload: "<img src=x onerror=alert(1)>" } }])));
    const user = userEvent.setup();
    renderApp("/audit");
    await screen.findByText("<b>operator</b>");
    expect(document.querySelector("img[src='x']")).toBeNull();
    await user.click(screen.getByRole("searchbox", { name: "Buscar auditoria" })); await user.paste("missing");
    expect(screen.getByText("Nenhuma ação corresponde aos filtros.")).toBeInTheDocument();
  });

  it("creates and revokes enrollment invitations while displaying a token only once", async () => {
    settingsBackend();
    let payload: unknown;
    let revoked = false;
    server.use(
      http.post("*/api/v1/enrollment/invitations", async ({ request }) => { payload = await request.json(); return HttpResponse.json({ invitation: "one-time-invitation", vdom: "Default", max_uses: 1, ttl_seconds: 3600 }); }),
      http.delete("*/api/v1/enrollment/invitations/:id", () => { revoked = true; return HttpResponse.json({ removed: "a".repeat(64) }); }),
    );
    const user = userEvent.setup();
    const rendered = renderApp("/settings");
    await user.click(await screen.findByRole("button", { name: "Gerar convite" }));
    expect(await screen.findByText("one-time-invitation")).toBeInTheDocument();
    expect(payload).toEqual({ vdom: "Default", max_uses: 1, ttl_seconds: 3600 });
    await user.click(screen.getByRole("button", { name: "Revogar convite de Default" }));
    await user.click(screen.getByRole("button", { name: "Confirmar revogação" }));
    await waitFor(() => expect(revoked).toBe(true));
    rendered.unmount();
    renderApp("/settings");
    await screen.findByRole("button", { name: "Gerar convite" });
    expect(screen.queryByText("one-time-invitation")).toBeNull();
  });

  it("shows installer availability honestly and creates administrators without caching the password", async () => {
    settingsBackend();
    let created: unknown;
    server.use(http.post("*/api/v1/admins", async ({ request }) => { created = await request.json(); return HttpResponse.json({ username: "new-reader", role: "viewer" }); }));
    const user = userEvent.setup();
    const rendered = renderApp("/settings");
    await screen.findByText(/Nenhum MSI configurado/);
    await user.click(screen.getByLabelText("Novo usuário")); await user.paste("new-reader");
    await user.click(screen.getByLabelText("Senha inicial")); await user.paste("test-password-123");
    await user.click(screen.getByRole("button", { name: "Criar administrador" }));
    await waitFor(() => expect(created).toEqual({ username: "new-reader", password: "test-password-123", role: "viewer" }));
    expect(screen.getByLabelText("Senha inicial")).toHaveValue("");
    expect(JSON.stringify(rendered.queryClient.getQueryCache().getAll().map((query) => query.state.data))).not.toContain("test-password-123");
  });

  it("keeps mutations hidden for viewers", async () => {
    settingsBackend();
    server.use(http.get("*/api/v1/auth/session", () => HttpResponse.json({ username: "reader", role: "viewer", csrf_token: "c" })));
    renderApp("/settings");
    expect(await screen.findByText("30 dias")).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Gerar convite" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Criar administrador" })).toBeNull();
  });

  it("persists dark mode and exposes a mobile navigation menu", async () => {
    const user = userEvent.setup();
    localStorage.removeItem("openems-theme");
    renderApp("/");
    await user.click(await screen.findByRole("button", { name: "Ativar modo escuro" }));
    expect(document.documentElement.dataset.theme).toBe("dark");
    expect(localStorage.getItem("openems-theme")).toBe("dark");
    await user.click(screen.getByRole("button", { name: "Abrir navegação" }));
    const navigation = screen.getByRole("navigation", { name: "Navegação móvel" });
    expect(within(navigation).getByRole("link", { name: "Configurações" })).toBeInTheDocument();
    cleanup();
    renderApp("/");
    expect(await screen.findByRole("button", { name: "Ativar modo claro" })).toBeInTheDocument();
    localStorage.removeItem("openems-theme");
    document.documentElement.removeAttribute("data-theme");
  });

  it("distinguishes applied application policies from real block events", async () => {
    server.use(http.get("*/api/v1/events", () => HttpResponse.json([
      { id: "setup", at: "2026-10-25T12:00:00Z", devid: "pc", kind: "app_control_applied", detail: "rule-1" },
      { id: "network", at: "2026-10-25T12:00:00Z", devid: "pc", kind: "app_network_policy", detail: "rule-2" },
      { id: "readonly", at: "2026-10-25T12:00:00Z", devid: "pc", kind: "usb_read_only", detail: "Test Drive" },
    ])));
    renderApp("/events");
    expect(await screen.findByRole("cell", { name: "Política de aplicativos aplicada" })).toBeInTheDocument();
    expect(screen.getByRole("cell", { name: "Regra de rede aplicada" })).toBeInTheDocument();
    expect(screen.getByRole("cell", { name: "USB em somente leitura" })).toBeInTheDocument();
  });

  it("shows the authenticated device inventories in its detail sheet", async () => {
    server.use(http.get("*/api/v1/endpoints/inventory", () => HttpResponse.json({ devid: "RSM-SP-001", collected_at: "2026-10-25T12:00:00Z", applications: [{ name: "Inventory App", path: "C:\\Test\\app.exe", sha256: "a".repeat(64), publisher: "Verified publisher", version: "1.0", running: true }], usb_devices: [{ instance_id: "USBSTOR\\INVENTORY", vid: "0781", pid: "1234", manufacturer: "Test", product: "Inventory Drive", serial: "SN1", class: "storage", drive_letters: ["E:"], present: true, first_seen: "2026-10-25T10:00:00Z", last_seen: "2026-10-25T12:00:00Z" }] })));
    const user = userEvent.setup();
    renderApp("/endpoints");
    await user.click(await screen.findByRole("button", { name: "Abrir RSM-SP-001" }));
    const sheet = await screen.findByRole("dialog", { name: "NB-FINANCEIRO-01" });
    expect(await within(sheet).findByText("Inventory App")).toBeInTheDocument();
    expect(within(sheet).getByText("Inventory Drive")).toBeInTheDocument();
    expect(within(sheet).getByText(/Verified publisher/)).toBeInTheDocument();
  });

  it("requires confirmation before revoking a device and never stores a rotated credential in queries", async () => {
    let revoked = false;
    server.use(
      http.post("*/api/v1/endpoints/revoke", () => { revoked = true; return HttpResponse.json({ ok: true }); }),
      http.post("*/api/v1/endpoints/credentials/rotate", () => HttpResponse.json({ device_token: "one-time-device-token" })),
    );
    const user = userEvent.setup();
    const rendered = renderApp("/endpoints");
    await user.click(await screen.findByRole("button", { name: "Abrir RSM-SP-001" }));
    await user.click(await screen.findByRole("button", { name: "Trocar credencial do agente" }));
    await user.click(screen.getByRole("button", { name: "Confirmar troca de credencial" }));
    expect(await screen.findByText("one-time-device-token")).toBeInTheDocument();
    expect(JSON.stringify(rendered.queryClient.getQueryCache().getAll().map((query) => query.state.data))).not.toContain("one-time-device-token");
    await user.click(screen.getByRole("button", { name: "Revogar cadastro" }));
    expect(revoked).toBe(false);
    await user.click(screen.getByRole("button", { name: "Confirmar revogação do cadastro" }));
    await waitFor(() => expect(revoked).toBe(true));
  });
});
