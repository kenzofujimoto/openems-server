import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { server } from "@/mocks/node";
import { session } from "@/mocks/data";
import { renderApp } from "@/test/render";

const CODE = "QZJ9T-4Y3D1";

async function openSheet(user: ReturnType<typeof userEvent.setup>, devid = "RSM-SP-001", name = "NB-FINANCEIRO-01") {
  renderApp("/endpoints");
  // Wait for the session-gated page before its endpoint list, as App.test does; each step keeps the default timeout.
  await screen.findByRole("heading", { name: "Endpoints" });
  await user.click(await screen.findByRole("button", { name: `Abrir ${devid}` }));
  return screen.findByRole("dialog", { name });
}

describe("uninstall codes", () => {
  it("shows a generated code once, copies it and forgets it when the sheet closes", async () => {
    let request: { devid?: string; csrf?: string | null } = {};
    server.use(http.post("*/api/v1/endpoints/uninstall_code", async ({ request: incoming }) => {
      request = { ...((await incoming.json()) as { devid: string }), csrf: incoming.headers.get("x-csrf-token") };
      return HttpResponse.json({ devid: "RSM-SP-001", counter: 3, code: CODE });
    }));
    const user = userEvent.setup();
    const sheet = await openSheet(user);
    const section = within(sheet).getByRole("region", { name: "Desinstalação" });
    expect(within(section).queryByText(CODE)).toBeNull();

    await user.click(within(section).getByRole("button", { name: "Gerar código de desinstalação" }));
    expect(await within(section).findByLabelText("Código de desinstalação")).toHaveTextContent(CODE);
    expect(within(section).getByText(/vale uma vez/)).toBeInTheDocument();
    expect(request).toEqual({ devid: "RSM-SP-001", csrf: "mock-csrf-token" });

    await user.click(within(section).getByRole("button", { name: "Copiar código" }));
    expect(await navigator.clipboard.readText()).toBe(CODE);
    expect(within(section).getByText("Código copiado")).toBeInTheDocument();

    await user.keyboard("{Escape}");
    const reopened = await openSheetAgain(user);
    expect(within(reopened).queryByText(CODE)).toBeNull();
  });

  it("explains when the server has no uninstall master key", async () => {
    server.use(http.post("*/api/v1/endpoints/uninstall_code", () =>
      HttpResponse.json({ detail: "uninstall codes are not configured on this server" }, { status: 503 })));
    const user = userEvent.setup();
    const sheet = await openSheet(user);
    await user.click(within(sheet).getByRole("button", { name: "Gerar código de desinstalação" }));
    expect(await within(sheet).findByRole("alert")).toHaveTextContent("Códigos de desinstalação não configurados no servidor");
  });

  it("reopens the secret delivery only after confirmation", async () => {
    const reopened: string[] = [];
    server.use(http.post("*/api/v1/endpoints/uninstall_secret/reset", async ({ request }) => {
      reopened.push(((await request.json()) as { devid: string }).devid);
      return HttpResponse.json({ ok: true });
    }));
    const user = userEvent.setup();
    const sheet = await openSheet(user);
    await user.click(within(sheet).getByRole("button", { name: "Reabrir entrega do segredo" }));
    expect(reopened).toEqual([]);
    await user.click(within(sheet).getByRole("button", { name: "Cancelar" }));
    await user.click(within(sheet).getByRole("button", { name: "Reabrir entrega do segredo" }));
    await user.click(within(sheet).getByRole("button", { name: "Confirmar reabertura" }));
    expect(await within(sheet).findByText(/Entrega reaberta/)).toBeInTheDocument();
    expect(reopened).toEqual(["RSM-SP-001"]);
  });

  it("hides uninstall actions from viewers", async () => {
    server.use(
      http.get("*/api/v1/auth/session", () => HttpResponse.json({ ...session, role: "viewer" })),
      http.get("*/api/v1/uninstall_release", () => HttpResponse.json([])),
    );
    const user = userEvent.setup();
    const sheet = await openSheet(user);
    expect(within(sheet).queryByRole("region", { name: "Desinstalação" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Liberar desinstalação" })).toBeNull();
  });
});

async function openSheetAgain(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole("button", { name: "Abrir RSM-SP-001" }));
  return screen.findByRole("dialog", { name: "NB-FINANCEIRO-01" });
}

describe("removal release", () => {
  it("releases a group after a warning, lists it and revokes it", async () => {
    const releases: Array<{ scope: string; released_at: string; released_by: string }> = [];
    const posted: Array<{ scope: string; released: boolean }> = [];
    server.use(
      http.get("*/api/v1/uninstall_release", () => HttpResponse.json(releases)),
      http.post("*/api/v1/uninstall_release", async ({ request }) => {
        const body = (await request.json()) as { scope: string; released: boolean };
        posted.push(body);
        if (body.released) releases.push({ scope: body.scope, released_at: "2026-10-25T12:00:00Z", released_by: "labadmin" });
        else releases.splice(0, releases.length, ...releases.filter((release) => release.scope !== body.scope));
        return HttpResponse.json(body);
      }),
    );
    const user = userEvent.setup();
    renderApp("/endpoints");
    await user.click(await screen.findByRole("button", { name: "Liberar desinstalação" }));
    const dialog = await screen.findByRole("dialog", { name: "Liberar desinstalação" });
    const scope = within(dialog).getByRole("combobox", { name: "Escopo" });
    expect(within(scope).getAllByRole("option").map((option) => option.textContent)).toEqual(["Toda a frota", "Default", "Strict"]);
    await user.selectOptions(scope, "Strict");
    await user.click(within(dialog).getByRole("button", { name: "Liberar" }));
    expect(within(dialog).getByText(/poderão ser removidas sem código/)).toBeInTheDocument();
    expect(posted).toEqual([]);
    await user.click(within(dialog).getByRole("button", { name: "Confirmar liberação" }));
    const row = await within(dialog).findByRole("row", { name: /Strict/ });
    expect(row).toHaveTextContent("labadmin");
    expect(posted).toEqual([{ scope: "Strict", released: true }]);

    await user.click(within(dialog).getByRole("button", { name: "Revogar liberação de Strict" }));
    await waitFor(() => expect(within(dialog).queryByRole("row", { name: /Strict/ })).toBeNull());
    expect(posted).toEqual([{ scope: "Strict", released: true }, { scope: "Strict", released: false }]);
  });

  it("names the fleet-wide release", async () => {
    server.use(http.get("*/api/v1/uninstall_release", () =>
      HttpResponse.json([{ scope: "*", released_at: "2026-10-25T12:00:00Z", released_by: "labadmin" }])));
    const user = userEvent.setup();
    renderApp("/endpoints");
    await user.click(await screen.findByRole("button", { name: "Liberar desinstalação" }));
    const dialog = await screen.findByRole("dialog", { name: "Liberar desinstalação" });
    expect(await within(dialog).findByRole("row", { name: /Toda a frota/ })).toBeInTheDocument();
  });

  it("is hidden when the server has no uninstall codes", async () => {
    server.use(http.get("*/api/v1/uninstall_release", () =>
      HttpResponse.json({ detail: "uninstall codes are not configured on this server" }, { status: 503 })));
    renderApp("/endpoints");
    await screen.findByRole("button", { name: "Abrir RSM-SP-001" });
    await waitFor(() => expect(screen.queryByRole("button", { name: "Liberar desinstalação" })).toBeNull());
  });
});

describe("uninstall tamper events", () => {
  it("names uninstall events in Portuguese", async () => {
    const now = new Date().toISOString();
    server.use(http.get("*/api/v1/events", () => HttpResponse.json([
      { id: "u1", at: now, devid: "RSM-SP-002", kind: "tamper", reason: "uninstall_code_rejected",
        detail: "an uninstall code was rejected" },
      { id: "u2", at: now, devid: "RSM-SP-003", kind: "tamper", reason: "uninstall_without_secret",
        detail: "agent removed without an uninstall secret on this machine" },
    ])));
    renderApp("/");
    expect(await screen.findByText("Código de desinstalação recusado")).toBeInTheDocument();
    expect(screen.getByText("Agente removido sem segredo de desinstalação")).toBeInTheDocument();
  });
});
