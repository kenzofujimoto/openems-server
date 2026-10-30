import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { server } from "@/mocks/node";
import { renderApp } from "@/test/render";

const manual = { id: "app-1", kind: "hash", value: "a".repeat(64), sample_path: "C:\\Tools\\tool.exe" };
const generated = { id: "catalog-abc123def456", kind: "publisher", value: "CN=Epic Games Inc.", if_present: true };
const catalog = {
  available: true, version: "2026-10-30T12:00:00Z", attribution: "winget-pkgs, MIT",
  categories: [
    { id: "games", label: "Jogos", apps: 377, observed_endpoints: 2 },
    { id: "p2p", label: "P2P e torrent", apps: 83, observed_endpoints: 0 },
  ],
  observed: { "Valve.Steam": 2 },
};
const apps = [
  { id: "Valve.Steam", name: "Steam", vendor: "valve", category: "games", blockable: true, observed_endpoints: 2 },
  { id: "Microsoft.Teams", name: "Microsoft Teams", vendor: "microsoft", category: "messaging", blockable: false, observed_endpoints: 1 },
];

function backend(body: Record<string, unknown>, available = true) {
  const writes: Array<Record<string, unknown>> = [];
  server.use(
    http.get("*/api/v1/profiles", () => HttpResponse.json([{ vdom: "Default", version: 1, digest: "a".repeat(64), body }])),
    http.get("*/api/v1/app_catalog", () => HttpResponse.json(available ? catalog : { available: false, version: null, attribution: "", categories: [], observed: {} })),
    http.get("*/api/v1/app_catalog/search", ({ request }) => {
      const q = new URL(request.url).searchParams.get("q")?.toLowerCase() ?? "";
      return HttpResponse.json(apps.filter((app) => app.name.toLowerCase().includes(q)));
    }),
    http.post("*/api/v1/profiles/:vdom", async ({ request }) => {
      writes.push(await request.json() as Record<string, unknown>);
      return HttpResponse.json({ vdom: "Default", version: 2, digest: "b".repeat(64), warnings: [], catalog_skipped: [] });
    }),
  );
  return writes;
}

afterEach(() => { window.sessionStorage.clear(); });

describe("application catalog", () => {
  it("blocks a category, allows one app inside it and keeps generated rules out of the manual editor", async () => {
    const writes = backend({ app_control: { execution_rules: [manual, generated] }, app_catalog: { actions: { "category:p2p": "block" } } });
    const user = userEvent.setup();
    renderApp("/policies/apps");
    const section = await screen.findByRole("region", { name: "Catálogo de aplicativos" });
    expect(await within(section).findByText(/377 apps/)).toBeInTheDocument();
    expect(within(section).getByText(/2 máquinas/)).toBeInTheDocument();
    expect(within(section).getByRole("radio", { name: "Bloquear P2P e torrent" })).toBeChecked();
    expect(screen.queryByDisplayValue(generated.value)).not.toBeInTheDocument();
    await user.click(within(section).getByRole("radio", { name: "Bloquear Jogos" }));
    await user.type(within(section).getByLabelText("Buscar aplicativo"), "steam");
    await user.click(await within(section).findByRole("radio", { name: "Permitir Steam" }));
    await user.click(screen.getByRole("button", { name: "Publicar política" }));
    await waitFor(() => expect(writes).toHaveLength(1));
    expect(writes[0]?.app_catalog).toEqual({ actions: { "category:p2p": "block", "category:games": "block", "app:Valve.Steam": "allow" } });
    expect((writes[0]?.app_control as { execution_rules: unknown[] }).execution_rules).toEqual([manual]);
  });

  it("marks Microsoft applications as not blockable", async () => {
    backend({});
    const user = userEvent.setup();
    renderApp("/policies/apps");
    const section = await screen.findByRole("region", { name: "Catálogo de aplicativos" });
    await user.type(await within(section).findByLabelText("Buscar aplicativo"), "teams");
    expect(await within(section).findByText(/não bloqueável/i)).toBeInTheDocument();
    expect(within(section).getByRole("radio", { name: "Bloquear Microsoft Teams" })).toBeDisabled();
  });

  it("explains an unavailable catalog and does not send catalog decisions", async () => {
    const writes = backend({ app_control: { execution_rules: [manual] } }, false);
    const user = userEvent.setup();
    renderApp("/policies/apps");
    const section = await screen.findByRole("region", { name: "Catálogo de aplicativos" });
    expect(await within(section).findByText(/catálogo ainda não foi publicado/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Publicar política" }));
    await waitFor(() => expect(writes).toHaveLength(1));
    expect(writes[0]).not.toHaveProperty("app_catalog");
  });
});

describe("application catalog network and process decisions", () => {
  afterEach(() => { window.sessionStorage.clear(); });
  it("offers network blocking and keeps generated processes and paths out of the manual lists", async () => {
    const writes = backend({ app_control: { blocked: ["manual.exe", "steam.exe"], network_blocked: ["C:\\Manual\\tool.exe", "C:\\Torrent\\qbittorrent.exe"] },
      app_catalog: { actions: { "category:games": "block" }, generated: { processes: ["steam.exe"], network: ["C:\\Torrent\\qbittorrent.exe"] } } });
    const user = userEvent.setup();
    renderApp("/policies/apps");
    const section = await screen.findByRole("region", { name: "Catálogo de aplicativos" });
    await within(section).findByText(/377 apps/);
    expect(screen.getByLabelText("Processos a encerrar")).toHaveValue("manual.exe");
    expect(screen.getByLabelText("Aplicativos sem acesso à rede")).toHaveValue("C:\\Manual\\tool.exe");
    await user.click(within(section).getByRole("radio", { name: "Bloquear rede P2P e torrent" }));
    await user.click(screen.getByRole("button", { name: "Publicar política" }));
    await waitFor(() => expect(writes).toHaveLength(1));
    expect(writes[0]?.app_catalog).toEqual({ actions: { "category:games": "block", "category:p2p": "block_network" },
      generated: { processes: ["steam.exe"], network: ["C:\\Torrent\\qbittorrent.exe"] } });
    expect(writes[0]?.app_control).toMatchObject({ blocked: ["manual.exe"], network_blocked: ["C:\\Manual\\tool.exe"] });
  });
});