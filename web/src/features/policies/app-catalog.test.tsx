import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { server } from "@/mocks/node";
import { openTab, renderApp } from "@/test/render";

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
    await user.click(screen.getByRole("button", { name: "Criar override" }));
    const dialog = screen.getByRole("dialog", { name: "Novo override" });
    await user.click(within(dialog).getByRole("radio", { name: "Permitir" }));
    await user.type(within(dialog).getByLabelText("Buscar aplicativo"), "steam");
    await user.click(await within(dialog).findByRole("checkbox", { name: "Selecionar Steam" }));
    await user.click(within(dialog).getByRole("button", { name: "Adicionar override" }));
    const overrides = screen.getByRole("table", { name: "Overrides de aplicativos" });
    expect(within(overrides).getByText("Steam")).toBeInTheDocument();
    expect(within(overrides).getByRole("radio", { name: "Permitir Steam" })).toBeChecked();
    await user.click(screen.getByRole("button", { name: "Publicar política" }));
    await waitFor(() => expect(writes).toHaveLength(1));
    expect(writes[0]?.app_catalog).toEqual({ actions: { "category:p2p": "block", "category:games": "block", "app:Valve.Steam": "allow" }, generated: {} });
    expect((writes[0]?.app_control as { execution_rules: unknown[] }).execution_rules).toEqual([manual]);
  });

  it("marks Microsoft applications as not blockable", async () => {
    backend({});
    const user = userEvent.setup();
    renderApp("/policies/apps");
    await user.click(await screen.findByRole("button", { name: "Criar override" }));
    const dialog = screen.getByRole("dialog", { name: "Novo override" });
    await user.type(within(dialog).getByLabelText("Buscar aplicativo"), "teams");
    expect(await within(dialog).findByText(/não bloqueável/i)).toBeInTheDocument();
    expect(within(dialog).getByRole("checkbox", { name: "Selecionar Microsoft Teams" })).toBeDisabled();
    await user.click(within(dialog).getByRole("radio", { name: "Permitir" }));
    expect(within(dialog).getByRole("checkbox", { name: "Selecionar Microsoft Teams" })).toBeEnabled();
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
    await openTab(user, "Rede e encerramento");
    expect(screen.getByLabelText("Processos a encerrar")).toHaveValue("manual.exe");
    expect(screen.getByLabelText("Aplicativos sem acesso à rede")).toHaveValue("C:\\Manual\\tool.exe");
    await openTab(user, "Categorias e overrides");
    await user.click(within(section).getByRole("radio", { name: "Bloquear rede P2P e torrent" }));
    await user.click(screen.getByRole("button", { name: "Publicar política" }));
    await waitFor(() => expect(writes).toHaveLength(1));
    expect(writes[0]?.app_catalog).toEqual({ actions: { "category:games": "block", "category:p2p": "block_network" },
      generated: { processes: ["steam.exe"], network: ["C:\\Torrent\\qbittorrent.exe"] } });
    expect(writes[0]?.app_control).toMatchObject({ blocked: ["manual.exe"], network_blocked: ["C:\\Manual\\tool.exe"] });
  });
});
describe("application overrides and bulk category decisions", () => {
  afterEach(() => { window.sessionStorage.clear(); });

  it("lists overrides in force, changes and removes them, and applies one action to every category", async () => {
    const writes = backend({ app_catalog: { actions: { "app:Valve.Steam": "allow", "app:Other.App": "block_network", "category:games": "block" } } });
    const user = userEvent.setup();
    renderApp("/policies/apps");
    const overrides = await screen.findByRole("table", { name: "Overrides de aplicativos" });
    expect(screen.getByText("Sem alterações desde a versão publicada.")).toBeInTheDocument();
    expect(within(overrides).getByText("Valve.Steam")).toBeInTheDocument();
    expect(within(overrides).getByRole("radio", { name: "Bloquear rede Other.App" })).toBeChecked();
    await user.click(within(overrides).getByRole("radio", { name: "Bloquear Valve.Steam" }));
    await user.click(within(overrides).getByRole("button", { name: "Remover override de Other.App" }));
    await user.selectOptions(screen.getByLabelText("Todas as categorias: ação"), "block_network");
    await user.click(screen.getByRole("button", { name: "Aplicar a todas" }));
    const summary = screen.getByRole("complementary", { name: "Resumo do perfil" });
    expect(within(summary).getByText("Categorias sem rede").nextElementSibling).toHaveTextContent("2");
    await user.click(screen.getByRole("button", { name: "Publicar política" }));
    await waitFor(() => expect(writes).toHaveLength(1));
    expect(writes[0]?.app_catalog).toEqual({ actions: { "app:Valve.Steam": "block", "category:games": "block_network", "category:p2p": "block_network" }, generated: {} });
  });

  it("clears every category decision but keeps the overrides", async () => {
    const writes = backend({ app_catalog: { actions: { "app:Valve.Steam": "allow", "category:games": "block" } } });
    const user = userEvent.setup();
    renderApp("/policies/apps");
    await user.selectOptions(await screen.findByLabelText("Todas as categorias: ação"), "none");
    await user.click(screen.getByRole("button", { name: "Aplicar a todas" }));
    expect(screen.getByRole("radio", { name: "Sem regra Jogos" })).toBeChecked();
    await user.click(screen.getByRole("button", { name: "Publicar política" }));
    await waitFor(() => expect(writes).toHaveLength(1));
    expect(writes[0]?.app_catalog).toEqual({ actions: { "app:Valve.Steam": "allow" }, generated: {} });
  });

  it("cancels the override dialog without changes and hides creation for viewers", async () => {
    backend({});
    const user = userEvent.setup();
    renderApp("/policies/apps");
    await user.click(await screen.findByRole("button", { name: "Criar override" }));
    const dialog = screen.getByRole("dialog", { name: "Novo override" });
    expect(within(dialog).getByRole("button", { name: "Adicionar override" })).toBeDisabled();
    await user.type(within(dialog).getByLabelText("Buscar aplicativo"), "steam");
    await user.click(await within(dialog).findByRole("checkbox", { name: "Selecionar Steam" }));
    await user.click(within(dialog).getByRole("button", { name: "Remover Steam da seleção" }));
    expect(within(dialog).getByRole("checkbox", { name: "Selecionar Steam" })).not.toBeChecked();
    await user.click(within(dialog).getByRole("button", { name: "Cancelar" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByText(/Nenhum override/)).toBeInTheDocument();
  });

  it("does not offer override creation to viewers", async () => {
    backend({});
    server.use(http.get("*/api/v1/auth/session", () => HttpResponse.json({ username: "reader", role: "viewer", csrf_token: "reader" })));
    renderApp("/policies/apps");
    await screen.findByRole("table", { name: "Overrides de aplicativos" });
    expect(screen.queryByRole("button", { name: "Criar override" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Aplicar a todas" })).toBeNull();
  });
});

describe("vendor filters and override comments", () => {
  afterEach(() => { window.sessionStorage.clear(); });

  it("creates a vendor filter with a comment and edits comments in the table", async () => {
    const writes = backend({ app_catalog: { actions: { "app:Valve.Steam": "allow" }, notes: { "app:Valve.Steam": "QA" } } });
    const user = userEvent.setup();
    renderApp("/policies/apps");
    const overrides = await screen.findByRole("table", { name: "Overrides de aplicativos" });
    expect(within(overrides).getByLabelText("Comentário de Valve.Steam")).toHaveValue("QA");
    await user.click(screen.getByRole("button", { name: "Criar override" }));
    const dialog = screen.getByRole("dialog", { name: "Novo override" });
    await user.click(within(dialog).getByRole("radio", { name: "Editor (filtro)" }));
    await user.click(within(dialog).getByRole("radio", { name: "Bloquear rede" }));
    await user.type(within(dialog).getByLabelText("Buscar aplicativo"), "steam");
    await user.click(await within(dialog).findByRole("checkbox", { name: "Selecionar valve" }));
    await user.type(within(dialog).getByLabelText("Comentário (opcional)"), "Sem internet");
    await user.click(within(dialog).getByRole("button", { name: "Adicionar override" }));
    expect(within(overrides).getByText("Filtro: editor")).toBeInTheDocument();
    expect(within(overrides).getByRole("radio", { name: "Bloquear rede Editor valve" })).toBeChecked();
    await user.clear(within(overrides).getByLabelText("Comentário de Valve.Steam"));
    await user.click(screen.getByRole("button", { name: "Publicar política" }));
    await waitFor(() => expect(writes).toHaveLength(1));
    expect(writes[0]?.app_catalog).toEqual({ actions: { "app:Valve.Steam": "allow", "vendor:valve": "block_network" }, generated: {}, notes: { "vendor:valve": "Sem internet" } });
  });

  it("keeps Microsoft out of blocking vendor filters and drops a removed override's comment", async () => {
    const writes = backend({ app_catalog: { actions: { "app:Valve.Steam": "allow" }, notes: { "app:Valve.Steam": "QA" } } });
    const user = userEvent.setup();
    renderApp("/policies/apps");
    await user.click(await screen.findByRole("button", { name: "Criar override" }));
    const dialog = screen.getByRole("dialog", { name: "Novo override" });
    await user.click(within(dialog).getByRole("radio", { name: "Editor (filtro)" }));
    await user.type(within(dialog).getByLabelText("Buscar aplicativo"), "teams");
    expect(await within(dialog).findByRole("checkbox", { name: "Selecionar microsoft" })).toBeDisabled();
    await user.click(within(dialog).getByRole("button", { name: "Cancelar" }));
    await user.click(screen.getByRole("button", { name: "Remover override de Valve.Steam" }));
    await user.click(screen.getByRole("button", { name: "Publicar política" }));
    await waitFor(() => expect(writes).toHaveLength(1));
    expect(writes[0]?.app_catalog).toEqual({ actions: {}, generated: {} });
  });
});
