import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { server } from "@/mocks/node";
import { renderApp } from "@/test/render";

const now = new Date().toISOString();
const log = [
  { id: "1", at: now, devid: "RSM-SP-001", kind: "web_block", detail: "bet365.com", reason: "domain", category: null, category_label: null, action: "blocked" },
  { id: "2", at: now, devid: "RSM-SP-001", kind: "app_block", detail: "game.exe", reason: "catalog-1", category: null, category_label: null },
  { id: "3", at: now, devid: "RSM-SP-001", kind: "usb_block", detail: "USB disk", reason: "default", category: null, category_label: null },
];
const profiles = [
  { vdom: "Default", version: 3, digest: "a".repeat(64), body: {
    web_filter: { domain_rules: [{ domain: "bet365.com", type: "wildcard", action: "block" }, { domain: "rsm.global", type: "wildcard", action: "allow" }], category_actions: { games: "block" } },
    app_control: { execution_rules: [{ id: "catalog-1", kind: "publisher", value: "CN=Game", if_present: true }] },
    app_catalog: { actions: { "category:games": "block" } }, usb_control: { default_action: "block", rules: [] } } },
  { vdom: "TI", version: 1, digest: "b".repeat(64), body: {} },
];

function backend() {
  const reads: string[] = [];
  const rules: unknown[] = [];
  server.use(
    http.get("*/api/v1/profiles", () => HttpResponse.json(profiles)),
    http.get("*/api/v1/events", ({ request }) => { reads.push(new URL(request.url).search); return HttpResponse.json(log); }),
    http.post("*/api/v1/assignment_rules", async ({ request }) => { rules.push(await request.json()); return HttpResponse.json({ ok: true }); }),
  );
  return { reads, rules };
}

describe("endpoint detail page", () => {
  it("opens from the endpoint list and summarizes the machine and its group", async () => {
    backend();
    const user = userEvent.setup();
    renderApp("/endpoints");
    await user.click(await screen.findByText("NB-FINANCEIRO-01"));
    const link = await screen.findByRole("link", { name: "Abrir ficha completa" });
    expect(link).toHaveAttribute("href", expect.stringContaining("/endpoints/RSM-SP-001"));
    await user.click(link);
    expect(await screen.findByRole("heading", { name: "NB-FINANCEIRO-01" })).toBeInTheDocument();
    expect(screen.getAllByRole("tab").map((tab) => tab.textContent)).toEqual(["Resumo", "Política", "Logs", "Inventário"]);
    expect(screen.getByRole("tabpanel")).toHaveTextContent("Grupo atribuído");
  });

  it("shows only this machine's logs with a type filter and CSV export", async () => {
    const { reads } = backend();
    const user = userEvent.setup();
    renderApp("/endpoints/RSM-SP-001");
    await user.click(await screen.findByRole("tab", { name: "Logs" }));
    const table = await screen.findByRole("table", { name: "Logs da máquina" });
    expect(within(table).getAllByRole("row")).toHaveLength(4);
    expect(reads.some((query) => new URLSearchParams(query).get("devid") === "RSM-SP-001")).toBe(true);
    await user.selectOptions(screen.getByLabelText("Tipo de evento"), "apps");
    expect(within(table).getAllByRole("row")).toHaveLength(2);
    expect(within(table).getByText("game.exe")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Exportar CSV" })).toBeEnabled();
  });

  it("explains the effective policy and moves the machine to another group by rule", async () => {
    const { rules } = backend();
    const user = userEvent.setup();
    renderApp("/endpoints/RSM-SP-001");
    await user.click(await screen.findByRole("tab", { name: "Política" }));
    const panel = screen.getByRole("tabpanel");
    expect(await within(panel).findByText(/1 domínio bloqueado · 1 permitido/)).toBeInTheDocument();
    expect(within(panel).getByText(/Categorias web bloqueadas: 1/)).toBeInTheDocument();
    expect(within(panel).getByText(/Catálogo de aplicativos: 1 decisão/)).toBeInTheDocument();
    expect(within(panel).getByText(/USB: bloquear por padrão/)).toBeInTheDocument();
    await user.selectOptions(within(panel).getByLabelText("Mover para o grupo"), "TI");
    await user.click(within(panel).getByRole("button", { name: "Mover máquina" }));
    await waitFor(() => expect(rules).toEqual([{ id: "endpoint-nb-financeiro-01", target_vdom: "TI", priority: 1, enabled: true,
      conditions: [{ field: "hostname", op: "equals", value: "NB-FINANCEIRO-01" }] }]));
  });
});
