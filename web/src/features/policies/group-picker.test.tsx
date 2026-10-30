import { cleanup, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { server } from "@/mocks/node";
import { renderApp } from "@/test/render";

const usb = { default_action: "allow", rules: [] };
const profiles = [
  { vdom: "Default", version: 2, digest: "a".repeat(64), body: { web_filter: { blocked: ["default.example"] }, usb_control: usb } },
  { vdom: "BPO", version: 1, digest: "b".repeat(64), body: { web_filter: { blocked: ["bpo.example"] }, usb_control: usb } },
  { vdom: "TI", version: 3, digest: "c".repeat(64), body: { web_filter: { blocked: ["ti.example"] }, usb_control: usb } },
];

function backend() {
  const writes: Array<{ vdom: string; match: string | null }> = [];
  server.use(
    http.get("*/api/v1/profiles", () => HttpResponse.json(profiles)),
    http.post("*/api/v1/profiles/:vdom", ({ request, params }) => {
      writes.push({ vdom: String(params.vdom), match: request.headers.get("if-match") });
      return HttpResponse.json({ vdom: String(params.vdom), version: 1, digest: "d".repeat(64), warnings: [] });
    }),
  );
  return writes;
}

afterEach(() => { window.sessionStorage.clear(); });

describe("policy group picker", () => {
  it("lists published groups and loads the chosen group's policy before publishing to it", async () => {
    const writes = backend();
    const user = userEvent.setup();
    renderApp("/policies/web");
    const groups = await screen.findByRole("radiogroup", { name: "Grupo da política" });
    expect(within(groups).getAllByRole("radio").map((radio) => radio.getAttribute("aria-label"))).toEqual(["BPO", "Default", "TI"]);
    expect(within(groups).getByRole("radio", { name: "Default" })).toBeChecked();
    expect(within(groups).getByText("v3")).toBeInTheDocument();
    await user.click(within(groups).getByRole("radio", { name: "BPO" }));
    expect(await screen.findByRole("button", { name: "Editar bpo.example" })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Editar default.example" })).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Publicar política" }));
    await waitFor(() => expect(writes).toEqual([{ vdom: "BPO", match: "b".repeat(64) }]));
  });

  it("creates a new group in one step and publishes its first profile without a digest precondition", async () => {
    const writes = backend();
    const user = userEvent.setup();
    renderApp("/policies/web");
    await screen.findByRole("radiogroup", { name: "Grupo da política" });
    await user.click(screen.getByRole("button", { name: "Novo grupo" }));
    await user.type(screen.getByLabelText("Nome do novo grupo"), "Auditoria");
    await user.click(screen.getByRole("button", { name: "Criar grupo" }));
    const created = screen.getByRole("radio", { name: "Auditoria" });
    expect(created).toBeChecked();
    expect(screen.getByText(/ainda não publicado/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Publicar política" }));
    await waitFor(() => expect(writes).toEqual([{ vdom: "Auditoria", match: null }]));
  });

  it("rejects empty or duplicate group names without changing the selection", async () => {
    backend();
    const user = userEvent.setup();
    renderApp("/policies/web");
    await screen.findByRole("radiogroup", { name: "Grupo da política" });
    await user.click(screen.getByRole("button", { name: "Novo grupo" }));
    await user.type(screen.getByLabelText("Nome do novo grupo"), "bpo");
    await user.click(screen.getByRole("button", { name: "Criar grupo" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Já existe um grupo chamado BPO.");
    await user.clear(screen.getByLabelText("Nome do novo grupo"));
    await user.type(screen.getByLabelText("Nome do novo grupo"), "   ");
    await user.click(screen.getByRole("button", { name: "Criar grupo" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Informe o nome do grupo.");
    expect(screen.getByRole("radio", { name: "Default" })).toBeChecked();
  });

  it("filters the group list without changing the selected group", async () => {
    backend();
    const user = userEvent.setup();
    renderApp("/policies/web");
    const groups = await screen.findByRole("radiogroup", { name: "Grupo da política" });
    await user.type(screen.getByLabelText("Buscar grupo"), "t");
    expect(within(groups).getAllByRole("radio").map((radio) => radio.getAttribute("aria-label"))).toEqual(["Default", "TI"]);
    expect(within(groups).getByRole("radio", { name: "Default" })).toBeChecked();
  });

  it("keeps the chosen group when moving to another policy page", async () => {
    backend();
    const user = userEvent.setup();
    renderApp("/policies/web");
    await user.click(await screen.findByRole("radio", { name: "TI" }));
    cleanup();
    renderApp("/policies/usb");
    expect(await screen.findByRole("radio", { name: "TI" })).toBeChecked();
  });
});
