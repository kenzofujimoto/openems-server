import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { server } from "@/mocks/node";
import { openTab, renderApp } from "@/test/render";

const categories = { version: "2026-10-24T03:00:00Z", attribution: "UT1", categories: [
  { id: "adult", label: "Conteúdo adulto", group: "Adulto", count: 10 },
  { id: "gambling", label: "Jogos de azar", group: "Adulto", count: 5 },
  { id: "games", label: "Jogos", group: "Lazer", count: 7 },
] };

function backend() {
  const writes: Array<{ web_filter?: Record<string, unknown> }> = [];
  server.use(
    http.get("*/api/v1/categories", () => HttpResponse.json(categories)),
    http.get("*/api/v1/profiles", () => HttpResponse.json([{ vdom: "Default", version: 1, digest: "a".repeat(64), body: { web_filter: { category_actions: { games: "monitor" } } } }])),
    http.post("*/api/v1/profiles/:vdom", async ({ request }) => { writes.push(await request.json() as { web_filter?: Record<string, unknown> }); return HttpResponse.json({ vdom: "Default", version: 2, digest: "b".repeat(64), warnings: [] }); }),
  );
  return writes;
}

afterEach(() => { window.sessionStorage.clear(); });

describe("category table", () => {
  it("applies one action to a whole group and to individual selections", async () => {
    const writes = backend();
    const user = userEvent.setup();
    renderApp("/policies/web");
    const block = await screen.findByRole("button", { name: "Bloquear selecionadas" });
    expect(block).toBeDisabled();
    await user.click(screen.getByRole("checkbox", { name: "Selecionar grupo Adulto" }));
    expect(screen.getByText("2 selecionadas")).toBeInTheDocument();
    await user.click(block);
    expect(screen.getByRole("radio", { name: "Bloquear Conteúdo adulto" })).toBeChecked();
    expect(screen.getByRole("radio", { name: "Bloquear Jogos de azar" })).toBeChecked();
    expect(screen.getByRole("radio", { name: "Monitorar Jogos" })).toBeChecked();
    await user.click(screen.getByRole("checkbox", { name: "Selecionar Jogos" }));
    await user.click(screen.getByRole("button", { name: "Permitir selecionadas" }));
    await user.click(screen.getByRole("button", { name: "Publicar política" }));
    await waitFor(() => expect(writes).toHaveLength(1));
    expect(writes[0]?.web_filter?.category_actions).toEqual({ adult: "block", gambling: "block", games: "allow" });
  });

  it("marks a partly selected group as mixed, filters and collapses groups", async () => {
    backend();
    const user = userEvent.setup();
    renderApp("/policies/web");
    await user.click(await screen.findByRole("checkbox", { name: "Selecionar Jogos de azar" }));
    expect(screen.getByRole("checkbox", { name: "Selecionar grupo Adulto" })).toHaveProperty("indeterminate", true);
    await user.type(screen.getByRole("textbox", { name: "Buscar categoria" }), "azar");
    expect(screen.queryByRole("row", { name: "Jogos" })).toBeNull();
    expect(screen.getByRole("row", { name: "Jogos de azar" })).toBeInTheDocument();
    await user.clear(screen.getByRole("textbox", { name: "Buscar categoria" }));
    await user.click(screen.getByRole("button", { name: /Lazer/ }));
    expect(screen.queryByRole("row", { name: "Jogos" })).toBeNull();
    await user.click(screen.getByRole("button", { name: "Expandir todos os grupos" }));
    expect(screen.getByRole("row", { name: "Jogos" })).toBeInTheDocument();
  });

  it("shows unpublished changes, discards them and keeps edits across tabs", async () => {
    backend();
    const user = userEvent.setup();
    renderApp("/policies/web");
    expect(await screen.findByText("Sem alterações desde a versão publicada.")).toBeInTheDocument();
    await user.click(await screen.findByRole("radio", { name: "Bloquear Jogos" }));
    expect(screen.getByText("Alterações não publicadas")).toBeInTheDocument();
    await openTab(user, "SafeSearch");
    await openTab(user, "Categorias");
    expect(screen.getByRole("radio", { name: "Bloquear Jogos" })).toBeChecked();
    const summary = screen.getByRole("complementary", { name: "Resumo do perfil" });
    expect(within(summary).getByText("Bloquear").nextElementSibling).toHaveTextContent("1");
    await user.click(screen.getByRole("button", { name: "Descartar alterações" }));
    expect(await screen.findByRole("radio", { name: "Monitorar Jogos" })).toBeChecked();
    expect(screen.getByText("Sem alterações desde a versão publicada.")).toBeInTheDocument();
  });

  it("moves between tabs with the keyboard", async () => {
    backend();
    const user = userEvent.setup();
    renderApp("/policies/web");
    const first = await screen.findByRole("tab", { name: "Categorias" });
    first.focus();
    await user.keyboard("{ArrowRight}");
    expect(screen.getByRole("tab", { name: "Filtro de URL estático" })).toHaveAttribute("aria-selected", "true");
    await user.keyboard("{End}");
    expect(screen.getByRole("tab", { name: "Horários" })).toHaveFocus();
    await user.keyboard("{Home}{ArrowLeft}");
    expect(screen.getByRole("tab", { name: "Horários" })).toHaveAttribute("aria-selected", "true");
  });
});
