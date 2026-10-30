import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { server } from "@/mocks/node";
import { renderApp } from "@/test/render";

const profiles = ["BPO", "Default", "TI"].map((vdom, index) => ({ vdom, version: index + 1, digest: String(index).repeat(64), body: {} }));
const move = (hostname: string, target: string) => ({ id: `endpoint-${hostname.toLowerCase()}`, target_vdom: target, priority: 1, enabled: true,
  conditions: [{ field: "hostname", op: "equals", value: hostname }] });

function backend() {
  const rules: unknown[] = [];
  server.use(
    http.get("*/api/v1/profiles", () => HttpResponse.json(profiles)),
    http.post("*/api/v1/assignment_rules", async ({ request }) => { rules.push(await request.json()); return HttpResponse.json({ ok: true }); }),
  );
  return rules;
}

describe("endpoint group assignment", () => {
  it("moves one machine by choosing its group from a list, never by typing", async () => {
    const rules = backend();
    const user = userEvent.setup();
    renderApp("/endpoints");
    const select = await screen.findByRole("combobox", { name: "Grupo de NB-FINANCEIRO-01" });
    expect(within(select).getAllByRole("option").map((option) => option.textContent)).toEqual(["BPO", "Default", "TI"]);
    expect(select).toHaveValue("Default");
    await user.selectOptions(select, "TI");
    await waitFor(() => expect(rules).toEqual([move("NB-FINANCEIRO-01", "TI")]));
  });

  it("moves several selected machines at once", async () => {
    const rules = backend();
    const user = userEvent.setup();
    renderApp("/endpoints");
    await user.click(await screen.findByRole("checkbox", { name: "Selecionar NB-FINANCEIRO-01" }));
    await user.click(screen.getByRole("checkbox", { name: "Selecionar NB-AUDITORIA-07" }));
    expect(screen.getByText("2 selecionados")).toBeInTheDocument();
    await user.selectOptions(screen.getByRole("combobox", { name: "Mover selecionados para o grupo" }), "BPO");
    await user.click(screen.getByRole("button", { name: "Mover selecionados" }));
    await waitFor(() => expect(rules).toEqual([move("NB-FINANCEIRO-01", "BPO"), move("NB-AUDITORIA-07", "BPO")]));
    expect(await screen.findByRole("status")).toHaveTextContent("2 máquinas movidas para BPO");
  });

  it("picks the rule target group from a list in Groups and rules", async () => {
    backend();
    renderApp("/groups");
    const target = await screen.findByRole("combobox", { name: "Grupo de destino" });
    await within(target).findByRole("option", { name: "TI" });
    expect(within(target).getAllByRole("option").filter((option) => !(option as HTMLOptionElement).disabled).map((option) => option.textContent)).toEqual(["BPO", "Default", "TI"]);
  });
});
