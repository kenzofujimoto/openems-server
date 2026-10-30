import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { server } from "@/mocks/node";
import { renderApp } from "@/test/render";

const legacy = { web_filter: { allowed: ["safe.example"], blocked: ["*.games.example"] }, app_control: { blocked: ["old.exe"] } };
function backend() {
  const writes: unknown[] = [];
  server.use(http.get("*/api/v1/profiles", () => HttpResponse.json([{ vdom: "Default", version: 4, digest: "a".repeat(64), body: legacy }])),
    http.post("*/api/v1/profiles/:vdom", async ({ request }) => { writes.push(await request.json()); return HttpResponse.json({ vdom: "Default", version: 5, digest: "b".repeat(64), warnings: [] }); }));
  return writes;
}

it("migrates allowed rows first, reorders entries and preserves other sections when publishing", async () => {
  const writes = backend(); const user = userEvent.setup(); renderApp("/policies/web");
  const table = await screen.findByRole("table", { name: "Regras de domínio" });
  expect(within(table).getAllByRole("row")[1]).toHaveTextContent("safe.example");
  await user.click(screen.getByRole("button", { name: "Mover games.example para cima" }));
  await user.click(screen.getByRole("button", { name: "Publicar política" }));
  await waitFor(() => expect(writes).toHaveLength(1));
  expect(writes[0]).toMatchObject({ app_control: legacy.app_control, web_filter: { domain_rules: [
    { domain: "games.example", type: "wildcard", action: "block" },
    { domain: "safe.example", type: "simple", action: "allow" },
  ] } });
  expect((writes[0] as {web_filter: object}).web_filter).not.toHaveProperty("allowed");
});

it("adds and edits individual domain rules with explicit match type and monitoring", async () => {
  const writes = backend(); const user = userEvent.setup(); renderApp("/policies/web");
  await user.click(await screen.findByRole("button", { name: "Adicionar domínio" }));
  const dialog = screen.getByRole("dialog", { name: "Adicionar domínio" });
  await user.type(within(dialog).getByLabelText("Domínio"), "watch.example");
  await user.selectOptions(within(dialog).getByLabelText("Tipo"), "wildcard");
  await user.selectOptions(within(dialog).getByLabelText("Ação"), "monitor");
  await user.click(within(dialog).getByRole("button", { name: "Salvar domínio" }));
  await user.click(screen.getByRole("button", { name: "Editar watch.example" }));
  const edit = screen.getByRole("dialog", { name: "Editar domínio" });
  await user.clear(within(edit).getByLabelText("Domínio")); await user.type(within(edit).getByLabelText("Domínio"), "video.example");
  await user.click(within(edit).getByRole("button", { name: "Salvar domínio" }));
  await user.click(screen.getByRole("button", { name: "Publicar política" }));
  await waitFor(() => expect(writes).toHaveLength(1));
  expect(writes[0]).toMatchObject({web_filter: {domain_rules: expect.arrayContaining([{domain:"video.example",type:"wildcard",action:"monitor"}])}});
});

it("previews CSV and rejects invalid rows without partial imports or automatic publication", async () => {
  const writes = backend(); const user = userEvent.setup(); renderApp("/policies/web");
  const upload = await screen.findByLabelText("Importar CSV");
  await user.upload(upload, new File(["domain,type,action\r\nvideo.example,wildcard,log\r\nhttps://bad.example,simple,block"], "bad.csv", { type: "text/csv" }));
  expect(await screen.findByRole("alert")).toHaveTextContent(/linha 3/i);
  expect(screen.queryByText("video.example")).not.toBeInTheDocument();
  await user.upload(upload, new File(["domain,type,action\r\nvideo.example,wildcard,log"], "valid.csv", {type:"text/csv"}));
  const preview = await screen.findByRole("dialog", {name:"Prévia da importação"});
  expect(preview).toHaveTextContent("video.example"); expect(writes).toHaveLength(0);
  await user.click(within(preview).getByRole("button", {name:"Importar 1 domínio"}));
  expect(within(screen.getByRole("table", {name:"Regras de domínio"})).getByText("video.example")).toBeInTheDocument();
  expect(writes).toHaveLength(0);
});
