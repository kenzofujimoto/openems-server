import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { server } from "@/mocks/node";
import { renderApp } from "@/test/render";

vi.setConfig({ testTimeout: 15000 });

function backend() {
  const writes: unknown[] = [];
  server.use(
    http.get("*/api/v1/profiles", () => HttpResponse.json([{ vdom: "Default", version: 1, digest: "a".repeat(64), body: {} }])),
    http.post("*/api/v1/profiles/:vdom", async ({ request }) => { writes.push(await request.json()); return HttpResponse.json({ vdom: "Default", version: 2, digest: "b".repeat(64), warnings: [] }); }),
    http.get("*/api/v1/endpoints/inventory", () => HttpResponse.json({ devid: "RSM-SP-001", collected_at: null, applications: [{ name: "Tool", path: "C:\\Tools\\tool.exe", publisher: "Publisher", sha256: "c".repeat(64), version: "1", running: false }], usb_devices: [] })),
  );
  return writes;
}

describe("control editor interactions", () => {
  it("edits and removes manual execution rules before publishing inventory publisher, name and network rules", async () => {
    const writes = backend(); const user = userEvent.setup(); renderApp("/policies/apps");
    await user.click(await screen.findByRole("button", { name: "Adicionar regra de execução" }));
    await user.selectOptions(screen.getByLabelText("Tipo da regra 1"), "path");
    await user.type(screen.getByLabelText("Valor da regra 1"), "C:\\Tools\\manual.exe");
    await user.type(screen.getByLabelText("Amostra local da regra 1"), "C:\\Tools\\manual.exe");
    await user.click(screen.getByRole("button", { name: "Adicionar regra de execução" }));
    await user.click(screen.getByRole("button", { name: "Remover regra 2" }));
    await user.click(await screen.findByRole("button", { name: "Bloquear editor de Tool" }));
    await user.click(screen.getByRole("button", { name: "Bloquear nome de Tool" }));
    await user.click(screen.getByRole("button", { name: "Bloquear rede de Tool" }));
    await user.click(screen.getByRole("button", { name: "Bloquear rede de Tool" }));
    await user.type(screen.getByLabelText("Processos a encerrar"), "tool.exe");
    await user.click(screen.getByRole("button", { name: "Publicar política" }));
    await waitFor(() => expect(writes).toHaveLength(1));
    expect(writes[0]).toMatchObject({ app_control: { blocked: ["tool.exe"], network_blocked: ["C:\\Tools\\tool.exe"], execution_rules: [{ id: "app-1", kind: "path", value: "C:\\Tools\\manual.exe" }, { id: "app-2", kind: "publisher", value: "Publisher" }, { id: "app-3", kind: "name", value: "tool.exe" }] } });
  });

  it("preserves USB selector edits and first-match priority through moves and removal", async () => {
    const writes = backend(); const user = userEvent.setup(); renderApp("/policies/usb");
    await user.click(await screen.findByRole("button", { name: "Adicionar regra USB" }));
    await user.selectOptions(screen.getByLabelText("Classe da regra USB 1"), "");
    await user.selectOptions(screen.getByLabelText("Ação da regra USB 1"), "read_only");
    await user.type(screen.getByLabelText("VID da regra USB 1"), "1234");
    await user.type(screen.getByLabelText("PID da regra USB 1"), "abcd");
    await user.type(screen.getByLabelText("Serial da regra USB 1"), "serial");
    await user.type(screen.getByLabelText("Instância da regra USB 1"), "device");
    await user.click(screen.getByRole("button", { name: "Adicionar regra USB" }));
    await user.click(screen.getByRole("button", { name: "Descer regra USB 1" }));
    expect(screen.getByLabelText("Serial da regra USB 2")).toHaveValue("serial");
    await user.click(screen.getByRole("button", { name: "Subir regra USB 2" }));
    await user.click(screen.getByRole("button", { name: "Remover regra USB 2" }));
    await user.selectOptions(screen.getByLabelText("Ação padrão para armazenamento"), "block");
    await user.click(screen.getByRole("button", { name: "Publicar política" }));
    await waitFor(() => expect(writes).toHaveLength(1));
    expect(writes[0]).toMatchObject({ usb_control: { default_action: "block", rules: [{ id: "usb-1", action: "read_only", vid: "1234", pid: "abcd", serial: "serial", instance_id: "device" }] } });
  });
});
