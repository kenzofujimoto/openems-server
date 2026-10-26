import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { server } from "@/mocks/node";
import { renderApp } from "@/test/render";

vi.setConfig({ testTimeout: 15000 });

function settings() {
  server.use(
    http.get("*/api/v1/settings", () => HttpResponse.json({ event_retention_days: 30, installer_available: true, installer_configuration: "operator", server_version: "0.2" })),
    http.get("*/api/v1/admins", () => HttpResponse.json([{ username: "other", role: "viewer" }, { username: "root", role: "superadmin" }])),
    http.get("*/api/v1/enrollment/invitations", () => HttpResponse.json([{ id: "a".repeat(64), vdom: "Default", remaining: 1, expires_at: "2026-10-26T00:00:00Z" }])),
    http.get("*/api/v1/installers/windows", () => HttpResponse.json({ available: true, filename: "agent.msi", size: 50, sha256: "a".repeat(64), download_url: "/api/v1/installers/windows/download", bundle_url: "/api/v1/installers/windows/bundle" })),
  );
}
afterEach(() => vi.restoreAllMocks());

describe("management mutation and recovery flows", () => {
  it("validates invitations, copies a one-time token and explains clipboard failure", async () => {
    settings();
    const user = userEvent.setup();
    renderApp("/settings");
    const uses = await screen.findByLabelText("Máximo de usos");
    await user.clear(uses); await user.type(uses, "0");
    await user.click(screen.getByRole("button", { name: "Gerar convite" }));
    expect(screen.getByRole("alert")).toHaveTextContent("1 a 1000");
    await user.clear(uses); await user.type(uses, "2");
    const ttl = screen.getByLabelText("Validade em segundos"); await user.clear(ttl); await user.type(ttl, "600");
    const group = screen.getByLabelText("Grupo do convite"); await user.clear(group); await user.type(group, "Remote");
    await user.click(screen.getByRole("button", { name: "Gerar convite" }));
    const copy = await screen.findByRole("button", { name: "Copiar convite" });
    await user.click(copy);
    expect(await screen.findByText("Convite copiado.")).toBeInTheDocument();
    vi.spyOn(navigator.clipboard, "writeText").mockRejectedValue(new Error("clipboard denied"));
    await user.click(copy);
    expect(await screen.findByText(/Selecione o token manualmente/)).toBeInTheDocument();
  });

  it("downloads a configured bundle and surfaces missing configuration separately from other failures", async () => {
    settings();
    const create = vi.fn().mockReturnValue("blob:installer"); const revoke = vi.fn();
    Object.defineProperty(URL, "createObjectURL", { configurable: true, value: create });
    Object.defineProperty(URL, "revokeObjectURL", { configurable: true, value: revoke });
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
    server.use(http.post("*/api/v1/installers/windows/bundle", () => new HttpResponse("package")));
    const user = userEvent.setup(); renderApp("/settings");
    expect(await screen.findByRole("link", { name: "Baixar MSI" })).toHaveAttribute("href", "/api/v1/installers/windows/download");
    await user.click(screen.getByRole("button", { name: "Baixar pacote configurado" }));
    await waitFor(() => expect(revoke).toHaveBeenCalledWith("blob:installer"));
    server.use(http.post("*/api/v1/installers/windows/bundle", () => HttpResponse.json({ detail: "not ready" }, { status: 503 })));
    await user.click(screen.getByRole("button", { name: "Baixar pacote configurado" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("URL pública");
    server.use(http.post("*/api/v1/enrollment/invitations", () => HttpResponse.error()));
    await user.click(screen.getByRole("button", { name: "Gerar convite" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Não foi possível gerar");
  });

  it("keeps failed invitation revocation open and allows cancellation", async () => {
    settings();
    server.use(http.delete("*/api/v1/enrollment/invitations/:id", () => HttpResponse.json({ detail: "offline" }, { status: 503 })));
    const user = userEvent.setup(); renderApp("/settings");
    await user.click(await screen.findByRole("button", { name: "Revogar convite de Default" }));
    await user.click(screen.getByRole("button", { name: "Confirmar revogação" }));
    expect(await screen.findByText("Não foi possível revogar o convite.")).toBeInTheDocument();
    expect(screen.getByRole("dialog")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Cancelar" }));
    expect(screen.queryByRole("dialog")).toBeNull();
  });

  it("edits a role without sending a blank password and requires confirmation before deleting", async () => {
    settings();
    let saved: unknown; let removed = false;
    server.use(
      http.put("*/api/v1/admins/:username", async ({ request }) => { saved = await request.json(); return HttpResponse.json({ username: "other", role: "admin" }); }),
      http.delete("*/api/v1/admins/:username", () => { removed = true; return HttpResponse.json({ removed: "other" }); }),
    );
    const user = userEvent.setup(); renderApp("/settings");
    await user.click(await screen.findByRole("button", { name: "Editar administrador other" }));
    expect(screen.getByLabelText("Novo usuário")).toBeDisabled();
    await user.selectOptions(screen.getByLabelText("Papel"), "admin");
    await user.click(screen.getByRole("button", { name: "Salvar administrador" }));
    expect(await screen.findByText("Administrador salvo.")).toBeInTheDocument();
    expect(saved).toEqual({ role: "admin" });
    await user.click(screen.getByRole("button", { name: "Excluir administrador other" }));
    expect(removed).toBe(false);
    await user.click(screen.getByRole("button", { name: "Cancelar" }));
    expect(removed).toBe(false);
    await user.click(screen.getByRole("button", { name: "Excluir administrador other" }));
    await user.click(screen.getByRole("button", { name: "Confirmar exclusão do administrador" }));
    await waitFor(() => expect(removed).toBe(true));
    await user.click(screen.getByRole("button", { name: "Novo administrador" }));
    expect(screen.getByLabelText("Novo usuário")).toHaveValue("");
    expect(screen.queryByRole("button", { name: "Editar administrador root" })).toBeNull();
  });

  it("validates administrators and explains protected-account and save failures", async () => {
    settings();
    const user = userEvent.setup(); renderApp("/settings");
    await user.click(await screen.findByRole("button", { name: "Criar administrador" }));
    expect(screen.getByRole("alert")).toHaveTextContent("usuário e senha");
    await user.type(screen.getByLabelText("Novo usuário"), "duplicate");
    await user.type(screen.getByLabelText("Senha inicial"), "test-password");
    server.use(http.post("*/api/v1/admins", () => HttpResponse.json({ detail: "duplicate" }, { status: 409 })));
    await user.click(screen.getByRole("button", { name: "Criar administrador" }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("último administrador"));
    server.use(http.post("*/api/v1/admins", () => HttpResponse.error()));
    await user.click(screen.getByRole("button", { name: "Criar administrador" }));
    await waitFor(() => expect(screen.getByRole("alert")).toHaveTextContent("permissões"));
    server.use(http.delete("*/api/v1/admins/:username", () => HttpResponse.json({ detail: "protected" }, { status: 409 })));
    await user.click(screen.getByRole("button", { name: "Excluir administrador other" }));
    await user.click(screen.getByRole("button", { name: "Confirmar exclusão do administrador" }));
    expect(await screen.findByText("Não foi possível concluir. Tente de novo.")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Cancelar" }));
    expect(screen.getByRole("alert")).toHaveTextContent("própria conta, o superadministrador");
  });

  it("imports SAML metadata, clears it on success and reports unsupported and invalid configurations", async () => {
    settings();
    const user = userEvent.setup(); renderApp("/settings");
    const xml = await screen.findByLabelText("Metadados XML do provedor");
    const prefix = screen.getByLabelText("Grupo SAML"); await user.clear(prefix); await user.type(prefix, "Remote");
    await user.click(xml); await user.paste("<EntityDescriptor/>");
    server.use(http.post("*/fct_saml/parse_remote_metadata", () => HttpResponse.json({ detail: "unsupported" }, { status: 503 })));
    await user.click(screen.getByRole("button", { name: "Importar provedor SAML" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("SAML não está configurado");
    server.use(http.post("*/fct_saml/parse_remote_metadata", () => HttpResponse.json({ detail: "bad XML" }, { status: 422 })));
    await user.click(screen.getByRole("button", { name: "Importar provedor SAML" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Confira o XML");
    server.use(http.post("*/fct_saml/parse_remote_metadata", () => HttpResponse.json({ prefix: "Remote", idp_entity_id: "https://idp.example", sso_url: "https://idp.example/sso" })));
    await user.click(screen.getByRole("button", { name: "Importar provedor SAML" }));
    expect(await screen.findByText("Provedor importado: https://idp.example")).toBeInTheDocument();
    expect(xml).toHaveValue("");
    expect(screen.getByRole("link", { name: "Metadados públicos do servidor" })).toHaveAttribute("href", "/fct_saml/Remote/metadata");
  });

  it.each([["/events", "/api/v1/events", "eventos"], ["/audit", "/api/v1/audit", "auditoria"]])("recovers %s after a failed request", async (route, path, label) => {
    server.use(http.get(`*${path}`, () => HttpResponse.error()));
    const user = userEvent.setup(); renderApp(route);
    const error = await screen.findByText(`Não foi possível carregar ${label === "auditoria" ? "a auditoria" : "os eventos"}.`);
    const notice = error.parentElement;
    if (!notice) throw new Error("Expected an error notice container");
    const retry = within(notice).getByRole("button");
    server.use(http.get(`*${path}`, () => HttpResponse.json([])));
    await user.click(retry);
    await waitFor(() => expect(error).not.toBeInTheDocument());
  });
});
