import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { server } from "@/mocks/node";
import { endpoints, session } from "@/mocks/data";
import { renderApp } from "@/test/render";

const OFFICE = {
  id: "sp", name: "Escritório SP", cidrs: ["192.168.1.0/24"], gateway_macs: ["00:11:22:33:44:55"],
  dns_suffixes: [], public_cidrs: [], probe: null,
};

function locationServer(initial = [OFFICE]) {
  const locations = [...initial];
  const mappings: Array<{ vdom: string; location_id: string; inside_vdom: string }> = [];
  const writes: Array<{ method: string; body: unknown; csrf: string | null }> = [];
  server.use(
    http.get("*/api/v1/network_locations", () => HttpResponse.json(locations)),
    http.post("*/api/v1/network_locations", async ({ request }) => {
      const body = (await request.json()) as typeof OFFICE;
      writes.push({ method: "POST", body, csrf: request.headers.get("x-csrf-token") });
      locations.push(body);
      return HttpResponse.json(body);
    }),
    http.put("*/api/v1/network_locations/:id", async ({ request, params }) => {
      const body = (await request.json()) as typeof OFFICE;
      writes.push({ method: "PUT", body, csrf: request.headers.get("x-csrf-token") });
      locations.splice(locations.findIndex((item) => item.id === params.id), 1, body);
      return HttpResponse.json(body);
    }),
    http.delete("*/api/v1/network_locations/:id", ({ params }) => {
      locations.splice(locations.findIndex((item) => item.id === params.id), 1);
      return HttpResponse.json({ ok: true });
    }),
    http.get("*/api/v1/location_policies", () => HttpResponse.json(mappings)),
    http.post("*/api/v1/location_policies", async ({ request }) => {
      const body = (await request.json()) as (typeof mappings)[number];
      writes.push({ method: "POST", body, csrf: request.headers.get("x-csrf-token") });
      mappings.push(body);
      return HttpResponse.json(body);
    }),
    http.delete("*/api/v1/location_policies", ({ request }) => {
      const query = new URL(request.url).searchParams;
      mappings.splice(mappings.findIndex((item) => item.vdom === query.get("vdom") && item.location_id === query.get("location_id")), 1);
      return HttpResponse.json({ ok: true });
    }),
  );
  return { writes, locations, mappings };
}

describe("network locations", () => {
  it("requires two local signal kinds, creates a location and sends CSRF", async () => {
    const backend = locationServer([]);
    const user = userEvent.setup();
    renderApp("/policies/locations");
    await user.click(await screen.findByRole("button", { name: "Novo local" }));
    const dialog = await screen.findByRole("dialog", { name: "Novo local de rede" });
    const fields: Array<[string, string]> = [["Identificador", "rj"], ["Nome", "Escritório RJ"], ["Faixas de IP local (CIDR)", "192.168.1.0/24"]];
    for (const [label, value] of fields) {
      await user.click(within(dialog).getByLabelText(label));
      await user.paste(value);
    }
    await user.click(within(dialog).getByRole("button", { name: "Salvar local" }));
    expect(within(dialog).getByRole("alert")).toHaveTextContent("pelo menos dois tipos de sinais locais");
    expect(backend.writes).toEqual([]);
    await user.click(within(dialog).getByLabelText("MACs dos gateways"));
    await user.paste("00:11:22:33:44:55");
    await user.click(within(dialog).getByRole("button", { name: "Salvar local" }));
    expect(await screen.findByRole("row", { name: /Escritório RJ/ })).toBeInTheDocument();
    expect(backend.writes).toEqual([{ method: "POST", body: { ...OFFICE, id: "rj", name: "Escritório RJ" }, csrf: "mock-csrf-token" }]);
  });

  it("edits an existing location while keeping its identifier", async () => {
    const backend = locationServer();
    const user = userEvent.setup();
    renderApp("/policies/locations");
    await user.click(await screen.findByRole("button", { name: "Editar Escritório SP" }));
    const dialog = await screen.findByRole("dialog", { name: "Editar local de rede" });
    expect(within(dialog).getByLabelText("Identificador")).toBeDisabled();
    await user.clear(within(dialog).getByLabelText("Nome"));
    await user.click(within(dialog).getByLabelText("Nome"));
    await user.paste("Sede SP");
    await user.click(within(dialog).getByRole("button", { name: "Salvar local" }));
    expect(await screen.findByRole("row", { name: /Sede SP/ })).toBeInTheDocument();
    expect(backend.writes[0]).toMatchObject({ method: "PUT", body: { id: "sp", name: "Sede SP" }, csrf: "mock-csrf-token" });
  });

  it("accepts the office public range as the only signal and rejects an invalid CIDR", async () => {
    const backend = locationServer([]);
    const user = userEvent.setup();
    renderApp("/policies/locations");
    await user.click(await screen.findByRole("button", { name: "Novo local" }));
    const dialog = await screen.findByRole("dialog", { name: "Novo local de rede" });
    await user.click(within(dialog).getByLabelText("Identificador"));
    await user.paste("vpn");
    await user.click(within(dialog).getByLabelText("Nome"));
    await user.paste("VPN corporativa");
    const publicRange = within(dialog).getByLabelText("Faixas de IP público (CIDR)");
    await user.click(publicRange);
    await user.paste("not-a-network");
    await user.click(within(dialog).getByRole("button", { name: "Salvar local" }));
    expect(within(dialog).getByRole("alert")).toHaveTextContent("faixas CIDR válidas");
    expect(backend.writes).toEqual([]);
    await user.clear(publicRange);
    await user.click(publicRange);
    await user.paste("203.0.113.0/24");
    await user.click(within(dialog).getByRole("button", { name: "Salvar local" }));
    expect(await screen.findByRole("row", { name: /VPN corporativa/ })).toBeInTheDocument();
    expect(backend.writes[0]).toMatchObject({ body: { public_cidrs: ["203.0.113.0/24"], cidrs: [], probe: null } });
  });

  it("requires the complete certificate signal and combines it with the DNS suffix", async () => {
    const backend = locationServer([]);
    const user = userEvent.setup();
    renderApp("/policies/locations");
    await user.click(await screen.findByRole("button", { name: "Novo local" }));
    const dialog = await screen.findByRole("dialog", { name: "Novo local de rede" });
    const fields: Array<[string, string]> = [["Identificador", "tls"], ["Nome", "Sede TLS"], ["Sufixos DNS", "Corp.Example."], ["Host interno (TLS)", "intranet.corp.example"]];
    for (const [label, value] of fields) {
      await user.click(within(dialog).getByLabelText(label));
      await user.paste(value);
    }
    await user.click(within(dialog).getByRole("button", { name: "Salvar local" }));
    expect(within(dialog).getByRole("alert")).toHaveTextContent("SHA-256 do certificado");
    expect(backend.writes).toEqual([]);
    await user.click(within(dialog).getByLabelText("SHA-256 do certificado"));
    await user.paste("AB".repeat(32));
    await user.click(within(dialog).getByRole("button", { name: "Salvar local" }));
    expect(await screen.findByRole("row", { name: /Sede TLS/ })).toBeInTheDocument();
    expect(backend.writes[0]).toMatchObject({ body: { probe: { host: "intranet.corp.example", port: 443, sha256: "ab".repeat(32) } } });
  });

  it("only deletes a location after explaining the outside-policy fallback", async () => {
    const backend = locationServer();
    const user = userEvent.setup();
    renderApp("/policies/locations");
    await user.click(await screen.findByRole("button", { name: "Excluir Escritório SP" }));
    const dialog = await screen.findByRole("dialog", { name: "Excluir local de rede" });
    expect(within(dialog).getByText(/política de fora/)).toBeInTheDocument();
    expect(backend.locations).toHaveLength(1);
    await user.click(within(dialog).getByRole("button", { name: "Confirmar exclusão" }));
    await waitFor(() => expect(screen.queryByRole("row", { name: /Escritório SP/ })).toBeNull());
    expect(backend.locations).toHaveLength(0);
  });

  it("assigns an inside profile to a group and removes the mapping", async () => {
    const backend = locationServer();
    const user = userEvent.setup();
    renderApp("/policies/locations");
    const mapping = await screen.findByRole("form", { name: "Perfil dentro do local" });
    await user.selectOptions(within(mapping).getByRole("combobox", { name: "Grupo" }), "Strict");
    await user.selectOptions(within(mapping).getByRole("combobox", { name: "Local" }), "sp");
    await user.selectOptions(within(mapping).getByRole("combobox", { name: "Perfil interno" }), "Default");
    await user.click(within(mapping).getByRole("button", { name: "Salvar mapeamento" }));
    const row = await screen.findByRole("row", { name: /Strict.*Escritório SP.*Default/ });
    expect(backend.writes[0]).toMatchObject({ body: { vdom: "Strict", location_id: "sp", inside_vdom: "Default" }, csrf: "mock-csrf-token" });
    await user.click(within(row).getByRole("button", { name: "Remover mapeamento de Strict em Escritório SP" }));
    await waitFor(() => expect(screen.queryByRole("row", { name: /Strict.*Escritório SP.*Default/ })).toBeNull());
    expect(backend.mappings).toHaveLength(0);
  });

  it("keeps the mapping selection valid after its selected location is deleted", async () => {
    const backend = locationServer([OFFICE, { ...OFFICE, id: "rj", name: "Escritório RJ" }]);
    const user = userEvent.setup();
    renderApp("/policies/locations");
    const mapping = await screen.findByRole("form", { name: "Perfil dentro do local" });
    const select = within(mapping).getByRole("combobox", { name: "Local" });
    await user.selectOptions(select, "rj");
    await user.selectOptions(select, "sp");
    await user.click(screen.getByRole("button", { name: "Excluir Escritório SP" }));
    const dialog = await screen.findByRole("dialog", { name: "Excluir local de rede" });
    await user.click(within(dialog).getByRole("button", { name: "Confirmar exclusão" }));
    await waitFor(() => expect(within(select).queryByRole("option", { name: "Escritório SP" })).toBeNull());
    expect(select).toHaveValue("rj");
    await user.click(within(mapping).getByRole("button", { name: "Salvar mapeamento" }));
    await waitFor(() => expect(backend.writes[0]).toMatchObject({ body: { location_id: "rj" } }));
  });

  it("allows viewers to read locations without exposing writes", async () => {
    locationServer();
    server.use(http.get("*/api/v1/auth/session", () => HttpResponse.json({ ...session, role: "viewer" })));
    renderApp("/policies/locations");
    expect(await screen.findByRole("row", { name: /Escritório SP/ })).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Novo local" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Editar Escritório SP" })).toBeNull();
    expect(screen.queryByRole("form", { name: "Perfil dentro do local" })).toBeNull();
  });

  it("keeps failed writes in the form so the operator can retry", async () => {
    locationServer();
    server.use(http.put("*/api/v1/network_locations/:id", () => HttpResponse.json({ detail: "failed" }, { status: 500 })));
    const user = userEvent.setup();
    renderApp("/policies/locations");
    await user.click(await screen.findByRole("button", { name: "Editar Escritório SP" }));
    const dialog = await screen.findByRole("dialog", { name: "Editar local de rede" });
    await user.click(within(dialog).getByRole("button", { name: "Salvar local" }));
    expect(await within(dialog).findByRole("alert")).toHaveTextContent("Não foi possível salvar o local");
    expect(within(dialog).getByLabelText("Nome")).toHaveValue("Escritório SP");
  });

  it("retries a failed locations request", async () => {
    locationServer();
    let fail = true;
    server.use(http.get("*/api/v1/network_locations", () => fail ? HttpResponse.json({ detail: "offline" }, { status: 503 }) : undefined));
    const user = userEvent.setup();
    renderApp("/policies/locations");
    expect(await screen.findByText("Não foi possível carregar os locais de rede.")).toBeInTheDocument();
    fail = false;
    await user.click(screen.getByRole("button", { name: "Tentar de novo" }));
    expect(await screen.findByRole("row", { name: /Escritório SP/ })).toBeInTheDocument();
  });

  it("shows the acknowledged location on the device sheet", async () => {
    server.use(http.get("*/api/v1/endpoints/index", () => HttpResponse.json([{ ...endpoints[0], location: "sp", location_name: "Escritório SP" }])));
    const user = userEvent.setup();
    renderApp("/endpoints");
    await user.click(await screen.findByRole("button", { name: "Abrir RSM-SP-001" }));
    const dialog = await screen.findByRole("dialog", { name: "NB-FINANCEIRO-01" });
    expect(within(dialog).getByText("Local de rede")).toBeInTheDocument();
    expect(within(dialog).getByText("Escritório SP")).toBeInTheDocument();
  });
});
