import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { server } from "@/mocks/node";
import { endpoints, overview } from "@/mocks/data";
import { renderApp } from "@/test/render";

describe("authentication", () => {
  it("sends unauthenticated visitors to the sign-in screen", async () => {
    server.use(http.get("*/api/v1/auth/session", () => HttpResponse.json({ detail: "authentication required" }, { status: 401 })));
    renderApp("/");
    expect(await screen.findByRole("heading", { name: "Entrar" })).toBeInTheDocument();
  });

  it("keeps credential errors visible and signs in with valid credentials", async () => {
    let authenticated = false;
    server.use(
      http.get("*/api/v1/auth/session", () =>
        authenticated
          ? HttpResponse.json({ username: "labadmin", role: "admin", csrf_token: "c" })
          : HttpResponse.json({ detail: "authentication required" }, { status: 401 }),
      ),
      http.post("*/api/v1/auth/login", async ({ request }) => {
        const body = (await request.json()) as { password: string };
        if (body.password !== "right") return HttpResponse.json({ detail: "invalid credentials" }, { status: 401 });
        authenticated = true;
        return HttpResponse.json({ username: "labadmin", role: "admin", csrf_token: "c", token: "t" });
      }),
    );
    const user = userEvent.setup();
    renderApp("/");
    await user.type(await screen.findByLabelText("Usuário"), "labadmin");
    await user.type(screen.getByLabelText("Senha"), "wrong");
    await user.click(screen.getByRole("button", { name: "Entrar" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Usuário ou senha inválidos");

    await user.clear(screen.getByLabelText("Senha"));
    await user.type(screen.getByLabelText("Senha"), "right");
    await user.click(screen.getByRole("button", { name: "Entrar" }));
    expect(await screen.findByRole("heading", { name: "Visão geral" })).toBeInTheDocument();
  });

  it("signs out through the user menu", async () => {
    let loggedOut = false;
    server.use(http.post("*/api/v1/auth/logout", ({ request }) => {
      loggedOut = request.headers.get("x-csrf-token") === "mock-csrf-token";
      return HttpResponse.json({ ok: true });
    }));
    const user = userEvent.setup();
    renderApp("/");
    await user.click(await screen.findByRole("button", { name: /labadmin/ }));
    await user.click(await screen.findByRole("menuitem", { name: "Sair" }));
    expect(await screen.findByRole("heading", { name: "Entrar" })).toBeInTheDocument();
    expect(loggedOut).toBe(true);
  });
});

describe("dashboard", () => {
  it("summarizes the fleet and recent activity", async () => {
    renderApp("/");
    expect(await screen.findByRole("heading", { name: "Visão geral" })).toBeInTheDocument();
    const online = await screen.findByRole("group", { name: "Endpoints online" });
    expect(within(online).getByText("9")).toBeInTheDocument();
    expect(within(screen.getByRole("group", { name: "Política aplicada" })).getByText("80%")).toBeInTheDocument();
    expect(within(screen.getByRole("group", { name: "Bloqueios (7 dias)" })).getByText("2.483")).toBeInTheDocument();
    expect(within(screen.getByRole("group", { name: "Erros de aplicação" })).getByText("1")).toBeInTheDocument();
    expect(await screen.findByText("tiktok.com", { selector: "[data-domain]" })).toBeInTheDocument();
    expect(screen.getByText("DNS settings reverted")).toBeInTheDocument();
  });

  it("shows a retryable error when statistics fail and keeps fleet data", async () => {
    let fail = true;
    server.use(http.get("*/api/v1/stats/overview", () => (fail ? HttpResponse.json({ detail: "boom" }, { status: 500 }) : undefined)));
    const user = userEvent.setup();
    renderApp("/");
    expect(await screen.findByText("Não foi possível carregar as estatísticas.")).toBeInTheDocument();
    expect(within(await screen.findByRole("group", { name: "Endpoints online" })).getByText("9")).toBeInTheDocument();
    fail = false;
    await user.click(screen.getByRole("button", { name: "Tentar de novo" }));
    await waitFor(() => expect(screen.queryByText("Não foi possível carregar as estatísticas.")).not.toBeInTheDocument());
  });

  it("explains statistics that the server does not provide yet instead of failing", async () => {
    server.use(
      http.get("*/api/v1/stats/overview", () => HttpResponse.json({ detail: "Not Found" }, { status: 404 })),
      http.get("*/api/v1/events", () => HttpResponse.json({ detail: "Not Found" }, { status: 404 })),
    );
    renderApp("/");
    expect(await screen.findByText(/Estatísticas de bloqueio chegam com o agente nativo/)).toBeInTheDocument();
    expect(screen.queryByText("Não foi possível carregar as estatísticas.")).not.toBeInTheDocument();
    expect(await screen.findByText("Nenhum evento recente.")).toBeInTheDocument();
  });
});

describe("endpoints", () => {
  it("lists devices, filters by search and opens the detail panel", async () => {
    const user = userEvent.setup();
    renderApp("/endpoints");
    expect(await screen.findByRole("heading", { name: "Endpoints" })).toBeInTheDocument();
    await screen.findByRole("button", { name: "Abrir RSM-SP-001" });
    expect(screen.getAllByRole("row")).toHaveLength(endpoints.length + 1);

    await user.type(screen.getByRole("searchbox", { name: "Buscar endpoints" }), "auditoria");
    expect(screen.getAllByRole("row")).toHaveLength(4);

    await user.click(screen.getByRole("button", { name: "Abrir RSM-SP-002" }));
    const dialog = await screen.findByRole("dialog", { name: "NB-AUDITORIA-07" });
    expect(within(dialog).getByText("enforcement failed: PermissionError")).toBeInTheDocument();
  });

  it("filters by policy status", async () => {
    const user = userEvent.setup();
    renderApp("/endpoints");
    await screen.findByRole("button", { name: "Abrir RSM-SP-001" });
    await user.click(screen.getByRole("button", { name: "Erro" }));
    expect(screen.getAllByRole("row")).toHaveLength(2);
  });

  it("renders hostile device data as plain text", async () => {
    const hostile = { ...endpoints[0], devid: "<img src=x onerror=alert(1)>", hostname: "<b>x</b>" };
    server.use(http.get("*/api/v1/endpoints/index", () => HttpResponse.json([hostile])));
    renderApp("/endpoints");
    expect(await screen.findByText("<img src=x onerror=alert(1)>")).toBeInTheDocument();
    expect(document.querySelector("img[src='x']")).toBeNull();
  });
});

describe("block log", () => {
  it("shows the category and count of web blocks next to the privacy notice", async () => {
    renderApp("/");
    expect(await screen.findByText("tiktok.com · Redes sociais · 12×")).toBeInTheDocument();
    // Single-count rows show only the domain (it also appears in the ranking, hence the selector).
    expect(screen.getByText("facebook.com", { selector: "p" })).toBeInTheDocument();
    expect(screen.getByText(/dado pessoal/)).toHaveTextContent("30 dias");
  });

  it("compares only what the server keeps history for", async () => {
    server.use(http.get("*/api/v1/stats/overview", () => HttpResponse.json({ ...overview, previous_period: { blocks: 1920 } })));
    renderApp("/");
    const blocks = await screen.findByRole("group", { name: "Bloqueios (7 dias)" });
    await waitFor(() => expect(blocks.querySelector("[data-tone]")).not.toBeNull());
    expect(screen.getByRole("group", { name: "Endpoints online" }).querySelector("[data-tone]")).toBeNull();
    expect(screen.getByRole("group", { name: "Erros de aplicação" }).querySelector("[data-tone]")).toBeNull();
  });

  it("warns when an agent cannot apply part of its policy", async () => {
    const user = userEvent.setup();
    renderApp("/endpoints");
    await user.click(await screen.findByRole("button", { name: "Abrir RSM-RJ-003" }));
    const dialog = await screen.findByRole("dialog", { name: "DT-RECEPCAO-02" });
    expect(within(dialog).getByText("Este agente não aplica parte da política")).toBeInTheDocument();
    expect(within(dialog).getByText(/Categorias de sites/)).toBeInTheDocument();
    expect(within(dialog).getByText(/DNS local/)).toBeInTheDocument();
    await user.keyboard("{Escape}");
    await user.click(screen.getByRole("button", { name: "Abrir RSM-SP-001" }));
    const current = await screen.findByRole("dialog", { name: "NB-FINANCEIRO-01" });
    expect(within(current).queryByText("Este agente não aplica parte da política")).toBeNull();
  });

  it("accepts endpoints from servers that do not report capabilities", async () => {
    const older: Record<string, unknown> = { ...endpoints[0] };
    delete older.missing_capabilities;
    server.use(http.get("*/api/v1/endpoints/index", () => HttpResponse.json([older])));
    renderApp("/endpoints");
    expect(await screen.findByRole("button", { name: "Abrir RSM-SP-001" })).toBeInTheDocument();
  });

  it("lists published categories by group with their attribution", async () => {
    renderApp("/policies/web");
    expect(await screen.findByRole("heading", { name: "Filtro web" })).toBeInTheDocument();
    const games = await screen.findByRole("listitem", { name: "Jogos" });
    expect(within(games).getByText("2.104 domínios")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Consumo de banda e lazer" })).toBeInTheDocument();
    expect(screen.getByText(/CC BY-SA 4.0/)).toBeInTheDocument();
    expect(screen.getByText(/F7/)).toBeInTheDocument();
  });

  it("explains when the server publishes no categories", async () => {
    server.use(http.get("*/api/v1/categories", () => HttpResponse.json({ detail: "Not Found" }, { status: 404 })));
    renderApp("/policies/web");
    expect(await screen.findByText("Nenhuma categoria publicada no servidor.")).toBeInTheDocument();
  });
});

describe("navigation", () => {
  it("marks upcoming modules with their roadmap phase", async () => {
    renderApp("/policies/usb");
    expect(await screen.findByRole("heading", { name: "Controle de USB" })).toBeInTheDocument();
    expect(screen.getByText(/F4/)).toBeInTheDocument();
  });
});
