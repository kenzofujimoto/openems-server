import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { http, HttpResponse } from "msw";
import { server } from "@/mocks/node";
import { renderApp } from "@/test/render";

it("distinguishes monitored domains from blocks and filters monitoring separately", async () => {
  server.use(http.get("*/api/v1/events", () => HttpResponse.json([
    { id: "blocked", at: "2026-10-27T12:00:00Z", devid: "PC-1", kind: "web_block", detail: "blocked.example", action: "blocked", source: "dns", count: 2 },
    { id: "monitored", at: "2026-10-27T12:00:00Z", devid: "PC-1", kind: "web_monitor", detail: "observed.example", action: "monitored", source: "dns", count: 1 },
  ])));
  const user = userEvent.setup();
  renderApp("/events");
  const table = await screen.findByRole("table", { name: "Eventos dos endpoints" });
  await waitFor(() => expect(within(table).getByText("observed.example")).toBeInTheDocument());
  expect(within(table).getByText("Domínio monitorado")).toBeInTheDocument();
  expect(within(table).getByText("Site bloqueado")).toBeInTheDocument();
  await user.selectOptions(screen.getByRole("combobox", { name: "Tipo de evento" }), "web_monitor");
  expect(within(table).queryByText("blocked.example")).not.toBeInTheDocument();
  expect(within(table).getByText("observed.example")).toBeInTheDocument();
  expect(screen.getByText(/consultas DNS não comprovam visitas/i)).toBeInTheDocument();
});
