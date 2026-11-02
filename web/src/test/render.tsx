import { QueryClient } from "@tanstack/react-query";
import { createMemoryHistory } from "@tanstack/react-router";
import { render, screen } from "@testing-library/react";
import { App } from "@/app/App";

/** Render the full application at a route, backed by MSW mocks. */
export function renderApp(path = "/") {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const history = createMemoryHistory({ initialEntries: [path] });
  return { queryClient, ...render(<App queryClient={queryClient} history={history} />) };
}

/** Switch to a profile section; inactive tab panels stay mounted but hidden. */
export async function openTab(user: { click: (element: Element) => Promise<void> }, name: string) {
  await user.click(await screen.findByRole("tab", { name }));
}
