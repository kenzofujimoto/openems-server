import { QueryClient } from "@tanstack/react-query";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "@/app/App";
import { BRAND } from "@/lib/brand";
import "./styles.css";

document.documentElement.dataset.brand = BRAND.id;
document.title = BRAND.title;

async function enableMocks(): Promise<void> {
  // Only `vite --mode mock` (or mock-rsm) bundles the mock API; production builds never do.
  if (import.meta.env.MODE !== "mock" && import.meta.env.MODE !== "mock-rsm") return;
  const { worker } = await import("@/mocks/browser");
  await worker.start({ serviceWorker: { url: `${import.meta.env.BASE_URL}mockServiceWorker.js` }, onUnhandledFrame: "bypass" });
}

const root = document.getElementById("root");
if (!root) throw new Error("Root element is missing");

const queryClient = new QueryClient({ defaultOptions: { queries: { retry: 1, refetchOnWindowFocus: false } } });

void enableMocks().then(() => {
  createRoot(root).render(
    <StrictMode>
      <App queryClient={queryClient} />
    </StrictMode>,
  );
});
