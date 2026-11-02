/// <reference types="vitest/config" />
import { fileURLToPath, URL } from "node:url";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { rmSync } from "node:fs";
import { defineConfig, type Plugin } from "vite";

// The mock API worker lives in public/ for `vite --mode mock`; production must not ship it.
function stripMockWorker(): Plugin {
  return {
    name: "strip-mock-worker",
    apply: "build",
    closeBundle() {
      rmSync(fileURLToPath(new URL("../app/panel_dist/mockServiceWorker.js", import.meta.url)), { force: true });
    },
  };
}

// VITE_BRAND=rsm (modes "rsm" and "mock-rsm") builds the RSM Brasil edition: title, favicon and logo follow the brand.
function brandHtml(brand: string | undefined): Plugin {
  return {
    name: "brand-html",
    transformIndexHtml(html) {
      if (brand !== "rsm") return html;
      return html
        .replace("<title>OpenEMS</title>", "<title>RSM Endpoint Management</title>")
        .replace('type="image/svg+xml" href="/panel/brand/openems-mark.svg"', 'type="image/png" href="/panel/brand/rsm-logo.png"')
        .replace('<html lang="pt-BR">', '<html lang="pt-BR" data-brand="rsm">');
    },
  };
}

// Served by FastAPI under /panel/ while the legacy console remains at /console/.
export default defineConfig(({ mode }) => {
  const brand = process.env.VITE_BRAND ?? (mode === "rsm" || mode === "mock-rsm" ? "rsm" : "openems");
  return {
  base: "/panel/",
  define: { "import.meta.env.VITE_BRAND": JSON.stringify(brand) },
  plugins: [react(), tailwindcss(), stripMockWorker(), brandHtml(brand)],
  resolve: { alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) } },
  build: { outDir: "../app/panel_dist", emptyOutDir: true },
  server: { proxy: { "/api": "http://127.0.0.1:8013" } },
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    // Must exceed the 5 s Testing Library wait in setup.ts so a slow find fails with its own message.
    testTimeout: 15000,
    css: false,
    coverage: {
      provider: "v8",
      include: ["src/**/*.{ts,tsx}"],
      exclude: ["src/main.tsx", "src/mocks/browser.ts", "src/**/*.test.{ts,tsx}", "src/test/**"],
      thresholds: { lines: 80, functions: 80, branches: 80, statements: 80 },
    },
  },
  };
});
