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

// Served by FastAPI under /panel/ while the legacy console remains at /console/.
export default defineConfig({
  base: "/panel/",
  plugins: [react(), tailwindcss(), stripMockWorker()],
  resolve: { alias: { "@": fileURLToPath(new URL("./src", import.meta.url)) } },
  build: { outDir: "../app/panel_dist", emptyOutDir: true },
  server: { proxy: { "/api": "http://127.0.0.1:8013" } },
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: ["./src/test/setup.ts"],
    css: false,
    coverage: {
      provider: "v8",
      include: ["src/**/*.{ts,tsx}"],
      exclude: ["src/main.tsx", "src/mocks/browser.ts", "src/**/*.test.{ts,tsx}", "src/test/**"],
      thresholds: { lines: 80, functions: 80, branches: 80, statements: 80 },
    },
  },
});
