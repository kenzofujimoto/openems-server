import "@testing-library/jest-dom/vitest";
import { cleanup, configure } from "@testing-library/react";
import { afterAll, afterEach, beforeAll } from "vitest";
import { server } from "@/mocks/node";

// Recharts measures its container; jsdom has no layout engine.
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}
globalThis.ResizeObserver = ResizeObserverStub as unknown as typeof ResizeObserver;

// Lazy routes plus MSW can exceed the 1 s default on a loaded runner (uninstall and controls specs
// failed intermittently on 2026-10-27); 5 s stays bounded and still fails a missing element.
configure({ asyncUtilTimeout: 5000 });

beforeAll(() => server.listen({ onUnhandledFrame: "error" }));
afterEach(() => {
  cleanup();
  server.resetHandlers();
});
afterAll(() => server.close());
