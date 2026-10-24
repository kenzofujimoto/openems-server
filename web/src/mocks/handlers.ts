import { http, HttpResponse } from "msw";
import { audit, categories, endpoints, events, overview, profiles, rules, session } from "./data";

export const handlers = [
  http.get("*/api/v1/auth/session", () => HttpResponse.json(session)),
  http.post("*/api/v1/auth/login", async ({ request }) => {
    const body = (await request.json()) as { username?: string; password?: string };
    if (body.username !== session.username || !body.password) {
      return HttpResponse.json({ detail: "invalid credentials" }, { status: 401 });
    }
    return HttpResponse.json({ ...session, token: "mock-token" });
  }),
  http.post("*/api/v1/auth/logout", () => HttpResponse.json({ ok: true })),
  http.get("*/api/v1/endpoints/index", () => HttpResponse.json(endpoints)),
  http.get("*/api/v1/stats/overview", () => HttpResponse.json(overview)),
  http.get("*/api/v1/events", () => HttpResponse.json(events)),
  http.get("*/api/v1/profiles", () => HttpResponse.json(profiles)),
  http.get("*/api/v1/assignment_rules", () => HttpResponse.json(rules)),
  http.get("*/api/v1/audit", () => HttpResponse.json(audit)),
  http.get("*/api/v1/categories", () => HttpResponse.json(categories)),
];
