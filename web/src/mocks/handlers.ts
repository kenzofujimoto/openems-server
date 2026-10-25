import { http, HttpResponse } from "msw";
import { locationPolicySchema, networkLocationSchema } from "@/lib/schemas";
import { audit, categories, endpoints, events, locationPolicies, networkLocations, overview, profiles, rules, session, uninstallReleases } from "./data";

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
  http.get("*/api/v1/uninstall_release", () => HttpResponse.json(uninstallReleases)),
  http.post("*/api/v1/uninstall_release", async ({ request }) => HttpResponse.json(await request.json())),
  http.post("*/api/v1/endpoints/uninstall_code", async ({ request }) => {
    const { devid } = (await request.json()) as { devid: string };
    return HttpResponse.json({ devid, counter: 1, code: "QZJ9T-4Y3D1" });
  }),
  http.post("*/api/v1/endpoints/uninstall_secret/reset", () => HttpResponse.json({ ok: true })),
  http.get("*/api/v1/network_locations", () => HttpResponse.json(networkLocations)),
  http.post("*/api/v1/network_locations", async ({ request }) => {
    const body = networkLocationSchema.safeParse(await request.json());
    if (!body.success) return HttpResponse.json({ detail: "invalid location" }, { status: 422 });
    if (networkLocations.some((item) => item.id === body.data.id)) return HttpResponse.json({ detail: "location already exists" }, { status: 409 });
    networkLocations.push(body.data);
    networkLocations.sort((a, b) => a.name.localeCompare(b.name));
    return HttpResponse.json(body.data);
  }),
  http.put("*/api/v1/network_locations/:id", async ({ request, params }) => {
    const body = networkLocationSchema.safeParse(await request.json());
    if (!body.success || body.data.id !== params.id) return HttpResponse.json({ detail: "invalid location" }, { status: 422 });
    const index = networkLocations.findIndex((item) => item.id === params.id);
    if (index < 0) return HttpResponse.json({ detail: "unknown location" }, { status: 404 });
    networkLocations[index] = body.data;
    networkLocations.sort((a, b) => a.name.localeCompare(b.name));
    return HttpResponse.json(body.data);
  }),
  http.delete("*/api/v1/network_locations/:id", ({ params }) => {
    const index = networkLocations.findIndex((item) => item.id === params.id);
    if (index < 0) return HttpResponse.json({ detail: "unknown location" }, { status: 404 });
    networkLocations.splice(index, 1);
    for (let index = locationPolicies.length - 1; index >= 0; index--) {
      if (locationPolicies[index]?.location_id === params.id) locationPolicies.splice(index, 1);
    }
    return HttpResponse.json({ ok: true });
  }),
  http.get("*/api/v1/location_policies", () => HttpResponse.json(locationPolicies)),
  http.post("*/api/v1/location_policies", async ({ request }) => {
    const body = locationPolicySchema.safeParse(await request.json());
    if (!body.success) return HttpResponse.json({ detail: "invalid mapping" }, { status: 422 });
    const index = locationPolicies.findIndex((item) => item.vdom === body.data.vdom && item.location_id === body.data.location_id);
    if (index < 0) locationPolicies.push(body.data);
    else locationPolicies[index] = body.data;
    return HttpResponse.json(body.data);
  }),
  http.delete("*/api/v1/location_policies", ({ request }) => {
    const query = new URL(request.url).searchParams;
    const index = locationPolicies.findIndex((item) => item.vdom === query.get("vdom") && item.location_id === query.get("location_id"));
    if (index >= 0) locationPolicies.splice(index, 1);
    return HttpResponse.json({ ok: true });
  }),
];
