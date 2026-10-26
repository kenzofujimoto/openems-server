import { http, HttpResponse } from "msw";
import { z } from "zod";
import { locationPolicySchema, networkLocationSchema } from "@/lib/schemas";
import { policyBodySchema, ruleSchema } from "@/lib/management";
import { audit, categories, endpoints, events, locationPolicies, networkLocations, overview, profiles, rules, session, uninstallReleases } from "./data";

const administrators: Array<{ username: string; role: "admin" | "viewer" }> = [{ username: session.username, role: "admin" }];
const invitations: Array<{ id: string; vdom: string; remaining: number; expires_at: string }> = [];
async function digest(value: string) { return [...new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value)))].map((byte) => byte.toString(16).padStart(2, "0")).join(""); }

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
  http.post("*/api/v1/profiles/:vdom", async ({ request, params }) => {
    const body = policyBodySchema.safeParse(await request.json());
    if (!body.success) return HttpResponse.json({ detail: "invalid profile" }, { status: 422 });
    const vdom = String(params.vdom);
    const old = profiles.find((profile) => profile.vdom === vdom);
    if (request.headers.get("if-match") && old?.digest !== request.headers.get("if-match")) return HttpResponse.json({ detail: "profile changed" }, { status: 412 });
    const profile = { vdom, body: body.data, version: (old?.version ?? 0) + 1, digest: await digest(JSON.stringify(body.data)), updated_at: new Date().toISOString() };
    if (old) profiles[profiles.indexOf(old)] = profile; else profiles.push(profile);
    return HttpResponse.json({ ...profile, warnings: [] });
  }),
  http.get("*/api/v1/assignment_rules", () => HttpResponse.json(rules)),
  http.post("*/api/v1/assignment_rules", async ({ request }) => {
    const parsed = ruleSchema.safeParse(await request.json());
    if (!parsed.success) return HttpResponse.json({ detail: "invalid rule" }, { status: 422 });
    const index = rules.findIndex((rule) => rule.id === parsed.data.id);
    if (index < 0) rules.push(parsed.data); else rules[index] = parsed.data;
    return HttpResponse.json(parsed.data);
  }),
  http.delete("*/api/v1/assignment_rules/:id", ({ params }) => { const index = rules.findIndex((rule) => rule.id === params.id); if (index >= 0) rules.splice(index, 1); return HttpResponse.json({ ok: true }); }),
  http.get("*/api/v1/audit", () => HttpResponse.json(audit)),
  http.get("*/api/v1/categories", () => HttpResponse.json(categories)),
  http.get("*/api/v1/endpoints/inventory", ({ request }) => HttpResponse.json({ devid: new URL(request.url).searchParams.get("devid") ?? "", collected_at: null, applications: [], usb_devices: [] })),
  http.post("*/api/v1/endpoints/revoke", async ({ request }) => { const value = z.object({ devid: z.string() }).parse(await request.json()); const endpoint = endpoints.find((endpoint) => endpoint.devid === value.devid); if (endpoint) endpoint.status = "unregistered"; return HttpResponse.json({ ok: true }); }),
  http.post("*/api/v1/endpoints/credentials/rotate", () => HttpResponse.json({ device_token: `mock-device-${crypto.randomUUID()}` })),
  http.get("*/api/v1/settings", () => HttpResponse.json({ event_retention_days: 30, installer_available: false, installer_configuration: "operator", server_version: "0.2.0" })),
  http.get("*/api/v1/installers/windows", () => HttpResponse.json({ available: false })),
  http.get("*/api/v1/admins", () => HttpResponse.json(administrators)),
  http.post("*/api/v1/admins", async ({ request }) => {
    const parsed = z.object({ username: z.string().min(1), password: z.string().min(1), role: z.enum(["viewer", "admin"]) }).safeParse(await request.json());
    if (!parsed.success) return HttpResponse.json({ detail: "invalid administrator" }, { status: 422 });
    if (administrators.some((administrator) => administrator.username === parsed.data.username)) return HttpResponse.json({ detail: "duplicate" }, { status: 409 });
    const administrator = { username: parsed.data.username, role: parsed.data.role };
    administrators.push(administrator); return HttpResponse.json(administrator);
  }),
  http.put("*/api/v1/admins/:username", async ({ request, params }) => {
    const body = z.object({ role: z.enum(["viewer", "admin"]) }).safeParse(await request.json());
    const administrator = administrators.find((administrator) => administrator.username === params.username);
    if (!administrator || !body.success) return HttpResponse.json({ detail: "unknown administrator" }, { status: 404 });
    administrator.role = body.data.role; return HttpResponse.json(administrator);
  }),
  http.delete("*/api/v1/admins/:username", ({ params }) => { const index = administrators.findIndex((administrator) => administrator.username === params.username); if (index >= 0) administrators.splice(index, 1); return HttpResponse.json({ removed: params.username }); }),
  http.get("*/api/v1/enrollment/invitations", () => HttpResponse.json(invitations)),
  http.post("*/api/v1/enrollment/invitations", async ({ request }) => {
    const payload = z.object({ vdom: z.string(), max_uses: z.number(), ttl_seconds: z.number() }).parse(await request.json());
    const invitation = `mock-invitation-${crypto.randomUUID()}`;
    invitations.push({ id: await digest(invitation), vdom: payload.vdom, remaining: payload.max_uses, expires_at: new Date(Date.now() + payload.ttl_seconds * 1000).toISOString() });
    return HttpResponse.json({ ...payload, invitation });
  }),
  http.delete("*/api/v1/enrollment/invitations/:id", ({ params }) => { const index = invitations.findIndex((invitation) => invitation.id === params.id); if (index >= 0) invitations.splice(index, 1); return HttpResponse.json({ removed: params.id }); }),
  http.post("*/fct_saml/parse_remote_metadata", async ({ request }) => { const payload = z.object({ prefix: z.string(), metadata: z.string() }).parse(await request.json()); return HttpResponse.json({ prefix: payload.prefix, idp_entity_id: "mock-idp", sso_url: "https://idp.example/sso" }); }),
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
