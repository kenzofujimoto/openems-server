import { endpoints, locationPolicies, networkLocations, profiles, rules, session } from "./data";

const originals = structuredClone({ endpoints, locationPolicies, networkLocations, profiles, rules });
afterEach(() => {
  endpoints.splice(0, endpoints.length, ...structuredClone(originals.endpoints));
  locationPolicies.splice(0, locationPolicies.length, ...structuredClone(originals.locationPolicies));
  networkLocations.splice(0, networkLocations.length, ...structuredClone(originals.networkLocations));
  profiles.splice(0, profiles.length, ...structuredClone(originals.profiles));
  rules.splice(0, rules.length, ...structuredClone(originals.rules));
});

async function request(path: string, method = "GET", body?: unknown, headers?: HeadersInit) {
  return fetch(`http://localhost${path}`, { method, headers: { "Content-Type": "application/json", ...headers }, body: body === undefined ? undefined : JSON.stringify(body) });
}

describe("development mock API contracts", () => {
  it("rejects invalid login, permits a configured account and closes a session", async () => {
    expect((await request("/api/v1/auth/login", "POST", { username: "unknown", password: "x" })).status).toBe(401);
    expect((await request("/api/v1/auth/login", "POST", { username: session.username })).status).toBe(401);
    expect(await (await request("/api/v1/auth/login", "POST", { username: session.username, password: "test" })).json()).toMatchObject({ username: session.username, csrf_token: session.csrf_token });
    expect(await (await request("/api/v1/auth/logout", "POST", {})).json()).toEqual({ ok: true });
  });

  it("publishes full profiles with optimistic concurrency and rejects malformed bodies", async () => {
    const initial = profiles[0];
    if (!initial) throw new Error("Expected a seeded profile");
    expect((await request(`/api/v1/profiles/${initial.vdom}`, "POST", [], { "if-match": initial.digest })).status).toBe(422);
    expect((await request(`/api/v1/profiles/${initial.vdom}`, "POST", {}, { "if-match": "stale" })).status).toBe(412);
    const updated = await (await request(`/api/v1/profiles/${initial.vdom}`, "POST", { web_filter: { blocked: ["mock.example"] } }, { "if-match": initial.digest })).json();
    expect(updated).toMatchObject({ version: initial.version + 1, warnings: [], body: { web_filter: { blocked: ["mock.example"] } } });
    expect(await (await request("/api/v1/profiles/NewGroup", "POST", {})).json()).toMatchObject({ vdom: "NewGroup", version: 1 });
  });

  it("creates and edits typed assignment conditions and removes rules idempotently", async () => {
    expect((await request("/api/v1/assignment_rules", "POST", {})).status).toBe(422);
    const rule = { id: "mock-contract", target_vdom: "Default", priority: 1, enabled: true, conditions: [{ field: "os", op: "in", value: ["linux", "win32"] }] };
    expect(await (await request("/api/v1/assignment_rules", "POST", rule)).json()).toEqual(rule);
    const changed = { ...rule, priority: 2 };
    expect(await (await request("/api/v1/assignment_rules", "POST", changed)).json()).toEqual(changed);
    expect(rules.filter((item) => item.id === rule.id)).toHaveLength(1);
    for (let count = 0; count < 2; count++) expect((await request(`/api/v1/assignment_rules/${rule.id}`, "DELETE")).ok).toBe(true);
  });

  it("validates administrator creation, prevents duplicates and persists role updates", async () => {
    expect((await request("/api/v1/admins", "POST", {})).status).toBe(422);
    const account = { username: "mock-reader-contract", password: "test-password", role: "viewer" };
    expect(await (await request("/api/v1/admins", "POST", account)).json()).toEqual({ username: account.username, role: "viewer" });
    expect((await request("/api/v1/admins", "POST", account)).status).toBe(409);
    expect((await request("/api/v1/admins/missing", "PUT", { role: "viewer" })).status).toBe(404);
    expect((await request(`/api/v1/admins/${account.username}`, "PUT", { role: "invalid" })).status).toBe(404);
    expect(await (await request(`/api/v1/admins/${account.username}`, "PUT", { role: "admin" })).json()).toMatchObject({ role: "admin" });
    await request(`/api/v1/admins/${account.username}`, "DELETE");
    expect(await (await request("/api/v1/admins")).json()).not.toEqual(expect.arrayContaining([expect.objectContaining({ username: account.username })]));
    expect((await request("/api/v1/admins/missing", "DELETE")).ok).toBe(true);
  });

  it("lists only invitation hashes and removes revoked invitations", async () => {
    const invitation = await (await request("/api/v1/enrollment/invitations", "POST", { vdom: "Contract", max_uses: 2, ttl_seconds: 600 })).json() as { invitation: string };
    const listed = await (await request("/api/v1/enrollment/invitations")).json() as Array<{ id: string; vdom: string }>;
    const created = listed.find((item) => item.vdom === "Contract");
    if (!created) throw new Error("Expected the created invitation");
    expect(created.id).toMatch(/^[a-f0-9]{64}$/);
    expect(JSON.stringify(listed)).not.toContain(invitation.invitation);
    await request(`/api/v1/enrollment/invitations/${created.id}`, "DELETE");
    expect((await request("/api/v1/enrollment/invitations/missing", "DELETE")).ok).toBe(true);
    expect(await (await request("/fct_saml/parse_remote_metadata", "POST", { prefix: "Contract", metadata: "<test/>" })).json()).toMatchObject({ prefix: "Contract", idp_entity_id: "mock-idp" });
  });

  it("updates device status and supplies side-effect-free inventory and credentials", async () => {
    const endpoint = endpoints[0];
    if (!endpoint) throw new Error("Expected a seeded endpoint");
    expect(await (await request(`/api/v1/endpoints/inventory?devid=${endpoint.devid}`)).json()).toMatchObject({ devid: endpoint.devid, applications: [], usb_devices: [] });
    expect(await (await request("/api/v1/endpoints/inventory")).json()).toMatchObject({ devid: "" });
    await request("/api/v1/endpoints/revoke", "POST", { devid: endpoint.devid });
    expect(endpoint.status).toBe("unregistered");
    expect((await request("/api/v1/endpoints/revoke", "POST", { devid: "missing" })).ok).toBe(true);
    expect(await (await request("/api/v1/endpoints/credentials/rotate", "POST", { devid: endpoint.devid })).json()).toMatchObject({ device_token: expect.stringContaining("mock-device-") });
  });

  it("validates location CRUD and cascade-removes group mappings", async () => {
    const location = { id: "contract", name: "Contract", cidrs: [], gateway_macs: [], dns_suffixes: [], public_cidrs: ["192.0.2.0/24"], probe: null };
    expect((await request("/api/v1/network_locations", "POST", {})).status).toBe(422);
    expect((await request("/api/v1/network_locations", "POST", location)).ok).toBe(true);
    expect((await request("/api/v1/network_locations", "POST", location)).status).toBe(409);
    expect((await request("/api/v1/network_locations/mismatch", "PUT", location)).status).toBe(422);
    expect((await request("/api/v1/network_locations/missing", "PUT", { ...location, id: "missing" })).status).toBe(404);
    expect(await (await request("/api/v1/network_locations/contract", "PUT", { ...location, name: "Changed" })).json()).toMatchObject({ name: "Changed" });
    expect((await request("/api/v1/location_policies", "POST", {})).status).toBe(422);
    const mapping = { vdom: "Contract", location_id: location.id, inside_vdom: "Default" };
    await request("/api/v1/location_policies", "POST", mapping);
    await request("/api/v1/location_policies", "POST", { ...mapping, inside_vdom: "Strict" });
    expect(locationPolicies.filter((item) => item.vdom === "Contract")).toEqual([{ ...mapping, inside_vdom: "Strict" }]);
    await request("/api/v1/network_locations/contract", "DELETE");
    expect(locationPolicies.some((item) => item.location_id === "contract")).toBe(false);
    expect((await request("/api/v1/network_locations/contract", "DELETE")).status).toBe(404);
    expect((await request("/api/v1/location_policies?vdom=missing&location_id=missing", "DELETE")).ok).toBe(true);
  });
});
