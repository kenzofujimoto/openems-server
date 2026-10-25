// Deterministic sample data shaped exactly like the openems management API.
// Endpoints, profiles, rules and audit mirror existing routes; overview and
// events define the contract for server routes that the roadmap adds next.

export interface MockEndpoint {
  devid: string;
  client_id: string;
  hostname: string;
  os: string;
  fctver: string;
  vdom: string;
  effective_vdom: string;
  status: "registered" | "unregistered";
  online: boolean;
  host_tags: string[];
  config_version: number;
  current_config_version: number;
  applied_vdom: string;
  applied_digest: string;
  last_error: string;
  last_applied: string | null;
  last_seen: string;
  desired_profile: { vdom: string; version: number; digest: string } | null;
  missing_capabilities: string[];
}

const DIGEST_DEFAULT = "1ff21ccf4803d8a83c72600aca58edae52d76066e632017bd918f1eda9aadb11";
const DIGEST_STRICT = "072a9d4439b6b6593a1f8ab65fa9c715f5d1c0f74e9655e9cf0c52ff98a247c6";
const NOW = Date.parse("2026-10-22T13:00:00Z");

function minutesAgo(minutes: number): string {
  return new Date(NOW - minutes * 60_000).toISOString();
}

interface Seed {
  devid: string;
  hostname: string;
  os: string;
  vdom: "Default" | "Strict";
  state: "applied" | "pending" | "error" | "offline";
  seen: number;
}

const SEEDS: Seed[] = [
  { devid: "RSM-SP-001", hostname: "NB-FINANCEIRO-01", os: "Windows 11 Pro", vdom: "Default", state: "applied", seen: 1 },
  { devid: "RSM-SP-002", hostname: "NB-AUDITORIA-07", os: "Windows 11 Pro", vdom: "Strict", state: "error", seen: 1 },
  { devid: "RSM-RJ-003", hostname: "DT-RECEPCAO-02", os: "Windows 10 Pro", vdom: "Default", state: "pending", seen: 2 },
  { devid: "RSM-SP-004", hostname: "NB-TAX-12", os: "Windows 11 Pro", vdom: "Default", state: "applied", seen: 1 },
  { devid: "RSM-SP-005", hostname: "NB-CONSULTORIA-03", os: "macOS 15", vdom: "Default", state: "applied", seen: 3 },
  { devid: "RSM-BH-006", hostname: "NB-AUDITORIA-11", os: "Windows 11 Pro", vdom: "Strict", state: "applied", seen: 1 },
  { devid: "RSM-SP-007", hostname: "DT-TI-01", os: "Ubuntu 24.04", vdom: "Default", state: "applied", seen: 1 },
  { devid: "RSM-POA-008", hostname: "NB-TAX-04", os: "Windows 11 Pro", vdom: "Default", state: "offline", seen: 600 },
  { devid: "RSM-SP-009", hostname: "NB-RH-02", os: "Windows 10 Pro", vdom: "Default", state: "applied", seen: 1 },
  { devid: "RSM-SP-010", hostname: "NB-AUDITORIA-15", os: "Windows 11 Pro", vdom: "Strict", state: "applied", seen: 2 },
];

export const endpoints: MockEndpoint[] = SEEDS.map((seed, index) => {
  const digest = seed.vdom === "Strict" ? DIGEST_STRICT : DIGEST_DEFAULT;
  const applied = seed.state === "applied" || seed.state === "offline";
  return {
    devid: seed.devid,
    client_id: (index + 1).toString(16).padStart(32, "0"),
    hostname: seed.hostname,
    os: seed.os,
    fctver: "7.4.0",
    vdom: seed.vdom,
    effective_vdom: seed.vdom,
    status: "registered",
    online: seed.state !== "offline",
    host_tags: [`vdom:${seed.vdom}`, applied ? "web-filter:2-blocked" : "web-filter:0-blocked"],
    config_version: applied ? 3 : 2,
    current_config_version: 3,
    applied_vdom: applied ? seed.vdom : "",
    applied_digest: applied ? digest : "",
    last_error: seed.state === "error" ? "enforcement failed: PermissionError" : "",
    last_applied: applied ? minutesAgo(seed.seen + 30) : null,
    last_seen: minutesAgo(seed.seen),
    desired_profile: { vdom: seed.vdom, version: 3, digest },
    // An agent that predates categories and the local resolver.
    missing_capabilities: seed.devid === "RSM-RJ-003" ? ["web-filter:categories", "web-filter:dns"] : [],
  };
});

export const overview = {
  generated_at: minutesAgo(0),
  blocks_by_day: [
    { date: "2026-10-16", web: 412, apps: 38, usb: 4 },
    { date: "2026-10-17", web: 388, apps: 41, usb: 2 },
    { date: "2026-10-18", web: 120, apps: 9, usb: 0 },
    { date: "2026-10-19", web: 98, apps: 6, usb: 1 },
    { date: "2026-10-20", web: 455, apps: 52, usb: 6 },
    { date: "2026-10-21", web: 501, apps: 47, usb: 3 },
    { date: "2026-10-22", web: 276, apps: 22, usb: 2 },
  ],
  top_domains: [
    { domain: "tiktok.com", count: 812 },
    { domain: "facebook.com", count: 640 },
    { domain: "instagram.com", count: 402 },
    { domain: "youtube.com", count: 233 },
    { domain: "bet365.com", count: 61 },
  ],
  previous_period: { blocks: 1920, online: 9, applied: 7, errors: 2 },
  retention_days: 30,
};

export const events = [
  { id: "evt-6", at: minutesAgo(2), devid: "RSM-SP-002", kind: "policy_error", detail: "enforcement failed: PermissionError" },
  { id: "evt-5", at: minutesAgo(9), devid: "RSM-SP-004", kind: "web_block", detail: "tiktok.com",
    reason: "category", category: "social", category_label: "Redes sociais", count: 12 },
  { id: "evt-4", at: minutesAgo(18), devid: "RSM-SP-009", kind: "usb_block", detail: "SanDisk Ultra (VID 0781 / PID 5581)" },
  { id: "evt-3", at: minutesAgo(41), devid: "RSM-SP-001", kind: "app_block", detail: "utorrent.exe" },
  { id: "evt-2", at: minutesAgo(65), devid: "RSM-BH-006", kind: "tamper", detail: "DNS settings reverted" },
  { id: "evt-1", at: minutesAgo(120), devid: "RSM-SP-005", kind: "web_block", detail: "facebook.com",
    reason: "rule", category: null, category_label: null, count: 1 },
];

export const profiles = [
  { vdom: "Default", version: 3, digest: DIGEST_DEFAULT, updated_at: minutesAgo(31), body: { web_filter: { blocked: ["facebook.com", "tiktok.com"] }, app_control: { blocked: ["utorrent.exe"] } } },
  { vdom: "Strict", version: 3, digest: DIGEST_STRICT, updated_at: minutesAgo(31), body: { web_filter: { blocked: ["facebook.com", "tiktok.com", "youtube.com", "instagram.com"] }, app_control: { blocked: ["utorrent.exe", "steam.exe"] } } },
];

export const rules = [
  { id: "auditoria-strict", target_vdom: "Strict", priority: 10, enabled: true, conditions: [{ field: "hostname", op: "contains", value: "AUDITORIA" }] },
];

export const audit = [
  { ts: minutesAgo(31), actor: "labadmin", action: "profile.publish", target: "Default", metadata: { version: 3 } },
  { ts: minutesAgo(32), actor: "labadmin", action: "rule.add", target: "auditoria-strict", metadata: { target_vdom: "Strict", priority: 10 } },
];

export const session = { username: "labadmin", role: "admin", csrf_token: "mock-csrf-token" } as const;

export const categories = {
  version: "2026-10-24T03:00:00Z",
  attribution: "Category lists: Université Toulouse Capitole (UT1 blacklists, Fabrice Prigent), licensed CC BY-SA 4.0. Hashed and regrouped by openems.",
  categories: [
    { id: "adult", label: "Conteúdo adulto", group: "Adulto", count: 4012345 },
    { id: "games", label: "Jogos", group: "Consumo de banda e lazer", count: 2104 },
    { id: "social", label: "Redes sociais", group: "Interesse geral", count: 812 },
  ],
};

export const uninstallReleases: Array<{ scope: string; released_at: string; released_by: string }> = [];
