import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { z } from "zod";
import { apiFetch } from "./api";

export const policyBodySchema = z.record(z.string(), z.unknown());
export const profileSchema = z.object({ vdom: z.string(), version: z.number().int(), digest: z.string(), body: policyBodySchema, updated_at: z.string().optional() });
export type Profile = z.infer<typeof profileSchema>;
export type PolicyBody = z.infer<typeof policyBodySchema>;
export const publicationSchema = z.object({ vdom: z.string(), version: z.number().int(), digest: z.string(), warnings: z.array(z.object({ devid: z.string(), missing: z.array(z.string()) })).default([]) });

export const applicationSchema = z.object({ name: z.string(), path: z.string(), sha256: z.string(), publisher: z.string(), version: z.string(), running: z.boolean() });
export const usbDeviceSchema = z.object({ instance_id: z.string(), vid: z.string(), pid: z.string(), manufacturer: z.string(), product: z.string(), serial: z.string(), class: z.string(), drive_letters: z.array(z.string()), present: z.boolean(), first_seen: z.string(), last_seen: z.string() });
export const inventorySchema = z.object({ devid: z.string(), collected_at: z.string().nullable(), applications: z.array(applicationSchema), usb_devices: z.array(usbDeviceSchema) });
export type Application = z.infer<typeof applicationSchema>;
export type UsbDevice = z.infer<typeof usbDeviceSchema>;

export function useProfiles() {
  return useQuery({ queryKey: ["profiles"], queryFn: () => apiFetch("/api/v1/profiles", z.array(profileSchema)) });
}

export function usePublishProfile() {
  const client = useQueryClient();
  return useMutation({
    mutationFn: ({ vdom, body, digest }: { vdom: string; body: PolicyBody; digest?: string }) => apiFetch(`/api/v1/profiles/${encodeURIComponent(vdom)}`, publicationSchema, {
      method: "POST", json: body, headers: digest ? { "If-Match": digest } : undefined,
    }),
    onSuccess: async () => { await Promise.all([client.invalidateQueries({ queryKey: ["profiles"] }), client.invalidateQueries({ queryKey: ["profile-summaries"] }), client.invalidateQueries({ queryKey: ["endpoints"] })]); },
  });
}

export const appCatalogSchema = z.object({
  available: z.boolean(), version: z.string().nullable(), attribution: z.string(),
  categories: z.array(z.object({ id: z.string(), label: z.string(), apps: z.number().int(), observed_endpoints: z.number().int() })),
  observed: z.record(z.string(), z.number().int()),
});
export const catalogAppSchema = z.object({ id: z.string(), name: z.string(), vendor: z.string(), category: z.string().nullable(), blockable: z.boolean(), observed_endpoints: z.number().int() });
export type CatalogApp = z.infer<typeof catalogAppSchema>;
export function useAppCatalog() {
  return useQuery({ queryKey: ["app-catalog"], queryFn: () => apiFetch("/api/v1/app_catalog", appCatalogSchema) });
}
export function useAppCatalogSearch(query: string) {
  const q = query.trim();
  return useQuery({ queryKey: ["app-catalog-search", q], queryFn: () => apiFetch(`/api/v1/app_catalog/search?${new URLSearchParams({ q })}`, z.array(catalogAppSchema)), enabled: q.length >= 2 });
}
export function useInventory(devid: string) {
  return useQuery({ queryKey: ["inventory", devid], queryFn: () => apiFetch(`/api/v1/endpoints/inventory?${new URLSearchParams({ devid })}`, inventorySchema), enabled: Boolean(devid) });
}

export const conditionSchema = z.object({ field: z.enum(["os", "hostname", "fctver", "vdom", "host_tag"]), op: z.enum(["equals", "contains", "in", "has_tag"]), value: z.union([z.string(), z.array(z.string())]) });
export const ruleSchema = z.object({ id: z.string(), target_vdom: z.string(), priority: z.number().int(), enabled: z.boolean(), conditions: z.array(conditionSchema) });
export type AssignmentRule = z.infer<typeof ruleSchema>;
export type Condition = z.infer<typeof conditionSchema>;
export function useAssignmentRules() { return useQuery({ queryKey: ["assignment-rules"], queryFn: () => apiFetch("/api/v1/assignment_rules", z.array(ruleSchema)) }); }
/** Moving one machine is a hostname rule at priority 1, so it always wins over broader group rules. */
export function moveEndpointRule(hostname: string, vdom: string): AssignmentRule {
  return { id: `endpoint-${hostname.toLowerCase().replace(/[^a-z0-9]+/g, "-")}`, target_vdom: vdom, priority: 1, enabled: true,
    conditions: [{ field: "hostname", op: "equals", value: hostname }] };
}export function useSaveAssignmentRule() {
  const client = useQueryClient();
  return useMutation({ mutationFn: (rule: AssignmentRule) => apiFetch("/api/v1/assignment_rules", z.unknown(), { method: "POST", json: rule }), onSuccess: async () => { await Promise.all([client.invalidateQueries({ queryKey: ["assignment-rules"] }), client.invalidateQueries({ queryKey: ["endpoints"] })]); } });
}
export function useRemoveAssignmentRule() {
  const client = useQueryClient();
  return useMutation({ mutationFn: (id: string) => apiFetch(`/api/v1/assignment_rules/${encodeURIComponent(id)}`, z.object({ ok: z.boolean() }), { method: "DELETE" }), onSuccess: async () => { await Promise.all([client.invalidateQueries({ queryKey: ["assignment-rules"] }), client.invalidateQueries({ queryKey: ["endpoints"] })]); } });
}

export const auditSchema = z.object({ ts: z.string(), actor: z.string(), action: z.string(), target: z.string(), metadata: z.record(z.string(), z.unknown()) });
export function useAudit() { return useQuery({ queryKey: ["audit"], queryFn: () => apiFetch("/api/v1/audit?limit=1000", z.array(auditSchema)) }); }

/** The downloaded data is generated locally; neutralize formula prefixes for spreadsheet readers. */
export function downloadCsv(filename: string, rows: unknown[][]) {
  const csv = rows.map((row) => row.map((value) => {
    const text = String(value ?? "");
    const safe = /^[=+@\-\t\r]/.test(text) ? `'${text}` : text;
    return `"${safe.replaceAll('"', '""')}"`;
  }).join(",")).join("\r\n");
  const url = URL.createObjectURL(new Blob(["\uFEFF", csv], { type: "text/csv;charset=utf-8" }));
  const link = document.createElement("a"); link.href = url; link.download = filename; link.click(); URL.revokeObjectURL(url);
}
