import { z } from "zod";

export const roleSchema = z.enum(["viewer", "admin", "superadmin"]);
export type Role = z.infer<typeof roleSchema>;

export const sessionSchema = z.object({
  username: z.string(),
  role: roleSchema,
  csrf_token: z.string(),
});
export type Session = z.infer<typeof sessionSchema>;

export const endpointSchema = z.object({
  devid: z.string(),
  client_id: z.string(),
  hostname: z.string(),
  os: z.string(),
  fctver: z.string(),
  vdom: z.string(),
  effective_vdom: z.string(),
  status: z.enum(["registered", "unregistered"]),
  online: z.boolean(),
  host_tags: z.array(z.string()),
  config_version: z.number().int(),
  current_config_version: z.number().int(),
  applied_vdom: z.string(),
  applied_digest: z.string(),
  last_error: z.string(),
  last_applied: z.string().nullable(),
  last_seen: z.string(),
  desired_profile: z.object({ vdom: z.string(), version: z.number().int(), digest: z.string() }).nullable(),
  // Agent tags the effective policy needs but this agent does not report; older servers omit it.
  missing_capabilities: z.array(z.string()).default([]),
});
export type Endpoint = z.infer<typeof endpointSchema>;

export const overviewSchema = z.object({
  generated_at: z.string(),
  blocks_by_day: z.array(z.object({ date: z.string(), web: z.number(), apps: z.number(), usb: z.number() })),
  top_domains: z.array(z.object({ domain: z.string(), count: z.number() })),
  // The server keeps no history of machine status, so only blocks are always compared.
  previous_period: z.object({
    blocks: z.number(),
    online: z.number().optional(),
    applied: z.number().optional(),
    errors: z.number().optional(),
  }),
  retention_days: z.number().int().optional(),
});
export type Overview = z.infer<typeof overviewSchema>;

export const eventKindSchema = z.enum(["web_block", "app_block", "usb_block", "tamper", "policy_error"]);
export type EventKind = z.infer<typeof eventKindSchema>;

export const eventSchema = z.object({
  id: z.string(),
  at: z.string(),
  devid: z.string(),
  kind: eventKindSchema,
  detail: z.string(),
  reason: z.string().optional(),
  category: z.string().nullable().optional(),
  category_label: z.string().nullable().optional(),
  count: z.number().int().optional(),
});
export type FleetEvent = z.infer<typeof eventSchema>;

export const categorySchema = z.object({ id: z.string(), label: z.string(), group: z.string(), count: z.number().int() });
export type Category = z.infer<typeof categorySchema>;

export const categoriesSchema = z.object({
  version: z.string().nullable(),
  attribution: z.string(),
  categories: z.array(categorySchema),
});

export const uninstallCodeSchema = z.object({ devid: z.string(), counter: z.number().int(), code: z.string() });
export type UninstallCode = z.infer<typeof uninstallCodeSchema>;

/** Removal released without a code for a policy group, or for the whole fleet with scope "*". */
export const uninstallReleaseSchema = z.object({ scope: z.string(), released_at: z.string(), released_by: z.string() });
export type UninstallRelease = z.infer<typeof uninstallReleaseSchema>;

export const FLEET_SCOPE = "*";
