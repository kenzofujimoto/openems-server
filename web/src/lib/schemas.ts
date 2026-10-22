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
});
export type Endpoint = z.infer<typeof endpointSchema>;

export const overviewSchema = z.object({
  generated_at: z.string(),
  blocks_by_day: z.array(z.object({ date: z.string(), web: z.number(), apps: z.number(), usb: z.number() })),
  top_domains: z.array(z.object({ domain: z.string(), count: z.number() })),
  previous_period: z.object({ blocks: z.number(), online: z.number(), applied: z.number(), errors: z.number() }),
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
});
export type FleetEvent = z.infer<typeof eventSchema>;
