import { useQuery } from "@tanstack/react-query";
import { z } from "zod";
import { apiFetch } from "./api";
import { roleSchema } from "./schemas";

export const settingsSchema = z.object({ event_retention_days: z.number().int(), installer_available: z.boolean(), installer_configuration: z.string(), server_version: z.string() });
export const administratorSchema = z.object({ username: z.string(), role: roleSchema });
export const invitationSchema = z.object({ id: z.string(), vdom: z.string(), remaining: z.number().int(), expires_at: z.string() });
export const createdInvitationSchema = z.object({ invitation: z.string(), vdom: z.string(), max_uses: z.number().int(), ttl_seconds: z.number().int() });
export const installerSchema = z.discriminatedUnion("available", [z.object({ available: z.literal(false) }), z.object({ available: z.literal(true), filename: z.string(), sha256: z.string(), size: z.number().int(), download_url: z.literal("/api/v1/installers/windows/download"), bundle_url: z.literal("/api/v1/installers/windows/bundle") })]);
export type Administrator = z.infer<typeof administratorSchema>;
export function useSettings() { return useQuery({ queryKey: ["settings"], queryFn: () => apiFetch("/api/v1/settings", settingsSchema) }); }
export function useAdministrators(enabled: boolean) { return useQuery({ queryKey: ["administrators"], queryFn: () => apiFetch("/api/v1/admins", z.array(administratorSchema)), enabled }); }
export function useInvitations(enabled: boolean) { return useQuery({ queryKey: ["invitations"], queryFn: () => apiFetch("/api/v1/enrollment/invitations", z.array(invitationSchema)), enabled }); }
export function useInstaller(enabled: boolean) { return useQuery({ queryKey: ["installer"], queryFn: () => apiFetch("/api/v1/installers/windows", installerSchema), enabled }); }
