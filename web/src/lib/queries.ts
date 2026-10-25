import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { z } from "zod";
import { ApiError, apiFetch, setCsrfToken } from "./api";
import {
  categoriesSchema,
  endpointSchema,
  eventSchema,
  overviewSchema,
  sessionSchema,
  type Session,
  uninstallCodeSchema,
  uninstallReleaseSchema,
  networkLocationSchema,
  locationPolicySchema,
  profileSummarySchema,
  type NetworkLocation,
  type LocationPolicy,
} from "./schemas";

const SESSION_KEY = ["session"] as const;

export function useSession() {
  return useQuery({
    queryKey: SESSION_KEY,
    queryFn: async (): Promise<Session | null> => {
      try {
        const session = await apiFetch("/api/v1/auth/session", sessionSchema);
        setCsrfToken(session.csrf_token);
        return session;
      } catch (error) {
        if (error instanceof ApiError && error.status === 401) return null;
        throw error;
      }
    },
    staleTime: Infinity,
  });
}

export function useLogin() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (credentials: { username: string; password: string }) =>
      apiFetch("/api/v1/auth/login", sessionSchema, { method: "POST", json: credentials }),
    onSuccess: (session) => {
      setCsrfToken(session.csrf_token);
      queryClient.setQueryData(SESSION_KEY, session);
    },
  });
}

export function useLogout() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => apiFetch("/api/v1/auth/logout", z.object({ ok: z.boolean() }), { method: "POST" }),
    onSettled: () => {
      // Drop every cached record so the next account never sees stale data.
      setCsrfToken(null);
      queryClient.removeQueries({ predicate: (query) => query.queryKey[0] !== SESSION_KEY[0] });
      queryClient.setQueryData(SESSION_KEY, null);
    },
  });
}

const REFRESH_MS = 30_000;

/** Routes added by later roadmap phases answer 404 on older servers: report them as unavailable. */
async function optional<T>(request: Promise<T>): Promise<T | null> {
  try {
    return await request;
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) return null;
    throw error;
  }
}

export function useEndpoints() {
  return useQuery({
    queryKey: ["endpoints"],
    queryFn: () => apiFetch("/api/v1/endpoints/index", z.array(endpointSchema)),
    refetchInterval: REFRESH_MS,
  });
}

export function useOverview() {
  return useQuery({
    queryKey: ["overview"],
    queryFn: () => optional(apiFetch("/api/v1/stats/overview", overviewSchema)),
    refetchInterval: REFRESH_MS,
  });
}

export function useEvents(limit = 8) {
  return useQuery({
    queryKey: ["events", limit],
    queryFn: () => optional(apiFetch(`/api/v1/events?limit=${limit}`, z.array(eventSchema))),
    refetchInterval: REFRESH_MS,
  });
}

export function useCategories() {
  return useQuery({
    queryKey: ["categories"],
    queryFn: () => optional(apiFetch("/api/v1/categories", categoriesSchema)),
  });
}

/** Uninstall codes are off (503) without a master key on the server, and absent (404) on older servers. */
async function uninstallFeature<T>(request: Promise<T>): Promise<T | null> {
  try {
    return await request;
  } catch (error) {
    if (error instanceof ApiError && (error.status === 404 || error.status === 503)) return null;
    throw error;
  }
}

const RELEASES_KEY = ["uninstall-releases"] as const;

export function useUninstallReleases(enabled: boolean) {
  return useQuery({
    queryKey: RELEASES_KEY,
    queryFn: () => uninstallFeature(apiFetch("/api/v1/uninstall_release", z.array(uninstallReleaseSchema))),
    enabled,
  });
}

export function useSetUninstallRelease() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (release: { scope: string; released: boolean }) =>
      apiFetch("/api/v1/uninstall_release", z.object({ scope: z.string(), released: z.boolean() }), {
        method: "POST",
        json: release,
      }),
    onSettled: () => queryClient.invalidateQueries({ queryKey: RELEASES_KEY }),
  });
}

/** The code is returned to the caller only: it never enters the query cache. */
export function useGenerateUninstallCode() {
  return useMutation({
    mutationFn: (devid: string) =>
      apiFetch("/api/v1/endpoints/uninstall_code", uninstallCodeSchema, { method: "POST", json: { devid } }),
  });
}

export function useReopenUninstallSecret() {
  return useMutation({
    mutationFn: (devid: string) =>
      apiFetch("/api/v1/endpoints/uninstall_secret/reset", z.object({ ok: z.boolean() }), {
        method: "POST",
        json: { devid },
      }),
  });
}

export function useIsAdmin(): boolean {
  const role = useSession().data?.role;
  return role === "admin" || role === "superadmin";
}

const LOCATIONS_KEY = ["network-locations"] as const;
const LOCATION_POLICIES_KEY = ["location-policies"] as const;

export function useNetworkLocations() {
  return useQuery({ queryKey: LOCATIONS_KEY, queryFn: () => apiFetch("/api/v1/network_locations", z.array(networkLocationSchema)) });
}

export function useLocationPolicies() {
  return useQuery({ queryKey: LOCATION_POLICIES_KEY, queryFn: () => apiFetch("/api/v1/location_policies", z.array(locationPolicySchema)) });
}

export function useProfileSummaries() {
  return useQuery({ queryKey: ["profile-summaries"], queryFn: () => apiFetch("/api/v1/profiles", z.array(profileSummarySchema)) });
}

export function useSaveNetworkLocation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ location, editing }: { location: NetworkLocation; editing: boolean }) =>
      apiFetch(editing ? `/api/v1/network_locations/${encodeURIComponent(location.id)}` : "/api/v1/network_locations", z.unknown(), {
        method: editing ? "PUT" : "POST", json: location,
      }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: LOCATIONS_KEY }),
  });
}

export function useDeleteNetworkLocation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/network_locations/${encodeURIComponent(id)}`, z.object({ ok: z.boolean() }), { method: "DELETE" }),
    onSuccess: async () => {
      await Promise.all([
        queryClient.invalidateQueries({ queryKey: LOCATIONS_KEY }),
        queryClient.invalidateQueries({ queryKey: LOCATION_POLICIES_KEY }),
      ]);
    },
  });
}

export function useSaveLocationPolicy() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (mapping: LocationPolicy) => apiFetch("/api/v1/location_policies", z.unknown(), { method: "POST", json: mapping }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: LOCATION_POLICIES_KEY }),
  });
}

export function useDeleteLocationPolicy() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ vdom, location_id }: LocationPolicy) => apiFetch(
      `/api/v1/location_policies?${new URLSearchParams({ vdom, location_id })}`, z.object({ ok: z.boolean() }), { method: "DELETE" },
    ),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: LOCATION_POLICIES_KEY }),
  });
}
