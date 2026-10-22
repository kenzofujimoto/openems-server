import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { z } from "zod";
import { ApiError, apiFetch, setCsrfToken } from "./api";
import { endpointSchema, eventSchema, overviewSchema, sessionSchema, type Session } from "./schemas";

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
