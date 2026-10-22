import type { Endpoint } from "./schemas";

export type PolicyStatus = "applied" | "pending" | "error";
export type ConnectionStatus = "online" | "offline" | "revoked";

/** Policy is applied only when the agent confirmed exactly the desired identity. */
export function policyStatus(endpoint: Endpoint): PolicyStatus {
  if (endpoint.last_error) return "error";
  const desired = endpoint.desired_profile;
  if (desired === null) {
    // A group without a profile is an explicit release acknowledged as version 0.
    const released = endpoint.applied_vdom === endpoint.effective_vdom && endpoint.last_applied !== null;
    return released ? "applied" : "pending";
  }
  const confirmed = endpoint.applied_vdom === desired.vdom && endpoint.applied_digest === desired.digest;
  return confirmed ? "applied" : "pending";
}

export function connectionStatus(endpoint: Endpoint): ConnectionStatus {
  if (endpoint.status === "unregistered") return "revoked";
  return endpoint.online ? "online" : "offline";
}

export interface FleetSummary {
  total: number;
  online: number;
  offline: number;
  applied: number;
  pending: number;
  error: number;
}

export function summarize(endpoints: Endpoint[]): FleetSummary {
  const summary: FleetSummary = { total: endpoints.length, online: 0, offline: 0, applied: 0, pending: 0, error: 0 };
  for (const endpoint of endpoints) {
    if (connectionStatus(endpoint) === "online") summary.online += 1;
    else summary.offline += 1;
    summary[policyStatus(endpoint)] += 1;
  }
  return summary;
}

export const POLICY_LABEL: Record<PolicyStatus, string> = {
  applied: "Aplicada",
  pending: "Pendente",
  error: "Erro",
};

export const CONNECTION_LABEL: Record<ConnectionStatus, string> = {
  online: "Online",
  offline: "Offline",
  revoked: "Revogado",
};
