import { cn } from "@/lib/cn";
import { CONNECTION_LABEL, POLICY_LABEL, type ConnectionStatus, type PolicyStatus } from "@/lib/status";

const POLICY_STYLE: Record<PolicyStatus, string> = {
  applied: "bg-rsm-green-soft text-rsm-green",
  pending: "bg-warning-soft text-warning",
  error: "bg-danger-soft text-danger",
};

export function PolicyBadge({ status }: { status: PolicyStatus }) {
  return (
    <span className={cn("inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium", POLICY_STYLE[status])}>
      {POLICY_LABEL[status]}
    </span>
  );
}

const DOT_STYLE: Record<ConnectionStatus, string> = {
  online: "bg-rsm-green",
  offline: "bg-rsm-gray-mid",
  revoked: "bg-danger",
};

export function ConnectionDot({ status }: { status: ConnectionStatus }) {
  return (
    <span className="inline-flex items-center gap-2 text-sm text-ink-soft">
      <span aria-hidden="true" className={cn("size-2 rounded-full", DOT_STYLE[status])} />
      {CONNECTION_LABEL[status]}
    </span>
  );
}
