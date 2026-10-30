import type { ReactNode } from "react";
import { ConnectionDot, PolicyBadge } from "@/components/StatusBadge";
import { formatDateTime, relativeTime } from "@/lib/format";
import type { Endpoint } from "@/lib/schemas";
import { connectionStatus, policyStatus } from "@/lib/status";

const CAPABILITY_LABEL: Record<string, string> = {
  "web-filter:categories": "Categorias de sites",
  "web-filter:dns": "DNS local (curingas, SafeSearch e categorias)",
  "web-filter:v2": "Horários e SafeSearch",
  "usb-control:v1": "Controle de armazenamento USB",
  "app-control:wdac": "Bloqueio antes da execução",
  "app-control:network": "Bloqueio de rede por aplicativo",
};

export function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[150px_1fr] gap-3 py-2.5 text-sm">
      <dt className="text-ink-muted">{label}</dt>
      <dd className="min-w-0 break-words text-ink">{children}</dd>
    </div>
  );
}

/** Status, identity, group and policy confirmation of one endpoint, shared by the sheet and the detail page. */
export function EndpointSummary({ endpoint }: { endpoint: Endpoint }) {
  return <>
    <div className="mb-4 flex flex-wrap gap-3">
      <PolicyBadge status={policyStatus(endpoint)} />
      <ConnectionDot status={connectionStatus(endpoint)} />
    </div>
    {endpoint.missing_capabilities.length ? (
      <div role="note" className="mb-4 rounded-xl bg-warning-soft px-4 py-3 text-sm text-warning">
        <p className="font-medium">Este agente não aplica parte da política</p>
        <p className="mt-0.5">
          Sem suporte a: {endpoint.missing_capabilities.map((tag) => CAPABILITY_LABEL[tag] ?? tag).join("; ")}.
          Atualize o agente ou ajuste a política do grupo.
        </p>
      </div>
    ) : null}
    <dl className="divide-y divide-line">
      <Row label="Sistema">{endpoint.os || "—"}</Row>
      <Row label="Versão do agente">{endpoint.fctver || "—"}</Row>
      <Row label="Grupo atribuído">{endpoint.effective_vdom}</Row>
      <Row label="Local de rede">{endpoint.location_name || endpoint.location || "Fora da rede da empresa"}</Row>
      <Row label="Política desejada">
        {endpoint.desired_profile ? (
          <>
            {endpoint.desired_profile.vdom} · v{endpoint.desired_profile.version}
            <span className="mt-1 block font-mono text-xs break-all text-ink-muted">{endpoint.desired_profile.digest}</span>
          </>
        ) : "Sem perfil (liberado)"}
      </Row>
      <Row label="Política confirmada">
        {endpoint.applied_vdom ? `${endpoint.applied_vdom} · v${endpoint.config_version}` : "Nenhuma confirmação"}
      </Row>
      <Row label="Última aplicação">{formatDateTime(endpoint.last_applied)}</Row>
      <Row label="Último erro">
        {endpoint.last_error ? <span className="text-danger">{endpoint.last_error}</span> : "Nenhum"}
      </Row>
      <Row label="Último contato">{relativeTime(endpoint.last_seen)} · {formatDateTime(endpoint.last_seen)}</Row>
      <Row label="Tags">
        {endpoint.host_tags.length ? (
          <span className="flex flex-wrap gap-1.5">
            {endpoint.host_tags.map((tag) => (
              <span key={tag} className="rounded-md bg-canvas px-2 py-0.5 font-mono text-xs text-ink-soft">{tag}</span>
            ))}
          </span>
        ) : "Nenhuma"}
      </Row>
    </dl>
  </>;
}
