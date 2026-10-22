import * as Dialog from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import type { ReactNode } from "react";
import { ConnectionDot, PolicyBadge } from "@/components/StatusBadge";
import { formatDateTime, relativeTime } from "@/lib/format";
import type { Endpoint } from "@/lib/schemas";
import { connectionStatus, policyStatus } from "@/lib/status";

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[150px_1fr] gap-3 py-2.5 text-sm">
      <dt className="text-ink-muted">{label}</dt>
      <dd className="min-w-0 break-words text-ink">{children}</dd>
    </div>
  );
}

export function EndpointSheet({ endpoint, onClose }: { endpoint: Endpoint | null; onClose: () => void }) {
  return (
    <Dialog.Root open={endpoint !== null} onOpenChange={(open) => (open ? undefined : onClose())}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-rsm-navy/30" />
        <Dialog.Content className="fixed inset-y-0 right-0 flex w-full max-w-lg flex-col border-l border-line bg-surface shadow-xl outline-none">
          {endpoint ? (
            <>
              <header className="flex items-start justify-between gap-4 border-b border-line px-6 py-5">
                <div className="min-w-0">
                  <Dialog.Title className="truncate text-lg font-medium text-ink">{endpoint.hostname || endpoint.devid}</Dialog.Title>
                  <Dialog.Description className="mt-0.5 truncate text-sm text-ink-muted">{endpoint.devid}</Dialog.Description>
                </div>
                <Dialog.Close aria-label="Fechar" className="rounded-lg p-1.5 text-ink-muted hover:bg-canvas hover:text-ink">
                  <X aria-hidden="true" className="size-5" />
                </Dialog.Close>
              </header>
              <div className="flex-1 overflow-y-auto px-6 py-4">
                <div className="mb-4 flex flex-wrap gap-3">
                  <PolicyBadge status={policyStatus(endpoint)} />
                  <ConnectionDot status={connectionStatus(endpoint)} />
                </div>
                <dl className="divide-y divide-line">
                  <Row label="Sistema">{endpoint.os || "—"}</Row>
                  <Row label="Versão do agente">{endpoint.fctver || "—"}</Row>
                  <Row label="Grupo atribuído">{endpoint.effective_vdom}</Row>
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
              </div>
            </>
          ) : null}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
