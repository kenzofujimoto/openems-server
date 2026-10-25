import * as Dialog from "@radix-ui/react-dialog";
import { Unlock, X } from "lucide-react";
import { useState } from "react";
import { Button } from "@/components/ui/Button";
import { formatDateTime } from "@/lib/format";
import { useSetUninstallRelease, useUninstallReleases } from "@/lib/queries";
import { FLEET_SCOPE } from "@/lib/schemas";

function scopeLabel(scope: string): string {
  return scope === FLEET_SCOPE ? "Toda a frota" : scope;
}

/** Planned shutdown (tamper-protection.md, decision 7a): let a group or the fleet uninstall without a code. */
export function ReleaseDialog({ groups }: { groups: string[] }) {
  const releases = useUninstallReleases(true);
  const setRelease = useSetUninstallRelease();
  const [scope, setScope] = useState(FLEET_SCOPE);
  const [confirming, setConfirming] = useState(false);

  // The server has no master key (or is older): there is nothing to release.
  if (!releases.data && !releases.isPending) return null;

  const release = () => setRelease.mutate({ scope, released: true }, { onSettled: () => setConfirming(false) });

  return (
    <Dialog.Root onOpenChange={() => setConfirming(false)}>
      <Dialog.Trigger asChild>
        <Button size="sm" disabled={releases.isPending}>
          <Unlock aria-hidden="true" className="size-4" />
          Liberar desinstalação
        </Button>
      </Dialog.Trigger>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-rsm-navy/30" />
        <Dialog.Content className="fixed top-1/2 left-1/2 w-[calc(100%-2rem)] max-w-lg -translate-x-1/2 -translate-y-1/2 rounded-2xl border border-line bg-surface p-6 shadow-xl outline-none">
          <div className="flex items-start justify-between gap-4">
            <div>
              <Dialog.Title className="text-lg font-medium text-ink">Liberar desinstalação</Dialog.Title>
              <Dialog.Description className="mt-1 text-sm text-ink-muted">
                Antes de desligar o servidor ou trocar de produto: as máquinas cobertas deixam de pedir código.
              </Dialog.Description>
            </div>
            <Dialog.Close aria-label="Fechar" className="rounded-lg p-1.5 text-ink-muted hover:bg-canvas hover:text-ink">
              <X aria-hidden="true" className="size-5" />
            </Dialog.Close>
          </div>

          <div className="mt-5 flex flex-wrap items-end gap-3">
            <label className="flex-1 text-sm">
              <span className="mb-1 block text-ink-muted">Escopo</span>
              <select
                aria-label="Escopo"
                value={scope}
                onChange={(event) => {
                  setScope(event.target.value);
                  setConfirming(false);
                }}
                className="h-10 w-full rounded-lg border border-line bg-surface px-3 text-sm outline-none focus:border-rsm-blue"
              >
                <option value={FLEET_SCOPE}>Toda a frota</option>
                {groups.map((group) => <option key={group} value={group}>{group}</option>)}
              </select>
            </label>
            {confirming ? null : <Button variant="primary" onClick={() => setConfirming(true)}>Liberar</Button>}
          </div>
          {confirming ? (
            <div role="group" aria-label="Confirmar liberação" className="mt-3 rounded-xl bg-warning-soft px-4 py-3 text-sm text-warning">
              <p>
                As máquinas de <strong>{scopeLabel(scope)}</strong> poderão ser removidas sem código até a liberação ser
                revogada.
              </p>
              <div className="mt-2 flex gap-2">
                <Button size="sm" variant="primary" onClick={release} disabled={setRelease.isPending}>Confirmar liberação</Button>
                <Button size="sm" variant="ghost" onClick={() => setConfirming(false)}>Cancelar</Button>
              </div>
            </div>
          ) : null}
          {setRelease.isError ? (
            <p role="alert" className="mt-3 rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">Não foi possível alterar a liberação.</p>
          ) : null}

          <h3 className="mt-6 text-sm font-medium text-ink">Liberações ativas</h3>
          {releases.data?.length ? (
            <table className="mt-2 w-full text-sm">
              <tbody className="divide-y divide-line">
                {releases.data.map((item) => (
                  <tr key={item.scope}>
                    <td className="py-2 pr-3 font-medium text-ink">{scopeLabel(item.scope)}</td>
                    <td className="py-2 pr-3 text-ink-soft">{item.released_by} · {formatDateTime(item.released_at)}</td>
                    <td className="py-2 text-right">
                      <Button
                        size="sm"
                        variant="ghost"
                        aria-label={`Revogar liberação de ${scopeLabel(item.scope)}`}
                        disabled={setRelease.isPending}
                        onClick={() => setRelease.mutate({ scope: item.scope, released: false })}
                      >
                        Revogar
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          ) : (
            <p className="mt-2 text-sm text-ink-muted">Nenhuma liberação ativa: todas as máquinas pedem código.</p>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
