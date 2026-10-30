import * as Dialog from "@radix-ui/react-dialog";
import { Link } from "@tanstack/react-router";
import { X } from "lucide-react";
import { useIsAdmin } from "@/lib/queries";
import type { Endpoint } from "@/lib/schemas";
import { UninstallSection } from "./UninstallSection";
import { EndpointInventory } from "./EndpointInventory";
import { EndpointActions } from "./EndpointActions";
import { EndpointSummary } from "./EndpointSummary";

export function EndpointSheet({ endpoint, onClose }: { endpoint: Endpoint | null; onClose: () => void }) {
  const isAdmin = useIsAdmin();
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
                  <Link to="/endpoints/$devid" params={{ devid: endpoint.devid }} className="mt-1 inline-block text-sm font-medium text-rsm-blue hover:underline">Abrir ficha completa</Link>
                </div>
                <Dialog.Close aria-label="Fechar" className="rounded-lg p-1.5 text-ink-muted hover:bg-canvas hover:text-ink">
                  <X aria-hidden="true" className="size-5" />
                </Dialog.Close>
              </header>
              <div className="flex-1 overflow-y-auto px-6 py-4">
                <EndpointSummary endpoint={endpoint} />
                <EndpointInventory key={`inventory:${endpoint.devid}`} devid={endpoint.devid} />
                {isAdmin ? <EndpointActions key={`access:${endpoint.devid}`} devid={endpoint.devid} /> : null}
                {/* Keyed by machine: a code shown for one device never carries over to another. */}
                {isAdmin ? <UninstallSection key={endpoint.devid} devid={endpoint.devid} /> : null}
              </div>
            </>
          ) : null}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}
