import * as Dialog from "@radix-ui/react-dialog";
import { Button } from "@/components/ui/Button";

export function ConfirmDialog({ title, message, confirm, pending, error, onClose, onConfirm }: {
  title: string; message: string; confirm: string; pending: boolean; error: boolean; onClose: () => void; onConfirm: () => void;
}) {
  return <Dialog.Root open onOpenChange={(open) => { if (!open && !pending) onClose(); }}><Dialog.Portal>
    <Dialog.Overlay className="fixed inset-0 z-40 bg-rsm-navy/40" />
    <Dialog.Content className="fixed top-1/2 left-1/2 z-50 w-[calc(100%-2rem)] max-w-lg -translate-x-1/2 -translate-y-1/2 rounded-2xl border border-line bg-surface p-6 shadow-xl">
      <Dialog.Title className="text-lg font-medium">{title}</Dialog.Title>
      <Dialog.Description className="mt-2 text-sm text-ink-soft">{message}</Dialog.Description>
      {error ? <p role="alert" className="mt-3 text-sm text-danger">Não foi possível concluir. Tente de novo.</p> : null}
      <div className="mt-5 flex justify-end gap-2"><Button disabled={pending} onClick={onClose}>Cancelar</Button><Button variant="primary" disabled={pending} onClick={onConfirm}>{pending ? "Aguarde…" : confirm}</Button></div>
    </Dialog.Content>
  </Dialog.Portal></Dialog.Root>;
}
