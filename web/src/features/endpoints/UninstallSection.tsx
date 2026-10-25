import { Copy, KeyRound } from "lucide-react";
import { useId, useState } from "react";
import { Button } from "@/components/ui/Button";
import { ApiError } from "@/lib/api";
import { useGenerateUninstallCode, useReopenUninstallSecret } from "@/lib/queries";

function failure(error: unknown, fallback: string): string {
  if (error instanceof ApiError && error.status === 503) return "Códigos de desinstalação não configurados no servidor.";
  return fallback;
}

/** Admin-only actions for one machine. The code lives only in this component's state: closing the sheet drops it. */
export function UninstallSection({ devid }: { devid: string }) {
  const headingId = useId();
  const generate = useGenerateUninstallCode();
  const reopen = useReopenUninstallSecret();
  const [code, setCode] = useState<string | null>(null);
  const [copy, setCopy] = useState<"idle" | "copied" | "failed">("idle");
  const [confirming, setConfirming] = useState(false);

  const onGenerate = () => {
    setCopy("idle");
    generate.mutate(devid, { onSuccess: (result) => setCode(result.code) });
  };
  const onCopy = async () => {
    if (!code) return;
    try {
      await navigator.clipboard.writeText(code);
      setCopy("copied");
    } catch {
      // Clipboard access needs HTTPS or localhost; the code stays selectable.
      setCopy("failed");
    }
  };
  const onReopen = () => {
    reopen.mutate(devid, { onSettled: () => setConfirming(false) });
  };

  return (
    <section aria-labelledby={headingId} className="mt-6 border-t border-line pt-5">
      <h2 id={headingId} className="text-sm font-medium text-ink">Desinstalação</h2>
      <p className="mt-1 text-sm text-ink-muted">
        Com o segredo entregue, o agente só é removido com um código de uso único.
      </p>
      <div className="mt-3 flex flex-wrap gap-2">
        <Button size="sm" onClick={onGenerate} disabled={generate.isPending}>
          <KeyRound aria-hidden="true" className="size-4" />
          Gerar código de desinstalação
        </Button>
        {confirming ? null : (
          <Button size="sm" variant="ghost" onClick={() => setConfirming(true)} disabled={reopen.isPending}>
            Reabrir entrega do segredo
          </Button>
        )}
      </div>
      {generate.isError ? (
        <p role="alert" className="mt-3 rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
          {failure(generate.error, "Não foi possível gerar o código.")}
        </p>
      ) : null}
      {code ? (
        <div className="mt-3 rounded-xl border border-line bg-canvas px-4 py-3">
          <output aria-label="Código de desinstalação" className="block font-mono text-2xl tracking-widest text-ink select-all">
            {code}
          </output>
          <p className="mt-1 text-xs text-ink-muted">
            O código vale uma vez e não fica guardado no painel. Use em msiexec /x com UNINSTALLCODE={code}.
          </p>
          <div className="mt-2 flex items-center gap-3">
            <Button size="sm" variant="secondary" onClick={() => void onCopy()}>
              <Copy aria-hidden="true" className="size-4" />
              Copiar código
            </Button>
            {copy === "copied" ? <span className="text-xs text-rsm-green">Código copiado</span> : null}
            {copy === "failed" ? <span className="text-xs text-danger">Copie o código manualmente</span> : null}
          </div>
        </div>
      ) : null}
      {confirming ? (
        <div role="group" aria-label="Confirmar reabertura" className="mt-3 rounded-xl bg-warning-soft px-4 py-3 text-sm text-warning">
          <p>
            O servidor voltará a entregar o segredo a este agente uma vez. Use só se o agente perdeu o arquivo de
            desinstalação.
          </p>
          <div className="mt-2 flex gap-2">
            <Button size="sm" variant="primary" onClick={onReopen} disabled={reopen.isPending}>Confirmar reabertura</Button>
            <Button size="sm" variant="ghost" onClick={() => setConfirming(false)}>Cancelar</Button>
          </div>
        </div>
      ) : null}
      {reopen.isSuccess ? <p className="mt-3 text-sm text-rsm-green">Entrega reaberta: o agente buscará o segredo no próximo contato.</p> : null}
      {reopen.isError ? (
        <p role="alert" className="mt-3 rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">
          {failure(reopen.error, "Não foi possível reabrir a entrega.")}
        </p>
      ) : null}
    </section>
  );
}
