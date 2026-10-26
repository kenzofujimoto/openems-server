import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { z } from "zod";
import { Button } from "@/components/ui/Button";
import { ConfirmDialog } from "@/features/management/ConfirmDialog";
import { apiFetch } from "@/lib/api";

export function EndpointActions({ devid }: { devid: string }) {
  const client = useQueryClient();
  const [action, setAction] = useState<"revoke" | "rotate" | null>(null);
  const [pending, setPending] = useState(false);
  const [error, setError] = useState(false);
  const [token, setToken] = useState("");
  const [message, setMessage] = useState("");
  async function confirm() {
    if (!action) return;
    setPending(true); setError(false); setToken(""); setMessage("");
    try {
      if (action === "rotate") setToken((await apiFetch("/api/v1/endpoints/credentials/rotate", z.object({ device_token: z.string() }), { method: "POST", json: { devid } })).device_token);
      else { await apiFetch("/api/v1/endpoints/revoke", z.object({ ok: z.boolean() }), { method: "POST", json: { devid } }); setMessage("Cadastro revogado."); }
      setAction(null); await client.invalidateQueries({ queryKey: ["endpoints"] });
    } catch { setError(true); }
    finally { setPending(false); }
  }
  return <section className="mt-6 space-y-3 border-t border-line pt-5" aria-label="Acesso do agente">
    <h3 className="text-sm font-medium">Acesso do agente</h3>
    <div className="flex flex-wrap gap-2"><Button size="sm" onClick={() => { setError(false); setAction("rotate"); }}>Trocar credencial do agente</Button><Button size="sm" onClick={() => { setError(false); setAction("revoke"); }}>Revogar cadastro</Button></div>
    {token ? <div className="rounded-xl bg-canvas p-3 text-sm"><p>Guarde a nova credencial para reconfigurar este agente. Ela desaparece ao fechar a ficha.</p><code className="mt-2 block break-all">{token}</code></div> : null}
    {message ? <p role="status" className="text-sm text-rsm-green">{message}</p> : null}
    {action ? <ConfirmDialog title={action === "rotate" ? "Trocar credencial" : "Revogar cadastro"} message={action === "rotate" ? "A credencial atual deixará de funcionar. Será necessário reconfigurar o agente com a nova credencial para voltar a sincronizar." : "O agente perderá acesso ao servidor. A última política continua no cache local; revogar não desinstala nem libera o filtro."} confirm={action === "rotate" ? "Confirmar troca de credencial" : "Confirmar revogação do cadastro"} pending={pending} error={error} onClose={() => setAction(null)} onConfirm={() => void confirm()} /> : null}
  </section>;
}
