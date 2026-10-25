import * as Dialog from "@radix-ui/react-dialog";
import { X } from "lucide-react";
import { useState, type ReactNode } from "react";
import { z } from "zod";
import { Button } from "@/components/ui/Button";
import { ApiError } from "@/lib/api";
import { useDeleteNetworkLocation, useSaveNetworkLocation } from "@/lib/queries";
import type { NetworkLocation } from "@/lib/schemas";

export const FIELD_CLASS = "w-full rounded-lg border border-line bg-surface px-3 py-2 text-sm text-ink outline-none focus:border-rsm-blue disabled:bg-canvas";

function Modal({ title, description, children, onClose }: { title: string; description: string; children: ReactNode; onClose: () => void }) {
  return (
    <Dialog.Root open onOpenChange={(open) => { if (!open) onClose(); }}>
      <Dialog.Portal>
        <Dialog.Overlay className="fixed inset-0 bg-rsm-navy/30" />
        <Dialog.Content className="fixed top-1/2 left-1/2 max-h-[90vh] w-[calc(100%-2rem)] max-w-2xl -translate-x-1/2 -translate-y-1/2 overflow-y-auto rounded-2xl border border-line bg-surface p-6 shadow-xl outline-none">
          <div className="flex items-start justify-between gap-4">
            <div>
              <Dialog.Title className="text-lg font-medium text-ink">{title}</Dialog.Title>
              <Dialog.Description className="mt-1 text-sm text-ink-muted">{description}</Dialog.Description>
            </div>
            <Dialog.Close aria-label="Fechar" className="rounded-lg p-1.5 text-ink-muted hover:bg-canvas"><X aria-hidden="true" className="size-5" /></Dialog.Close>
          </div>
          {children}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function lines(value: string): string[] {
  return [...new Set(value.split(/[\n,]+/).map((item) => item.trim()).filter(Boolean))];
}

const cidrSchema = z.union([z.cidrv4(), z.cidrv6()]);
const hostSchema = z.union([z.hostname(), z.ipv4(), z.ipv6()]);

export function LocationDialog({ location, onClose }: { location: NetworkLocation | null; onClose: () => void }) {
  const save = useSaveNetworkLocation();
  const [id, setId] = useState(location?.id ?? "");
  const [name, setName] = useState(location?.name ?? "");
  const [cidrs, setCidrs] = useState(location?.cidrs.join("\n") ?? "");
  const [gateways, setGateways] = useState(location?.gateway_macs.join("\n") ?? "");
  const [suffixes, setSuffixes] = useState(location?.dns_suffixes.join("\n") ?? "");
  const [publicCidrs, setPublicCidrs] = useState(location?.public_cidrs.join("\n") ?? "");
  const [host, setHost] = useState(location?.probe?.host ?? "");
  const [port, setPort] = useState(String(location?.probe?.port ?? 443));
  const [pin, setPin] = useState(location?.probe?.sha256 ?? "");
  const [error, setError] = useState("");

  function submit(event: React.SubmitEvent<HTMLFormElement>) {
    event.preventDefault();
    setError("");
    const body: NetworkLocation = {
      id: id.trim(), name: name.trim(), cidrs: lines(cidrs), gateway_macs: lines(gateways),
      dns_suffixes: lines(suffixes), public_cidrs: lines(publicCidrs),
      probe: host.trim() || pin.trim() ? { host: host.trim(), port: Number(port), sha256: pin.trim().toLowerCase() } : null,
    };
    if (!/^[a-z0-9][a-z0-9_-]{0,127}$/.test(body.id)) return setError("Use um identificador com até 128 letras minúsculas, números, traços ou sublinhados.");
    if (!body.name || body.name.length > 128) return setError("Informe um nome com até 128 caracteres.");
    if ([...body.cidrs, ...body.public_cidrs].some((value) => !cidrSchema.safeParse(value).success)) return setError("Informe faixas CIDR válidas, como 192.168.1.0/24 ou 2001:db8::/32.");
    if (body.gateway_macs.some((value) => !/^[0-9a-f]{12}$/i.test(value.replace(/[:.\- ]/g, "")))) return setError("Informe MACs válidos com 12 dígitos hexadecimais.");
    if (body.dns_suffixes.some((value) => !z.hostname().safeParse(value.replace(/\.$/, "")).success)) return setError("Informe sufixos DNS válidos, como corp.example.");
    if (body.probe && (!hostSchema.safeParse(body.probe.host).success || !Number.isInteger(body.probe.port) || body.probe.port < 1 || body.probe.port > 65535 || !/^[0-9a-f]{64}$/i.test(body.probe.sha256))) {
      return setError("Informe o host interno, uma porta de 1 a 65535 e o SHA-256 do certificado (64 dígitos hexadecimais).");
    }
    const localKinds = [body.cidrs.length > 0, body.gateway_macs.length > 0, body.dns_suffixes.length > 0, body.probe !== null].filter(Boolean).length;
    if (!body.public_cidrs.length && localKinds < 2) return setError("Informe IP público ou pelo menos dois tipos de sinais locais; a faixa local sozinha não identifica a empresa.");
    save.mutate({ location: body, editing: location !== null }, { onSuccess: onClose });
  }

  return (
    <Modal title={location ? "Editar local de rede" : "Novo local de rede"} description="O local casa pelo IP público ou por dois tipos de sinais locais. Na dúvida, o agente mantém a política de fora." onClose={onClose}>
      <form onSubmit={submit} className="mt-5 space-y-4">
        <fieldset disabled={save.isPending} className="grid gap-4 sm:grid-cols-2">
          <label className="text-sm text-ink-soft">Identificador<input className={`mt-1 ${FIELD_CLASS}`} value={id} onChange={(event) => setId(event.target.value)} disabled={location !== null} autoComplete="off" /></label>
          <label className="text-sm text-ink-soft">Nome<input className={`mt-1 ${FIELD_CLASS}`} value={name} onChange={(event) => setName(event.target.value)} maxLength={128} /></label>
          <label className="text-sm text-ink-soft">Faixas de IP local (CIDR)<textarea className={`mt-1 ${FIELD_CLASS}`} value={cidrs} onChange={(event) => setCidrs(event.target.value)} placeholder="192.168.1.0/24" rows={3} /></label>
          <label className="text-sm text-ink-soft">MACs dos gateways<textarea className={`mt-1 ${FIELD_CLASS}`} value={gateways} onChange={(event) => setGateways(event.target.value)} placeholder="00:11:22:33:44:55" rows={3} /></label>
          <label className="text-sm text-ink-soft">Sufixos DNS<textarea className={`mt-1 ${FIELD_CLASS}`} value={suffixes} onChange={(event) => setSuffixes(event.target.value)} placeholder="corp.example" rows={3} /></label>
          <label className="text-sm text-ink-soft">Faixas de IP público (CIDR)<textarea className={`mt-1 ${FIELD_CLASS}`} value={publicCidrs} onChange={(event) => setPublicCidrs(event.target.value)} placeholder="203.0.113.10/32" rows={3} /></label>
          <p className="text-xs text-ink-muted sm:col-span-2">Um valor por linha ou separado por vírgula. Prefira o IP público de saída ou o certificado de um host interno: sinais locais podem ser imitados. VPN de túnel completo usa o IP público da VPN.</p>
          <label className="text-sm text-ink-soft">Host interno (TLS)<input className={`mt-1 ${FIELD_CLASS}`} value={host} onChange={(event) => setHost(event.target.value)} placeholder="intranet.corp.example" /></label>
          <label className="text-sm text-ink-soft">Porta TLS<input className={`mt-1 ${FIELD_CLASS}`} type="number" min="1" max="65535" value={port} onChange={(event) => setPort(event.target.value)} /></label>
          <label className="text-sm text-ink-soft sm:col-span-2">SHA-256 do certificado<input className={`mt-1 font-mono ${FIELD_CLASS}`} value={pin} onChange={(event) => setPin(event.target.value)} autoComplete="off" /></label>
        </fieldset>
        {error || save.isError ? <p role="alert" className="rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">{error || (save.error instanceof ApiError && save.error.status === 409 ? "Já existe um local com esse identificador." : "Não foi possível salvar o local. Verifique os sinais e tente de novo.")}</p> : null}
        <div className="flex justify-end gap-2"><Button onClick={onClose}>Cancelar</Button><Button type="submit" variant="primary" disabled={save.isPending}>{save.isPending ? "Salvando…" : "Salvar local"}</Button></div>
      </form>
    </Modal>
  );
}

export function DeleteLocationDialog({ location, onClose }: { location: NetworkLocation; onClose: () => void }) {
  const remove = useDeleteNetworkLocation();
  return (
    <Modal title="Excluir local de rede" description={`Excluir ${location.name} remove também seus mapeamentos. No próximo ciclo, máquinas nesse local voltam à política de fora se nenhum outro local casar.`} onClose={onClose}>
      {remove.isError ? <p role="alert" className="mt-4 text-sm text-danger">Não foi possível excluir o local. Tente de novo.</p> : null}
      <div className="mt-5 flex justify-end gap-2"><Button onClick={onClose}>Cancelar</Button><Button variant="primary" disabled={remove.isPending} onClick={() => remove.mutate(location.id, { onSuccess: onClose })}>{remove.isPending ? "Excluindo…" : "Confirmar exclusão"}</Button></div>
    </Modal>
  );
}
