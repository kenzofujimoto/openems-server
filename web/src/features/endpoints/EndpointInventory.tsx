import { ErrorNotice } from "@/components/PageHeader";
import { formatDateTime } from "@/lib/format";
import { useInventory } from "@/lib/management";

export function EndpointInventory({ devid }: { devid: string }) {
  const inventory = useInventory(devid);
  return <section className="mt-6 space-y-4 border-t border-line pt-5" aria-label="Inventário do endpoint">
    <h3 className="text-sm font-medium">Inventário do agente</h3>
    {inventory.isPending ? <p role="status" className="text-sm">Carregando inventário…</p> : null}
    {inventory.isError ? <ErrorNotice message="Não foi possível carregar o inventário." onRetry={() => void inventory.refetch()} /> : null}
    {inventory.data ? <><p className="text-xs text-ink-muted">Última coleta: {formatDateTime(inventory.data.collected_at)}</p>
      <details open><summary className="cursor-pointer text-sm font-medium">Aplicativos ({inventory.data.applications.length})</summary><ul className="mt-2 divide-y divide-line">{inventory.data.applications.map((application, index) => <li key={`${application.path}:${index}`} className="py-3 text-sm"><p>{application.name}</p><p className="mt-1 break-all text-xs text-ink-muted">{application.path}</p><p className="mt-1 text-xs text-ink-soft">{application.publisher || "Editor não verificado"} · {application.version || "Sem versão"}{application.running ? " · Em execução" : ""}</p><code className="mt-1 block break-all text-xs text-ink-muted">{application.sha256 || "Sem hash"}</code></li>)}</ul>{!inventory.data.applications.length ? <p className="mt-2 text-sm text-ink-muted">Nenhum aplicativo informado.</p> : null}</details>
      <details open><summary className="cursor-pointer text-sm font-medium">Dispositivos USB ({inventory.data.usb_devices.length})</summary><ul className="mt-2 divide-y divide-line">{inventory.data.usb_devices.map((device) => <li key={device.instance_id} className="py-3 text-sm"><p>{device.product || device.instance_id}</p><p className="mt-1 text-xs text-ink-soft">{device.manufacturer} · VID {device.vid || "—"} / PID {device.pid || "—"} · Serial {device.serial || "—"}</p><p className="mt-1 break-all text-xs text-ink-muted">{device.instance_id}</p><p className="mt-1 text-xs text-ink-muted">{device.present ? "Conectado" : "Desconectado"} · {device.drive_letters.join(", ") || "Sem unidade"}</p><p className="mt-1 text-xs text-ink-muted">Primeira conexão: {formatDateTime(device.first_seen)} · Última: {formatDateTime(device.last_seen)}</p></li>)}</ul>{!inventory.data.usb_devices.length ? <p className="mt-2 text-sm text-ink-muted">Nenhum dispositivo USB informado.</p> : null}</details>
    </> : null}
  </section>;
}
