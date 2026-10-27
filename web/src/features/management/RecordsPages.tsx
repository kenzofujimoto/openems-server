import { useState } from "react";
import { ErrorNotice, InfoNotice, PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { eventDetail } from "@/features/dashboard/widgets";
import { FIELD_CLASS } from "@/features/policies/PolicyWorkspace";
import { formatDateTime } from "@/lib/format";
import { downloadCsv, useAudit } from "@/lib/management";
import { useEvents, useOverview } from "@/lib/queries";

const KINDS: Record<string, string> = { web_block: "Site bloqueado", web_monitor: "Domínio monitorado", app_block: "Aplicativo bloqueado", app_network_block: "Conexão do aplicativo bloqueada", app_control_applied: "Política de aplicativos aplicada", app_network_policy: "Regra de rede aplicada", usb_block: "USB bloqueado", usb_read_only: "USB em somente leitura", tamper: "Tentativa de adulteração", policy_error: "Erro de política" };

export function EventsPage() {
  const events = useEvents(1000);
  const overview = useOverview();
  const [kind, setKind] = useState("");
  const [search, setSearch] = useState("");
  const rows = (events.data ?? []).filter((event) => (!kind || event.kind === kind) && `${event.devid} ${eventDetail(event)}`.toLowerCase().includes(search.toLowerCase()));
  return <div className="space-y-6">
    <PageHeader title="Eventos" description="Até mil ocorrências recentes, com filtros e exportação da lista exibida." actions={<Button disabled={!rows.length} onClick={() => downloadCsv("openems-events.csv", [["Data", "Endpoint", "Tipo", "Detalhe"], ...rows.map((event) => [event.at, event.devid, KINDS[event.kind], eventDetail(event)])])}>Exportar eventos</Button>} />
    <InfoNotice>Os registros identificam o uso de cada máquina e são dados pessoais. Consultas DNS não comprovam visitas nem identificam a pessoa; monitoramento e bloqueios são eventos distintos.{overview.data?.retention_days !== undefined ? ` Retenção configurada no servidor: ${overview.data.retention_days} dias.` : " A retenção é definida no servidor."}</InfoNotice>
    {events.isError ? <ErrorNotice message="Não foi possível carregar os eventos." onRetry={() => void events.refetch()} /> : null}
    <div className="flex flex-wrap gap-4"><label className="text-sm">Tipo de evento<select className={`mt-1 ${FIELD_CLASS}`} value={kind} onChange={(event) => setKind(event.target.value)}><option value="">Todos</option>{Object.entries(KINDS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label><label className="min-w-64 flex-1 text-sm">Buscar eventos<input type="search" className={`mt-1 ${FIELD_CLASS}`} value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Endpoint ou detalhe" /></label></div>
    <Card className="overflow-x-auto"><table className="w-full text-left text-sm"><caption className="sr-only">Eventos dos endpoints</caption><thead className="border-b border-line bg-canvas"><tr>{["Data", "Endpoint", "Tipo", "Detalhe"].map((label) => <th className="p-4 font-medium" key={label}>{label}</th>)}</tr></thead><tbody className="divide-y divide-line">{rows.map((event) => <tr key={event.id}><td className="whitespace-nowrap p-4 text-ink-muted">{formatDateTime(event.at)}</td><td className="p-4">{event.devid}</td><td className="p-4">{KINDS[event.kind]}</td><td className="max-w-xl break-words p-4">{eventDetail(event)}</td></tr>)}</tbody></table>
      {events.isPending ? <p role="status" className="p-5">Carregando eventos…</p> : events.data === null ? <p className="p-5 text-sm">O servidor não oferece o histórico de eventos.</p> : !rows.length ? <p className="p-5 text-sm text-ink-muted">Nenhum evento corresponde aos filtros.</p> : null}
    </Card>
  </div>;
}

export function AuditPage() {
  const audit = useAudit();
  const [search, setSearch] = useState("");
  const rows = (audit.data ?? []).filter((entry) => `${entry.actor} ${entry.action} ${entry.target} ${JSON.stringify(entry.metadata)}`.toLowerCase().includes(search.toLowerCase()));
  return <div className="space-y-6">
    <PageHeader title="Auditoria" description="Ações administrativas registradas pelo servidor; até mil entradas recentes." actions={<Button disabled={!rows.length} onClick={() => downloadCsv("openems-audit.csv", [["Data", "Usuário", "Ação", "Alvo", "Metadados"], ...rows.map((entry) => [entry.ts, entry.actor, entry.action, entry.target, JSON.stringify(entry.metadata)])])}>Exportar auditoria</Button>} />
    {audit.isError ? <ErrorNotice message="Não foi possível carregar a auditoria." onRetry={() => void audit.refetch()} /> : null}
    <label className="block max-w-xl text-sm">Buscar auditoria<input type="search" className={`mt-1 ${FIELD_CLASS}`} value={search} onChange={(event) => setSearch(event.target.value)} placeholder="Usuário, ação, alvo ou metadados" /></label>
    <Card className="overflow-x-auto"><table className="w-full text-left text-sm"><caption className="sr-only">Ações administrativas</caption><thead className="border-b border-line bg-canvas"><tr>{["Data", "Usuário", "Ação", "Alvo", "Metadados"].map((label) => <th key={label} className="p-4 font-medium">{label}</th>)}</tr></thead><tbody className="divide-y divide-line">{rows.map((entry, index) => <tr key={`${entry.ts}:${index}`}><td className="whitespace-nowrap p-4 text-ink-muted">{formatDateTime(entry.ts)}</td><td className="p-4">{entry.actor}</td><td className="p-4">{entry.action}</td><td className="p-4">{entry.target || "—"}</td><td className="p-4"><details><summary className="cursor-pointer">Ver metadados</summary><pre className="mt-2 max-w-md overflow-x-auto whitespace-pre-wrap break-all text-xs">{JSON.stringify(entry.metadata, null, 2)}</pre></details></td></tr>)}</tbody></table>
      {audit.isPending ? <p role="status" className="p-5">Carregando auditoria…</p> : !rows.length ? <p className="p-5 text-sm text-ink-muted">Nenhuma ação corresponde aos filtros.</p> : null}
    </Card>
  </div>;
}
