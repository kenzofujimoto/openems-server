import { Link, useParams } from "@tanstack/react-router";
import { useState } from "react";
import { ErrorNotice, InfoNotice, PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { FIELD_CLASS } from "@/features/locations/LocationDialog";
import { formatDateTime } from "@/lib/format";
import { downloadCsv, moveEndpointRule, useProfiles, useSaveAssignmentRule, type Profile } from "@/lib/management";
import { useEndpointEvents, useEndpoints, useIsAdmin } from "@/lib/queries";
import type { Endpoint, EventKind } from "@/lib/schemas";
import { EndpointInventory } from "./EndpointInventory";
import { EndpointSummary } from "./EndpointSummary";

const TABS = ["Resumo", "Política", "Logs", "Inventário"] as const;
type Tab = (typeof TABS)[number];

const KIND_LABEL: Record<EventKind, string> = {
  web_block: "Site bloqueado", web_monitor: "Site monitorado", app_block: "App bloqueado",
  app_network_block: "Rede de app bloqueada", app_control_applied: "Política de execução aplicada",
  app_network_policy: "Política de rede aplicada", usb_block: "USB bloqueado", usb_read_only: "USB somente leitura",
  tamper: "Proteção do agente", policy_error: "Erro de política",
};
const FILTERS = { all: "Todos", web: "Web", apps: "Aplicativos", usb: "USB", protection: "Proteção" } as const;
type Filter = keyof typeof FILTERS;
function matches(filter: Filter, kind: EventKind) {
  if (filter === "all") return true;
  if (filter === "web") return kind.startsWith("web_");
  if (filter === "apps") return kind.startsWith("app_");
  if (filter === "usb") return kind.startsWith("usb_");
  return kind === "tamper" || kind === "policy_error";
}
const plural = (count: number, one: string, many: string) => `${count} ${count === 1 ? one : many}`;
const record = (value: unknown): Record<string, unknown> => value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {};
const list = (value: unknown): unknown[] => Array.isArray(value) ? value : [];

function PolicyTab({ endpoint, profile, profiles }: { endpoint: Endpoint; profile: Profile | undefined; profiles: Profile[] }) {
  const save = useSaveAssignmentRule();
  const isAdmin = useIsAdmin();
  const others = profiles.map((item) => item.vdom).filter((vdom) => vdom !== endpoint.effective_vdom);
  const [target, setTarget] = useState(others[0] ?? "");
  const body = record(profile?.body);
  const web = record(body.web_filter);
  const domainRules = list(web.domain_rules).map(record);
  const blocked = domainRules.filter((rule) => rule.action === "block").length + list(web.blocked).length;
  const allowed = domainRules.filter((rule) => rule.action === "allow").length + list(web.allowed).length;
  const categories = new Set([...list(web.blocked_categories).map(String),
    ...Object.entries(record(web.category_actions)).filter(([, action]) => action === "block").map(([id]) => id)]).size;
  const catalog = Object.keys(record(record(body.app_catalog).actions)).length;
  const manual = list(record(body.app_control).execution_rules).map(record).filter((rule) => !String(rule.id).startsWith("catalog-")).length;
  const usb = record(body.usb_control);
  const hostname = endpoint.hostname;
  return <div className="space-y-5">
    {profile ? <ul className="space-y-2 text-sm text-ink">
      <li>Grupo <strong>{profile.vdom}</strong> · versão v{profile.version}</li>
      <li>Filtro web: {plural(blocked, "domínio bloqueado", "domínios bloqueados")} · {plural(allowed, "permitido", "permitidos")}</li>
      <li>Categorias web bloqueadas: {categories}</li>
      <li>Catálogo de aplicativos: {plural(catalog, "decisão", "decisões")}</li>
      <li>Regras de execução manuais: {manual}</li>
      <li>USB: {usb.default_action === "block" ? "bloquear por padrão" : "liberado por padrão"} · {plural(list(usb.rules).length, "regra", "regras")}</li>
    </ul> : <InfoNotice>O grupo {endpoint.effective_vdom} ainda não tem política publicada: a máquina fica liberada.</InfoNotice>}
    {isAdmin && hostname ? <form className="flex flex-wrap items-end gap-3" onSubmit={(event) => {
      event.preventDefault();
      save.mutate(moveEndpointRule(hostname, target));
    }}>
      <label className="block text-sm text-ink-soft">Mover para o grupo<select className={`mt-1 ${FIELD_CLASS}`} value={target} onChange={(event) => setTarget(event.target.value)}>
        {others.map((vdom) => <option key={vdom} value={vdom}>{vdom}</option>)}
      </select></label>
      <Button type="submit" disabled={!target || save.isPending}>Mover máquina</Button>
      {save.isSuccess ? <p role="status" className="text-sm text-rsm-green">Regra de atribuição criada: {hostname} → {target}.</p> : null}
      {save.isError ? <p role="alert" className="text-sm text-danger">Não foi possível criar a regra de atribuição.</p> : null}
    </form> : null}
  </div>;
}

function LogsTab({ devid }: { devid: string }) {
  const events = useEndpointEvents(devid);
  const [filter, setFilter] = useState<Filter>("all");
  const rows = (events.data ?? []).filter((event) => matches(filter, event.kind));
  return <div className="space-y-4">
    <div className="flex flex-wrap items-end justify-between gap-3">
      <label className="block text-sm text-ink-soft">Tipo de evento<select className={`mt-1 ${FIELD_CLASS}`} value={filter} onChange={(event) => setFilter(event.target.value as Filter)}>
        {Object.entries(FILTERS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
      </select></label>
      <Button disabled={!rows.length} onClick={() => downloadCsv(`logs-${devid}.csv`, [["horario", "tipo", "detalhe", "motivo"],
        ...rows.map((event) => [event.at, event.kind, event.detail, event.category_label ?? event.reason ?? ""])])}>Exportar CSV</Button>
    </div>
    <p className="text-xs text-ink-muted">Registros desta máquina dentro da retenção configurada. Cada consulta fica registrada na auditoria.</p>
    {events.isPending ? <p role="status">Carregando logs…</p> : null}
    {events.isError ? <ErrorNotice message="Não foi possível carregar os logs." onRetry={() => void events.refetch()} /> : null}
    {events.isSuccess ? <div className="overflow-x-auto"><table aria-label="Logs da máquina" className="w-full text-left text-sm">
      <thead><tr className="border-b border-line text-ink-muted"><th className="py-2 pr-4 font-medium">Horário</th><th className="py-2 pr-4 font-medium">Tipo</th><th className="py-2 pr-4 font-medium">Detalhe</th><th className="py-2 font-medium">Motivo</th></tr></thead>
      <tbody>{rows.map((event) => <tr key={event.id} className="border-b border-line">
        <td className="py-2 pr-4 whitespace-nowrap">{formatDateTime(event.at)}</td><td className="py-2 pr-4">{KIND_LABEL[event.kind]}</td>
        <td className="py-2 pr-4 break-all">{event.detail}</td><td className="py-2">{event.category_label ?? event.reason ?? "—"}</td>
      </tr>)}</tbody>
    </table>{!rows.length ? <p className="py-4 text-sm text-ink-soft">Nenhum registro para este filtro.</p> : null}</div> : null}
  </div>;
}

export function EndpointDetailPage() {
  const { devid } = useParams({ from: "/endpoints/$devid" });
  const endpoints = useEndpoints();
  const profiles = useProfiles();
  const [tab, setTab] = useState<Tab>("Resumo");
  const endpoint = endpoints.data?.find((item) => item.devid === devid);
  if (endpoints.isPending) return <p role="status">Carregando máquina…</p>;
  if (!endpoint) return <div className="space-y-4"><PageHeader title="Máquina não encontrada" /><Link to="/endpoints" className="text-rsm-blue">Voltar aos endpoints</Link></div>;
  const profile = profiles.data?.find((item) => item.vdom === endpoint.effective_vdom);
  return <div className="space-y-6">
    <PageHeader title={endpoint.hostname || endpoint.devid} description={`${endpoint.devid} · grupo ${endpoint.effective_vdom}`} actions={<Link to="/endpoints" className="text-sm text-rsm-blue">Voltar aos endpoints</Link>} />
    <div role="tablist" aria-label="Ficha da máquina" className="flex flex-wrap gap-2 border-b border-line">
      {TABS.map((name) => <button key={name} type="button" role="tab" aria-selected={tab === name} onClick={() => setTab(name)}
        className={`-mb-px border-b-2 px-3 py-2 text-sm ${tab === name ? "border-rsm-blue text-rsm-blue" : "border-transparent text-ink-soft"}`}>{name}</button>)}
    </div>
    <Card role="tabpanel" aria-label={tab} className="p-5">
      {tab === "Resumo" ? <EndpointSummary endpoint={endpoint} /> : null}
      {tab === "Política" ? <PolicyTab endpoint={endpoint} profile={profile} profiles={profiles.data ?? []} /> : null}
      {tab === "Logs" ? <LogsTab devid={endpoint.devid} /> : null}
      {tab === "Inventário" ? <EndpointInventory devid={endpoint.devid} /> : null}
    </Card>
  </div>;
}
