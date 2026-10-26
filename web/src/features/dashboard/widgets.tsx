import type { LucideIcon } from "lucide-react";
import { AppWindow, Globe, ShieldAlert, TriangleAlert, Usb } from "lucide-react";
import { Bar, BarChart, CartesianGrid, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { Card, CardHeader } from "@/components/ui/Card";
import { cn } from "@/lib/cn";
import { formatNumber, relativeTime } from "@/lib/format";
import type { Endpoint, EventKind, FleetEvent, Overview } from "@/lib/schemas";
import type { FleetSummary } from "@/lib/status";

const SERIES = [
  { key: "web", label: "Web", color: "#009cde" },
  { key: "apps", label: "Aplicativos", color: "#27455c" },
  { key: "usb", label: "USB", color: "#3f9c35" },
] as const;

function shortDay(date: string): string {
  const [, month, day] = date.split("-");
  return `${day}/${month}`;
}

export function BlocksChart({ overview }: { overview: Overview }) {
  const data = overview.blocks_by_day.map((day) => ({ ...day, label: shortDay(day.date) }));
  return (
    <Card className="col-span-full flex flex-col xl:col-span-2">
      <CardHeader
        title="Bloqueios por dia"
        description="Web, aplicativos e USB nos últimos 7 dias"
        action={
          <ul className="flex gap-3 text-xs text-ink-soft">
            {SERIES.map((series) => (
              <li key={series.key} className="flex items-center gap-1.5">
                <span aria-hidden="true" className="size-2 rounded-sm" style={{ background: series.color }} />
                {series.label}
              </li>
            ))}
          </ul>
        }
      />
      <div className="h-72 min-h-72 flex-1 px-2 pt-4 pb-3">
        <ResponsiveContainer width="100%" height="100%">
          <BarChart data={data} barCategoryGap="28%">
            <CartesianGrid vertical={false} stroke="#eef0f2" />
            <XAxis dataKey="label" tickLine={false} axisLine={false} tick={{ fill: "#888b8d", fontSize: 12 }} />
            <YAxis tickLine={false} axisLine={false} width={40} tick={{ fill: "#888b8d", fontSize: 12 }} />
            <Tooltip
              cursor={{ fill: "#f6f7f9" }}
              contentStyle={{ borderRadius: 10, border: "1px solid var(--color-line)", background: "var(--color-surface)", color: "var(--color-ink)", fontSize: 13 }}
              formatter={(value) => formatNumber(Number(value))}
            />
            {SERIES.map((series, index) => (
              <Bar
                key={series.key}
                dataKey={series.key}
                name={series.label}
                stackId="blocks"
                fill={series.color}
                radius={index === SERIES.length - 1 ? [6, 6, 0, 0] : 0}
              />
            ))}
          </BarChart>
        </ResponsiveContainer>
      </div>
    </Card>
  );
}

const EVENT_STYLE: Record<EventKind, { icon: LucideIcon; label: string; tone: string }> = {
  web_block: { icon: Globe, label: "Site bloqueado", tone: "bg-rsm-blue-soft text-rsm-blue-dark" },
  app_block: { icon: AppWindow, label: "Aplicativo bloqueado", tone: "bg-[#e9eef2] text-rsm-navy" },
  app_network_block: { icon: AppWindow, label: "Conexão do aplicativo bloqueada", tone: "bg-rsm-blue-soft text-rsm-blue-dark" },
  app_control_applied: { icon: AppWindow, label: "Política de aplicativos aplicada", tone: "bg-rsm-green-soft text-rsm-green" },
  app_network_policy: { icon: AppWindow, label: "Regra de rede aplicada", tone: "bg-rsm-green-soft text-rsm-green" },
  usb_block: { icon: Usb, label: "USB bloqueado", tone: "bg-rsm-green-soft text-rsm-green" },
  usb_read_only: { icon: Usb, label: "USB em somente leitura", tone: "bg-warning-soft text-warning" },
  tamper: { icon: ShieldAlert, label: "Tentativa de adulteração", tone: "bg-warning-soft text-warning" },
  policy_error: { icon: TriangleAlert, label: "Erro de política", tone: "bg-danger-soft text-danger" },
};

// Agents send fixed English details; the panel names known tamper kinds in Portuguese.
const TAMPER_DETAIL: Record<string, string> = {
  dns_rule_restored: "Regra de DNS do agente recriada",
  wfp_restored: "Filtros de rede antiburla recriados",
  browser_policy_restored: "Políticas de DNS do navegador reaplicadas",
  hosts_restored: "Bloco gerenciado do hosts regravado",
  service_config_restored: "Início, recuperação ou permissões do serviço restaurados",
  watchdog_restored: "Tarefa agendada do watchdog recriada",
  service_started_by_watchdog: "Serviço parado foi iniciado pelo watchdog",
  unexpected_exit: "O agente terminou sem parada normal",
  uninstall_code_rejected: "Código de desinstalação recusado",
  uninstall_without_secret: "Agente removido sem segredo de desinstalação",
};

export function eventDetail(event: FleetEvent): string {
  const tamper = event.kind === "tamper" && event.reason ? TAMPER_DETAIL[event.reason] : undefined;
  if (tamper) return tamper;
  const count = event.count !== undefined && event.count > 1 ? `${formatNumber(event.count)}×` : null;
  return [event.detail, event.category_label, count].filter(Boolean).join(" · ");
}

export function RecentEvents({ events, wide = false, retentionDays }: { events: FleetEvent[]; wide?: boolean; retentionDays?: number }) {
  return (
    <Card className={cn("col-span-full", !wide && "xl:col-span-1")}>
      <CardHeader title="Eventos recentes" description="Últimas ocorrências nos endpoints" />
      <ul className="divide-y divide-line px-5 pt-3 pb-2">
        {events.length === 0 ? <li className="py-6 text-center text-sm text-ink-muted">Nenhum evento recente.</li> : null}
        {events.map((event) => {
          const style = EVENT_STYLE[event.kind];
          return (
            <li key={event.id} className="flex items-start gap-3 py-3">
              <span className={cn("mt-0.5 grid size-8 shrink-0 place-items-center rounded-lg", style.tone)}>
                <style.icon aria-hidden="true" className="size-4" />
              </span>
              <div className="min-w-0 flex-1">
                <p className="text-sm font-medium text-ink">{style.label}</p>
                <p className="truncate text-[13px] text-ink-soft">{eventDetail(event)}</p>
                <p className="mt-0.5 text-xs text-ink-muted">{event.devid} · {relativeTime(event.at)}</p>
              </div>
            </li>
          );
        })}
      </ul>
      {retentionDays !== undefined ? (
        <p className="border-t border-line px-5 py-3 text-xs text-ink-muted">
          O registro de bloqueios é dado pessoal de quem usa cada máquina e fica guardado por {retentionDays} dias.
        </p>
      ) : null}
    </Card>
  );
}

export function PolicyStatusCard({ summary }: { summary: FleetSummary }) {
  const rows = [
    { label: "Aplicada", value: summary.applied, color: "bg-rsm-green" },
    { label: "Pendente", value: summary.pending, color: "bg-warning" },
    { label: "Erro", value: summary.error, color: "bg-danger" },
    { label: "Offline", value: summary.offline, color: "bg-rsm-gray-mid" },
  ];
  const max = Math.max(1, ...rows.map((row) => row.value));
  return (
    <Card>
      <CardHeader title="Status da política" description="Confirmação enviada pelos agentes" />
      <ul className="space-y-3.5 px-5 pt-4 pb-5">
        {rows.map((row) => (
          <li key={row.label} className="grid grid-cols-[72px_1fr_32px] items-center gap-3 text-sm">
            <span className="text-ink-soft">{row.label}</span>
            <span className="h-2.5 overflow-hidden rounded-full bg-canvas" aria-hidden="true">
              <span className={cn("block h-full rounded-full", row.color)} style={{ width: `${(row.value / max) * 100}%` }} />
            </span>
            <span className="text-right font-medium text-ink">{row.value}</span>
          </li>
        ))}
      </ul>
    </Card>
  );
}

export function TopDomainsCard({ overview }: { overview: Overview }) {
  const total = overview.top_domains.reduce((sum, item) => sum + item.count, 0) || 1;
  return (
    <Card>
      <CardHeader title="Domínios mais bloqueados" description="Últimos 7 dias" />
      <ol className="space-y-3 px-5 pt-4 pb-5">
        {overview.top_domains.map((item, index) => (
          <li key={item.domain} className="flex items-center gap-3 text-sm">
            <span className="w-4 text-xs text-ink-muted">{index + 1}</span>
            <span data-domain className="min-w-0 flex-1 truncate text-ink">{item.domain}</span>
            <span className="text-ink-muted">{formatNumber(item.count)}</span>
            <span className="w-10 text-right font-medium text-ink">{Math.round((item.count / total) * 100)}%</span>
          </li>
        ))}
      </ol>
    </Card>
  );
}

function osFamily(os: string): string {
  const name = os.toLowerCase();
  if (name.includes("windows")) return "Windows";
  if (name.includes("mac")) return "macOS";
  if (name.includes("ubuntu") || name.includes("linux") || name.includes("debian") || name.includes("fedora")) return "Linux";
  return "Outros";
}

const OS_COLOR: Record<string, string> = { Windows: "#009cde", macOS: "#27455c", Linux: "#3f9c35", Outros: "#888b8d" };

export function OsBreakdownCard({ endpoints }: { endpoints: Endpoint[] }) {
  const counts = new Map<string, number>();
  for (const endpoint of endpoints) counts.set(osFamily(endpoint.os), (counts.get(osFamily(endpoint.os)) ?? 0) + 1);
  const total = endpoints.length || 1;
  const rows = [...counts.entries()].sort((a, b) => b[1] - a[1]);
  return (
    <Card>
      <CardHeader title="Sistemas operacionais" description={`${endpoints.length} endpoints cadastrados`} />
      <div className="px-5 pt-4 pb-5">
        <div className="flex h-3 overflow-hidden rounded-full bg-canvas" aria-hidden="true">
          {rows.map(([name, count]) => (
            <span key={name} style={{ width: `${(count / total) * 100}%`, background: OS_COLOR[name] }} />
          ))}
        </div>
        <ul className="mt-4 space-y-2.5">
          {rows.map(([name, count]) => (
            <li key={name} className="flex items-center gap-2.5 text-sm">
              <span aria-hidden="true" className="size-2.5 rounded-sm" style={{ background: OS_COLOR[name] }} />
              <span className="flex-1 text-ink-soft">{name}</span>
              <span className="font-medium text-ink">{count}</span>
            </li>
          ))}
        </ul>
      </div>
    </Card>
  );
}
