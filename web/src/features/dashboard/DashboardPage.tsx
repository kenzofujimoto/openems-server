import { CircleCheck, Monitor, ShieldBan, ShieldCheck, TriangleAlert } from "lucide-react";
import { KpiCard } from "@/components/KpiCard";
import { ErrorNotice, InfoNotice, PageHeader } from "@/components/PageHeader";
import { formatDelta, formatNumber, relativeTime } from "@/lib/format";
import { useEndpoints, useEvents, useOverview } from "@/lib/queries";
import { summarize } from "@/lib/status";
import { BlocksChart, OsBreakdownCard, PolicyStatusCard, RecentEvents, TopDomainsCard } from "./widgets";

const CAPTION = "vs. semana passada";

export function DashboardPage() {
  const endpoints = useEndpoints();
  const overview = useOverview();
  const events = useEvents();
  const summary = summarize(endpoints.data ?? []);
  const previous = overview.data?.previous_period;
  const blocks = overview.data?.blocks_by_day.reduce((sum, day) => sum + day.web + day.apps + day.usb, 0);
  const appliedPercent = summary.total ? Math.round((summary.applied / summary.total) * 100) : 0;

  return (
    <div className="space-y-6">
      <PageHeader
        title="Visão geral"
        description={
          endpoints.dataUpdatedAt ? (
            <span className="inline-flex items-center gap-1.5 text-rsm-green">
              <CircleCheck aria-hidden="true" className="size-4" />
              Atualizado {relativeTime(new Date(endpoints.dataUpdatedAt).toISOString())}
            </span>
          ) : "Carregando dados da frota…"
        }
      />

      {endpoints.isError ? <ErrorNotice message="Não foi possível carregar os endpoints." onRetry={() => void endpoints.refetch()} /> : null}

      <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
        <KpiCard label="Endpoints online" value={formatNumber(summary.online)} icon={Monitor}
          delta={previous?.online !== undefined ? formatDelta(summary.online, previous.online) : undefined} caption={CAPTION} />
        <KpiCard label="Política aplicada" value={`${appliedPercent}%`} icon={ShieldCheck}
          delta={previous?.applied !== undefined ? formatDelta(summary.applied, previous.applied) : undefined} caption={CAPTION} />
        <KpiCard label="Bloqueios (7 dias)" value={blocks === undefined ? "—" : formatNumber(blocks)} icon={ShieldBan}
          delta={previous && blocks !== undefined ? formatDelta(blocks, previous.blocks) : undefined} caption={CAPTION} />
        <KpiCard label="Erros de aplicação" value={formatNumber(summary.error)} icon={TriangleAlert}
          delta={previous?.errors !== undefined ? formatDelta(summary.error, previous.errors) : undefined} caption={CAPTION} invertTone />
      </div>

      {overview.isError ? <ErrorNotice message="Não foi possível carregar as estatísticas." onRetry={() => void overview.refetch()} /> : null}
      {overview.data === null ? (
        <InfoNotice>Estatísticas de bloqueio chegam com o agente nativo (entregas F1 e F2 do roadmap). Os dados da frota abaixo já são reais.</InfoNotice>
      ) : null}

      <div className="grid gap-4 xl:grid-cols-3">
        {overview.data ? <BlocksChart overview={overview.data} /> : null}
        <RecentEvents events={events.data ?? []} wide={!overview.data} retentionDays={overview.data?.retention_days} />
      </div>

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        <PolicyStatusCard summary={summary} />
        {overview.data ? <TopDomainsCard overview={overview.data} /> : null}
        <OsBreakdownCard endpoints={endpoints.data ?? []} />
      </div>
    </div>
  );
}
