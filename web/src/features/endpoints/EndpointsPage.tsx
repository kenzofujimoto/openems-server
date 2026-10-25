import { Search } from "lucide-react";
import { useMemo, useState } from "react";
import { ErrorNotice, PageHeader } from "@/components/PageHeader";
import { ConnectionDot, PolicyBadge } from "@/components/StatusBadge";
import { Card } from "@/components/ui/Card";
import { cn } from "@/lib/cn";
import { relativeTime } from "@/lib/format";
import { useEndpoints, useIsAdmin } from "@/lib/queries";
import type { Endpoint } from "@/lib/schemas";
import { connectionStatus, policyStatus } from "@/lib/status";
import { EndpointSheet } from "./EndpointSheet";
import { ReleaseDialog } from "./ReleaseDialog";

type Filter = "all" | "applied" | "pending" | "error" | "offline";

const FILTERS: Array<{ id: Filter; label: string }> = [
  { id: "all", label: "Todos" },
  { id: "applied", label: "Aplicada" },
  { id: "pending", label: "Pendente" },
  { id: "error", label: "Erro" },
  { id: "offline", label: "Offline" },
];

function matches(endpoint: Endpoint, filter: Filter, query: string): boolean {
  if (filter === "offline" && connectionStatus(endpoint) === "online") return false;
  if (filter !== "all" && filter !== "offline" && policyStatus(endpoint) !== filter) return false;
  if (!query) return true;
  const needle = query.toLowerCase();
  return [endpoint.devid, endpoint.hostname, endpoint.os, endpoint.effective_vdom].some((value) => value.toLowerCase().includes(needle));
}

export function EndpointsPage() {
  const endpoints = useEndpoints();
  const [filter, setFilter] = useState<Filter>("all");
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const rows = useMemo(() => (endpoints.data ?? []).filter((endpoint) => matches(endpoint, filter, query.trim())), [endpoints.data, filter, query]);
  const selectedEndpoint = endpoints.data?.find((endpoint) => endpoint.devid === selected) ?? null;
  const isAdmin = useIsAdmin();
  const groups = useMemo(
    () => [...new Set((endpoints.data ?? []).map((endpoint) => endpoint.effective_vdom))].sort((a, b) => a.localeCompare(b)),
    [endpoints.data],
  );

  return (
    <div className="space-y-6">
      <PageHeader
        title="Endpoints"
        description={`${endpoints.data?.length ?? 0} dispositivos cadastrados`}
        actions={isAdmin ? <ReleaseDialog groups={groups} /> : null}
      />
      {endpoints.isError ? <ErrorNotice message="Não foi possível carregar os endpoints." onRetry={() => void endpoints.refetch()} /> : null}
      <Card>
        <div className="flex flex-wrap items-center justify-between gap-3 border-b border-line px-5 py-4">
          <div className="flex flex-wrap gap-1 rounded-lg bg-canvas p-1">
            {FILTERS.map((item) => (
              <button
                key={item.id}
                type="button"
                aria-pressed={filter === item.id}
                onClick={() => setFilter(item.id)}
                className={cn(
                  "rounded-md px-3 py-1.5 text-sm text-ink-soft hover:text-ink",
                  filter === item.id && "bg-surface font-medium text-ink shadow-sm",
                )}
              >
                {item.label}
              </button>
            ))}
          </div>
          <label className="relative block w-full max-w-xs">
            <Search aria-hidden="true" className="pointer-events-none absolute top-1/2 left-3 size-4 -translate-y-1/2 text-ink-muted" />
            <input
              type="search"
              aria-label="Buscar endpoints"
              placeholder="Buscar por nome, ID ou grupo"
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              className="h-9 w-full rounded-lg border border-line pr-3 pl-9 text-sm outline-none focus:border-rsm-blue"
            />
          </label>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-ink-muted">
                <th className="px-5 py-3 font-medium">Dispositivo</th>
                <th className="px-5 py-3 font-medium">Sistema</th>
                <th className="px-5 py-3 font-medium">Grupo</th>
                <th className="px-5 py-3 font-medium">Conexão</th>
                <th className="px-5 py-3 font-medium">Política</th>
                <th className="px-5 py-3 font-medium">Último contato</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line border-t border-line">
              {rows.map((endpoint) => (
                <tr key={endpoint.devid} className="hover:bg-canvas/60">
                  <td className="px-5 py-3">
                    <button
                      type="button"
                      aria-label={`Abrir ${endpoint.devid}`}
                      onClick={() => setSelected(endpoint.devid)}
                      className="text-left"
                    >
                      <span className="block font-medium text-ink hover:text-rsm-blue-dark">{endpoint.hostname || endpoint.devid}</span>
                      <span className="block text-xs text-ink-muted">{endpoint.devid}</span>
                    </button>
                  </td>
                  <td className="px-5 py-3 text-ink-soft">{endpoint.os || "—"}</td>
                  <td className="px-5 py-3 text-ink-soft">{endpoint.effective_vdom}</td>
                  <td className="px-5 py-3"><ConnectionDot status={connectionStatus(endpoint)} /></td>
                  <td className="px-5 py-3"><PolicyBadge status={policyStatus(endpoint)} /></td>
                  <td className="px-5 py-3 text-ink-soft">{relativeTime(endpoint.last_seen)}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {rows.length === 0 && endpoints.isSuccess ? (
            <p className="px-5 py-10 text-center text-sm text-ink-muted">Nenhum endpoint corresponde aos filtros.</p>
          ) : null}
        </div>
      </Card>
      <EndpointSheet endpoint={selectedEndpoint} onClose={() => setSelected(null)} />
    </div>
  );
}
