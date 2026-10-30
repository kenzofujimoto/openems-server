import { useState } from "react";
import { InfoNotice } from "@/components/PageHeader";
import { Card, CardHeader } from "@/components/ui/Card";
import { formatNumber } from "@/lib/format";
import { useAppCatalog, useAppCatalogSearch } from "@/lib/management";
import { FIELD_CLASS } from "./PolicyWorkspace";

export type CatalogAction = "allow" | "block";
export type CatalogActions = Record<string, CatalogAction>;

const machines = (count: number) => `${formatNumber(count)} ${count === 1 ? "máquina" : "máquinas"}`;

function Decision({ name, label, value, onChange, disabled, readonly }: { name: string; label: string; value: CatalogAction | undefined; onChange: (value: CatalogAction | undefined) => void; disabled?: boolean; readonly: boolean }) {
  const options: Array<[CatalogAction | undefined, string]> = [[undefined, "Sem regra"], ["allow", "Permitir"], ["block", "Bloquear"]];
  return <div className="flex flex-wrap gap-2" role="radiogroup" aria-label={`Decisão para ${label}`}>
    {options.map(([option, text]) => <label key={text} className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs ${value === option ? "border-rsm-blue bg-rsm-blue-soft text-rsm-blue" : "border-line text-ink-soft"}`}>
      <input type="radio" name={name} aria-label={`${text} ${label}`} checked={value === option} disabled={readonly || (option === "block" && disabled)} onChange={() => onChange(option)} />{text}
    </label>)}
  </div>;
}

/** Category and per-application decisions; the server expands them into present-only rules. */
export function AppCatalogSection({ actions, onChange, readonly }: { actions: CatalogActions; onChange: (actions: CatalogActions) => void; readonly: boolean }) {
  const catalog = useAppCatalog();
  const [query, setQuery] = useState("");
  const results = useAppCatalogSearch(query);
  const labels = new Map(catalog.data?.categories.map((category) => [category.id, category.label]));
  const set = (key: string, value: CatalogAction | undefined) => {
    const next = Object.fromEntries(Object.entries(actions).filter(([current]) => current !== key));
    onChange(value ? { ...next, [key]: value } : next);
  };
  return <Card aria-label="Catálogo de aplicativos">
    <CardHeader title="Catálogo de aplicativos" description="Bloqueie categorias inteiras e libere ou bloqueie aplicativos específicos. A regra só vale nas máquinas onde o aplicativo existe." />
    <div className="space-y-5 p-5">
      {catalog.isPending ? <p role="status">Carregando catálogo…</p> : null}
      {catalog.data && !catalog.data.available ? <InfoNotice>O catálogo ainda não foi publicado no servidor. Confira o serviço app-catalog antes de usar categorias de aplicativos.</InfoNotice> : null}
      {catalog.data?.available ? <>
        <ul className="divide-y divide-line">{catalog.data.categories.map((category) => <li key={category.id} className="flex flex-wrap items-center justify-between gap-3 py-2.5">
          <div><p className="text-sm font-medium text-ink">{category.label}</p><p className="text-xs text-ink-soft">{formatNumber(category.apps)} apps · vistos em {machines(category.observed_endpoints)}</p></div>
          <Decision name={`category-${category.id}`} label={category.label} value={actions[`category:${category.id}`]} onChange={(value) => set(`category:${category.id}`, value)} readonly={readonly} />
        </li>)}</ul>
        <div className="space-y-3">
          <label className="block max-w-sm text-sm text-ink-soft">Buscar aplicativo<input className={`mt-1 ${FIELD_CLASS}`} value={query} onChange={(event) => setQuery(event.target.value)} /></label>
          {results.data?.map((app) => <article key={app.id} className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-line p-3">
            <div className="text-sm"><p className="font-medium text-ink">{app.name}</p><p className="text-xs text-ink-soft">{app.vendor || "Editor desconhecido"} · {app.category ? labels.get(app.category) ?? app.category : "Sem categoria"} · {machines(app.observed_endpoints)}{app.blockable ? "" : " · Microsoft: não bloqueável"}</p></div>
            <Decision name={`app-${app.id}`} label={app.name} value={actions[`app:${app.id}`]} onChange={(value) => set(`app:${app.id}`, value)} disabled={!app.blockable} readonly={readonly} />
          </article>)}
          {results.isSuccess && !results.data.length ? <p className="text-sm text-ink-soft">Nenhum aplicativo encontrado.</p> : null}
        </div>
        <p className="text-xs text-ink-muted">{catalog.data.attribution}</p>
      </> : null}
    </div>
  </Card>;
}
