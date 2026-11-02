import * as Dialog from "@radix-ui/react-dialog";
import type { LucideIcon } from "lucide-react";
import {
  AppWindow, Ban, Bitcoin, Bug, CircleCheck, CircleDashed, Cloud, Compass, Download, Gamepad2, GlobeLock, Layers, Mail, MessageCircle,
  MonitorSmartphone, Music, Plus, Search, Share2, ShieldOff, Sparkles, Trash2, Users, X,
} from "lucide-react";
import { useId, useState } from "react";
import { InfoNotice } from "@/components/PageHeader";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader } from "@/components/ui/Card";
import { cn } from "@/lib/cn";
import { formatNumber } from "@/lib/format";
import { useAppCatalog, useAppCatalogSearch } from "@/lib/management";

export type CatalogAction = "allow" | "block" | "block_network";
export const CATALOG_ACTIONS: readonly CatalogAction[] = ["allow", "block", "block_network"];
export type CatalogActions = Record<string, CatalogAction>;
interface CatalogApp { id: string; name: string; vendor: string; category: string | null; blockable: boolean; observed_endpoints: number }

const machines = (count: number) => `${formatNumber(count)} ${count === 1 ? "máquina" : "máquinas"}`;

const OPTIONS: ReadonlyArray<{ value: CatalogAction | undefined; label: string; icon: LucideIcon; tone: string; tile: string }> = [
  { value: undefined, label: "Sem regra", icon: CircleDashed, tone: "peer-checked:border-idle peer-checked:bg-idle-soft peer-checked:text-ink", tile: "bg-idle-soft text-idle" },
  { value: "allow", label: "Permitir", icon: CircleCheck, tone: "peer-checked:border-allow peer-checked:bg-allow-soft peer-checked:text-allow", tile: "bg-allow-soft text-allow" },
  { value: "block", label: "Bloquear", icon: Ban, tone: "peer-checked:border-block peer-checked:bg-block-soft peer-checked:text-block", tile: "bg-block-soft text-block" },
  { value: "block_network", label: "Bloquear rede", icon: GlobeLock, tone: "peer-checked:border-netblock peer-checked:bg-netblock-soft peer-checked:text-netblock", tile: "bg-netblock-soft text-netblock" },
];
const tileTone = (value: CatalogAction | undefined) => OPTIONS.find((item) => item.value === value)?.tile ?? "bg-idle-soft text-idle";

const CATEGORY_ICONS: Record<string, LucideIcon> = {
  p2p: Share2, proxy_vpn: ShieldOff, remote_access: MonitorSmartphone, crypto: Bitcoin, hacking: Bug, games: Gamepad2, cloud_storage: Cloud,
  messaging: MessageCircle, social: Users, media: Music, browser: Compass, ai: Sparkles, email: Mail, download: Download,
};

/** Segmented radios; `allowEmpty` adds "Sem regra" (categories), overrides always carry an action. */
function Decision({ label, value, onChange, disabled, allowEmpty = true }: { label: string; value: CatalogAction | undefined; onChange: (value: CatalogAction | undefined) => void; disabled?: boolean; allowEmpty?: boolean }) {
  const name = useId();
  return <div className="flex flex-wrap gap-1" role="radiogroup" aria-label={`Decisão para ${label}`}>
    {OPTIONS.filter((item) => allowEmpty || item.value).map(({ value: current, label: text, icon: Icon, tone }) => <label key={text} className="cursor-pointer">
      <input type="radio" name={name} className="peer sr-only" aria-label={`${text} ${label}`} checked={value === current} disabled={(current === "block" || current === "block_network") && disabled} onChange={() => onChange(current)} />
      <span className={cn("flex items-center gap-1 rounded-md border border-line px-2 py-1 text-xs whitespace-nowrap text-ink-soft peer-checked:font-medium peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-brand peer-disabled:cursor-not-allowed peer-disabled:opacity-50", tone)}><Icon aria-hidden="true" className="size-3.5" />{text}</span>
    </label>)}
  </div>;
}

function without(actions: CatalogActions, key: string) { return Object.fromEntries(Object.entries(actions).filter(([current]) => current !== key)); }

/** Category decisions shown as a grid, with one action for all categories at once. */
export function AppCategoryGrid({ actions, onChange, readonly }: { actions: CatalogActions; onChange: (actions: CatalogActions) => void; readonly: boolean }) {
  const catalog = useAppCatalog();
  const [bulk, setBulk] = useState<string>("block");
  const set = (key: string, value: CatalogAction | undefined) => onChange(value ? { ...without(actions, key), [key]: value } : without(actions, key));
  const categories = catalog.data?.categories ?? [];
  return <Card aria-label="Catálogo de aplicativos">
    <CardHeader title="Categorias de aplicativos" description={catalog.data?.available ? `${categories.length} categorias${catalog.data.version ? ` · catálogo de ${new Date(catalog.data.version).toLocaleDateString("pt-BR")}` : ""}` : undefined}
      action={catalog.data?.available && !readonly ? <div className="flex items-center gap-2">
        <label className="flex items-center gap-2 text-sm text-ink-soft"><Layers aria-hidden="true" className="size-4" /><span>Todas as categorias<span className="sr-only">: ação</span></span>
          <select value={bulk} onChange={(event) => setBulk(event.target.value)} className="h-8 rounded-md border border-line-strong bg-surface px-2 text-sm text-ink">
            <option value="none">Sem regra</option><option value="allow">Permitir</option><option value="block">Bloquear</option><option value="block_network">Bloquear rede</option>
          </select></label>
        <Button size="sm" onClick={() => {
          const rest = Object.fromEntries(Object.entries(actions).filter(([key]) => !key.startsWith("category:")));
          onChange(bulk === "none" ? rest : { ...rest, ...Object.fromEntries(categories.map((category) => [`category:${category.id}`, bulk as CatalogAction])) });
        }}>Aplicar a todas</Button>
      </div> : null} />
    <div className="space-y-4 p-5">
      {catalog.isPending ? <p role="status">Carregando catálogo…</p> : null}
      {catalog.data && !catalog.data.available ? <InfoNotice>O catálogo ainda não foi publicado no servidor. Confira o serviço app-catalog antes de usar categorias de aplicativos.</InfoNotice> : null}
      {catalog.data?.available ? <>
        <ul className="grid gap-2 lg:grid-cols-2">{categories.map((category) => {
          const value = actions[`category:${category.id}`];
          const Icon = CATEGORY_ICONS[category.id] ?? AppWindow;
          return <li key={category.id} className="flex items-start gap-3 rounded-lg border border-line px-3 py-2.5">
            <span aria-hidden="true" className={cn("grid size-8 shrink-0 place-items-center rounded-md", tileTone(value))}><Icon className="size-4" /></span>
            <div className="min-w-0 flex-1 space-y-2">
              <div><p className="text-sm font-medium text-ink">{category.label}</p><p className="text-xs text-ink-muted">{formatNumber(category.apps)} apps · vistos em {machines(category.observed_endpoints)}</p></div>
              <Decision label={category.label} value={value} onChange={(next) => set(`category:${category.id}`, next)} />
            </div>
          </li>;
        })}</ul>
        <p className="text-xs text-ink-muted">Bloquear impede a execução (WDAC, quando o Windows suporta) e encerra o processo em qualquer edição. Bloquear rede deixa o aplicativo abrir sem acesso à internet. As regras só valem nas máquinas onde o aplicativo existe. {catalog.data.attribution}</p>
      </> : null}
    </div>
  </Card>;
}

function OverrideDialog({ onClose, onAdd }: { onClose: () => void; onAdd: (apps: CatalogApp[], action: CatalogAction) => void }) {
  const [query, setQuery] = useState("");
  const [action, setAction] = useState<CatalogAction>("block");
  const [picked, setPicked] = useState<CatalogApp[]>([]);
  const results = useAppCatalogSearch(query);
  const catalog = useAppCatalog();
  const labels = new Map(catalog.data?.categories.map((category) => [category.id, category.label]));
  const name = useId();
  const blocking = action !== "allow";
  const selectable = (app: CatalogApp) => app.blockable || !blocking;
  const chosen = picked.filter(selectable);
  return <Dialog.Root open onOpenChange={(open) => { if (!open) onClose(); }}><Dialog.Portal>
    <Dialog.Overlay className="fixed inset-0 z-40 bg-night/50" />
    <Dialog.Content className="fixed top-1/2 left-1/2 z-50 flex max-h-[90vh] w-[calc(100%-2rem)] max-w-3xl -translate-x-1/2 -translate-y-1/2 flex-col overflow-hidden rounded-xl border border-line bg-surface text-ink shadow-2xl">
      <div className="flex items-start gap-3 border-b border-line px-5 py-4">
        <div><Dialog.Title className="text-base font-semibold">Novo override</Dialog.Title><Dialog.Description className="mt-0.5 text-sm text-ink-muted">A decisão por aplicativo vence a da categoria e só vale onde o aplicativo existe.</Dialog.Description></div>
        <Dialog.Close aria-label="Fechar" className="ml-auto rounded p-1 text-ink-muted hover:text-ink"><X aria-hidden="true" className="size-5" /></Dialog.Close>
      </div>
      <div className="space-y-4 overflow-y-auto px-5 py-4">
        <div><p className="mb-1.5 text-xs font-semibold text-ink-soft">Ação</p>
          <div role="radiogroup" aria-label="Ação do override" className="inline-flex gap-1 rounded-lg border border-line-strong p-0.5">
            {OPTIONS.flatMap(({ value, ...item }) => value ? [{ value, ...item }] : []).map(({ value, label, icon: Icon, tone }) => <label key={label} className="cursor-pointer">
              <input type="radio" name={name} className="peer sr-only" aria-label={label} checked={action === value} onChange={() => setAction(value)} />
              <span className={cn("flex items-center gap-1.5 rounded-md border border-transparent px-3 py-1.5 text-sm font-medium text-ink-soft peer-focus-visible:outline-2 peer-focus-visible:outline-brand", tone)}><Icon aria-hidden="true" className="size-4" />{label}</span>
            </label>)}
          </div>
        </div>
        <label className="flex h-9 items-center gap-2 rounded-md border border-line-strong px-3 text-sm text-ink-muted"><Search aria-hidden="true" className="size-4" /><span className="sr-only">Buscar aplicativo</span>
          <input autoFocus value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Buscar aplicativo pelo nome (mínimo de 2 letras)" className="w-full bg-transparent text-ink outline-none" /></label>
        <div className="overflow-hidden rounded-lg border border-line">
          <table aria-label="Resultados do catálogo" className="w-full text-left text-sm">
            <thead className="bg-surface-2 text-xs text-ink-soft"><tr><th scope="col" className="w-10 px-3 py-2"><span className="sr-only">Seleção</span></th><th scope="col" className="px-2 py-2 font-semibold">Aplicativo</th><th scope="col" className="px-2 py-2 font-semibold">Categoria</th><th scope="col" className="px-3 py-2 text-right font-semibold">Máquinas</th></tr></thead>
            <tbody className="divide-y divide-line">
              {results.data?.map((app) => <tr key={app.id} className={cn(picked.some((item) => item.id === app.id) && selectable(app) && "bg-brand-soft/60")}>
                <td className="px-3 py-2"><input type="checkbox" className="size-4 accent-brand" aria-label={`Selecionar ${app.name}`} disabled={!selectable(app)} checked={picked.some((item) => item.id === app.id) && selectable(app)} onChange={(event) => setPicked((current) => event.target.checked ? [...current, app] : current.filter((item) => item.id !== app.id))} /></td>
                <td className="px-2 py-2"><p className="font-medium text-ink">{app.name} <span className="font-mono text-xs font-normal text-ink-muted">{app.id}</span></p><p className="text-xs text-ink-muted">{app.vendor || "Editor desconhecido"}{app.blockable ? "" : " · Microsoft: não bloqueável"}</p></td>
                <td className="px-2 py-2 text-ink-soft">{app.category ? labels.get(app.category) ?? app.category : "Sem categoria"}</td>
                <td className="px-3 py-2 text-right text-ink-soft tabular-nums">{formatNumber(app.observed_endpoints)}</td>
              </tr>)}
              {results.isSuccess && !results.data.length ? <tr><td colSpan={4} className="px-3 py-6 text-center text-ink-muted">Nenhum aplicativo encontrado.</td></tr> : null}
              {!results.data ? <tr><td colSpan={4} className="px-3 py-6 text-center text-ink-muted">{results.isFetching ? "Buscando…" : "Digite para buscar no catálogo."}</td></tr> : null}
            </tbody>
          </table>
        </div>
        {chosen.length ? <div className="flex flex-wrap items-center gap-2 text-sm"><span className="text-xs font-semibold text-ink-soft">Selecionados</span>{chosen.map((app) => <span key={app.id} className="inline-flex items-center gap-1 rounded-md border border-line-strong px-2 py-0.5">{app.name}<button type="button" aria-label={`Remover ${app.name} da seleção`} onClick={() => setPicked((current) => current.filter((item) => item.id !== app.id))}><X aria-hidden="true" className="size-3.5" /></button></span>)}</div> : null}
      </div>
      <div className="flex justify-end gap-2 border-t border-line bg-surface-2 px-5 py-3">
        <Button onClick={onClose}>Cancelar</Button>
        <Button variant="primary" disabled={!chosen.length} onClick={() => onAdd(chosen, action)}>Adicionar override</Button>
      </div>
    </Dialog.Content>
  </Dialog.Portal></Dialog.Root>;
}

/** Per-application decisions (`app:<id>`), listed so the exceptions in force are always visible. */
export function AppOverrides({ actions, onChange, readonly }: { actions: CatalogActions; onChange: (actions: CatalogActions) => void; readonly: boolean }) {
  const catalog = useAppCatalog();
  const [adding, setAdding] = useState(false);
  const [known, setKnown] = useState<Record<string, CatalogApp>>({});
  const labels = new Map(catalog.data?.categories.map((category) => [category.id, category.label]));
  const overrides = Object.entries(actions).filter(([key]) => key.startsWith("app:")).map(([key, value]) => ({ key, id: key.slice(4), value }));
  if (!catalog.data?.available) return null;
  return <Card aria-label="Overrides de aplicativos">
    <CardHeader title="Overrides de aplicativos" description="Decisões por aplicativo; valem antes da categoria." action={!readonly ? <Button size="sm" variant="primary" onClick={() => setAdding(true)}><Plus aria-hidden="true" className="size-4" />Criar override</Button> : null} />
    <div className="p-5">
      <div className="overflow-x-auto rounded-lg border border-line">
        <table aria-label="Overrides de aplicativos" className="w-full text-left text-sm">
          <thead className="bg-surface-2 text-xs text-ink-soft"><tr><th scope="col" className="px-3 py-2 font-semibold">Aplicativo</th><th scope="col" className="px-3 py-2 font-semibold">Categoria</th><th scope="col" className="px-3 py-2 font-semibold">Ação</th><th scope="col" className="px-3 py-2"><span className="sr-only">Gerenciar</span></th></tr></thead>
          <tbody className="divide-y divide-line">
            {overrides.map(({ key, id, value }) => {
              const app = known[id];
              const label = app?.name ?? id;
              return <tr key={key}>
                <td className="px-3 py-2"><p className="font-medium text-ink">{label}</p>{app ? <p className="font-mono text-xs text-ink-muted">{id}</p> : null}</td>
                <td className="px-3 py-2 text-ink-soft">{app?.category ? labels.get(app.category) ?? app.category : "—"}</td>
                <td className="px-3 py-2"><Decision allowEmpty={false} label={label} value={value} disabled={app ? !app.blockable : false} onChange={(next) => next && onChange({ ...actions, [key]: next })} /></td>
                <td className="px-3 py-2 text-right">{!readonly ? <Button size="sm" variant="ghost" aria-label={`Remover override de ${label}`} onClick={() => onChange(without(actions, key))}><Trash2 aria-hidden="true" className="size-4" /></Button> : null}</td>
              </tr>;
            })}
            {!overrides.length ? <tr><td colSpan={4} className="px-3 py-8 text-center text-ink-muted">Nenhum override. Os aplicativos seguem a decisão da categoria.</td></tr> : null}
          </tbody>
        </table>
      </div>
    </div>
    {adding ? <OverrideDialog onClose={() => setAdding(false)} onAdd={(apps, action) => {
      setKnown((current) => ({ ...current, ...Object.fromEntries(apps.map((app) => [app.id, app])) }));
      onChange({ ...actions, ...Object.fromEntries(apps.map((app) => [`app:${app.id}`, action])) });
      setAdding(false);
    }} /> : null}
  </Card>;
}
