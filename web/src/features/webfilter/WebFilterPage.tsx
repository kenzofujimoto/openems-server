import { useState } from "react";
import { z } from "zod";
import { ErrorNotice } from "@/components/PageHeader";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader } from "@/components/ui/Card";
import { WebActionSelector, type CategoryActions } from "@/components/ui/WebActionSelector";
import { formatDateTime, formatNumber } from "@/lib/format";
import { useCategories } from "@/lib/queries";
import type { Category } from "@/lib/schemas";
import type { Profile } from "@/lib/management";
import { FIELD_CLASS, Field, lines, PolicyForm, PolicyWorkspace, record, strings, TextArea } from "@/features/policies/PolicyWorkspace";

function byGroup(categories: Category[]): [string, Category[]][] {
  const groups = new Map<string, Category[]>();
  for (const category of categories) groups.set(category.group, [...(groups.get(category.group) ?? []), category]);
  return [...groups.entries()];
}

const DAYS = [["mon", "Segunda"], ["tue", "Terça"], ["wed", "Quarta"], ["thu", "Quinta"], ["fri", "Sexta"], ["sat", "Sábado"], ["sun", "Domingo"]] as const;
const ENGINES = [["google", "Google"], ["bing", "Bing"], ["youtube", "YouTube"], ["duckduckgo", "DuckDuckGo"]] as const;
interface Window { days: string[]; from: string; to: string; blocked: string[]; category_actions?: CategoryActions }
function categoryActions(settings: Record<string, unknown>): CategoryActions {
  const actions: CategoryActions = Object.fromEntries(strings(settings.blocked_categories).map((id) => [id, "block"]));
  for (const [id, action] of Object.entries(record(settings.category_actions))) if (action === "allow" || action === "block" || action === "monitor") actions[id] = action;
  return actions;
}
function validDomains(rules: string[]) {
  for (const rule of rules) {
    const host = rule.replace(/^\*\./, "");
    let normalized = "";
    try { normalized = new URL(`http://${host}`).hostname; } catch { /* Validation below reports the same useful error for every malformed rule. */ }
    if (/[\s/:@?#%\\*]/.test(host) || host.endsWith(".") || !z.hostname().safeParse(normalized).success || z.ipv4().safeParse(host).success || !host.includes(".")) throw new Error("Informe um domínio válido, como example.com ou *.example.com, sem URL ou caminho.");
  }
  return rules;
}

function WebEditor({ profile, vdom, readonly }: { profile: Profile | undefined; vdom: string; readonly: boolean }) {
  const categories = useCategories();
  const published = categories.data?.categories ?? [];
  const settings = record(profile?.body.web_filter);
  const safe = record(settings.safe_search);
  const [blocked, setBlocked] = useState(strings(settings.blocked).join("\n"));
  const [allowed, setAllowed] = useState(strings(settings.allowed).join("\n"));
  const [actions, setActions] = useState(() => categoryActions(settings));
  const [monitorAll, setMonitorAll] = useState(settings.monitor_all === true);
  const [engines, setEngines] = useState(strings(safe.engines));
  const [youtube, setYoutube] = useState(typeof safe.youtube === "string" ? safe.youtube : "strict");
  const [timezone, setTimezone] = useState(typeof settings.timezone === "string" ? settings.timezone : "America/Sao_Paulo");
  const [windows, setWindows] = useState<Window[]>(() => Array.isArray(settings.scheduled) ? settings.scheduled.map((value) => { const window = record(value); const actions = categoryActions(window); return { days: strings(window.days), from: String(window.from ?? "08:00"), to: String(window.to ?? "18:00"), blocked: strings(window.blocked), ...(Object.keys(actions).length ? { category_actions: actions } : {}) }; }) : []);
  const toggle = (values: string[], value: string) => values.includes(value) ? values.filter((item) => item !== value) : [...values, value];
  const updateWindow = (index: number, patch: Partial<Window>) => setWindows((values) => values.map((window, at) => at === index ? { ...window, ...patch } : window));
  return <PolicyForm profile={profile} vdom={vdom} section="web_filter" readonly={readonly} build={() => {
    const next: Record<string, unknown> = { ...settings, blocked: validDomains(lines(blocked)), allowed: validDomains(lines(allowed)) };
    delete next.blocked_categories;
    if (Object.keys(actions).length) next.category_actions = actions; else delete next.category_actions;
    if (monitorAll) next.monitor_all = true; else delete next.monitor_all;
    if (engines.length) next.safe_search = { engines, youtube }; else delete next.safe_search;
    if (windows.length) {
      try { new Intl.DateTimeFormat("pt-BR", { timeZone: timezone }).format(); } catch { throw new Error("Informe um fuso horário IANA válido."); }
      next.timezone = timezone;
      next.scheduled = windows.map((window) => {
        if (!window.days.length || !/^\d\d:\d\d$/.test(window.from) || window.from >= window.to) throw new Error("Cada horário precisa de dias e de início anterior ao fim. Divida períodos que atravessam a meia-noite.");
        return { ...window, blocked: validDomains(window.blocked) };
      });
    } else { delete next.scheduled; delete next.timezone; }
    return next;
  }}>
    <Card><CardHeader title="Domínios" description="Permitidos têm prioridade e não geram log de navegação. Use *.example.com para o domínio e seus subdomínios." /><div className="grid gap-4 p-5 md:grid-cols-2"><TextArea label="Domínios bloqueados" value={blocked} onChange={setBlocked} /><TextArea label="Domínios permitidos" value={allowed} onChange={setAllowed} /></div></Card>
      {categories.isError ? <ErrorNotice message="Não foi possível carregar as categorias." onRetry={() => void categories.refetch()} /> : null}
      <Card>
        <CardHeader
          title="Categorias de sites"
          description={categories.data?.version ? `Listas publicadas em ${formatDateTime(categories.data.version)}` : "Listas abertas, atualizadas uma vez por dia"}
        />
        <div className="space-y-5 px-5 pt-4 pb-5">
          {categories.data?.health && categories.data.health.status !== "current" ? <p role="note" className="rounded-lg bg-warning-soft p-3 text-sm text-warning">{categories.data.health.status === "stale" ? "As listas de categorias estão desatualizadas. Confira a publicação antes de aplicar novas regras." : "A classificação por categoria está indisponível ou vazia. Confira a publicação das listas antes de aplicar novas regras."}</p> : null}
          {categories.isSuccess && published.length === 0 ? (
            <p className="py-4 text-center text-sm text-ink-muted">Nenhuma categoria publicada no servidor.</p>
          ) : null}
          {byGroup(published).map(([group, items]) => (
            <section key={group}>
              <h3 className="text-xs font-medium tracking-wide text-ink-muted uppercase">{group}</h3>
              <ul className="mt-2 grid gap-3 xl:grid-cols-2">
                {items.map((category) => (
                  <li key={category.id} aria-label={category.label}
                    className="space-y-2 rounded-lg bg-canvas px-3 py-3 text-sm">
                    <div className="flex items-center justify-between gap-2"><span className="text-ink">{category.label}</span><span className="text-xs text-ink-muted">{formatNumber(category.count)} domínios</span></div>
                    <WebActionSelector label={category.label} value={actions[category.id] ?? (monitorAll ? "monitor" : "allow")} onChange={(action) => setActions((current) => ({ ...current, [category.id]: action }))} />
                  </li>
                ))}
              </ul>
            </section>
          ))}
          <p className="text-sm text-ink-soft">Permitir não registra navegação. Bloquear registra a tentativa. Monitorar permite e registra o domínio observado. Se houver várias categorias, Bloquear prevalece sobre Monitorar e Permitir. A exceção por domínio tem prioridade.</p>
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={monitorAll} onChange={(event) => setMonitorAll(event.target.checked)} />Monitorar todos os domínios observados pelo DNS</label>
          <p className="text-xs text-ink-muted">O registro DNS não representa todas as páginas visitadas: inclui consultas de aplicativos e pré-carregamento, e não contém URLs completas nem identifica a pessoa. A coleta depende da capacidade do agente; cache e conexões existentes reduzem a visibilidade.</p>
          {Object.keys(actions).some((id) => !published.some((category) => category.id === id)) && categories.isSuccess ? <p className="text-sm text-warning">Há ações para categorias não publicadas. As regras foram preservadas; confira a disponibilidade das listas antes de publicar.</p> : null}
          {categories.data?.attribution ? <p className="text-xs text-ink-muted">{categories.data.attribution}</p> : null}
        </div>
      </Card>
    <Card><CardHeader title="SafeSearch" description="Força o modo seguro nos mecanismos selecionados." /><div className="space-y-3 p-5"><div className="flex flex-wrap gap-5">{ENGINES.map(([key, label]) => <label key={key} className="flex items-center gap-2 text-sm"><input type="checkbox" checked={engines.includes(key)} onChange={() => setEngines(toggle(engines, key))} />{label}</label>)}</div><label className="block max-w-sm text-sm">Restrição do YouTube<select className={`mt-1 ${FIELD_CLASS}`} value={youtube} onChange={(event) => setYoutube(event.target.value)}><option value="strict">Estrita</option><option value="moderate">Moderada</option></select></label></div></Card>
    <Card><CardHeader title="Horários" description="As regras dos períodos ativos se somam aos bloqueios permanentes." /><div className="space-y-4 p-5"><Field label="Fuso horário" value={timezone} onChange={setTimezone} />{windows.map((window, index) => <div key={index} className="space-y-3 rounded-xl border border-line p-4"><div className="flex flex-wrap gap-3">{DAYS.map(([day, label]) => <label key={day} className="flex items-center gap-1 text-sm"><input type="checkbox" aria-label={`${label} ${index + 1}`} checked={window.days.includes(day)} onChange={() => updateWindow(index, { days: toggle(window.days, day) })} />{label}</label>)}</div><div className="grid gap-3 sm:grid-cols-2"><Field type="time" label={`Início ${index + 1}`} value={window.from} onChange={(from) => updateWindow(index, { from })} /><Field type="time" label={`Fim ${index + 1}`} value={window.to} onChange={(to) => updateWindow(index, { to })} /></div><TextArea label={`Domínios no horário ${index + 1}`} value={window.blocked.join("\n")} onChange={(value) => updateWindow(index, { blocked: lines(value) })} /><div className="grid gap-3 xl:grid-cols-2">{published.map((category) => <div key={category.id} className="space-y-2"><span className="text-sm">{category.label}</span><WebActionSelector label={`${category.label} no horário ${index + 1}`} value={window.category_actions?.[category.id] ?? actions[category.id] ?? (monitorAll ? "monitor" : "allow")} onChange={(action) => updateWindow(index, { category_actions: { ...window.category_actions, [category.id]: action } })} /></div>)}</div><Button onClick={() => setWindows((values) => values.filter((_, at) => at !== index))}>Remover horário {index + 1}</Button></div>)}<Button onClick={() => setWindows((values) => [...values, { days: ["mon", "tue", "wed", "thu", "fri"], from: "08:00", to: "18:00", blocked: [] }])}>Adicionar horário</Button></div></Card>
  </PolicyForm>;
}

export function WebFilterPage() { return <PolicyWorkspace title="Filtro web" description="Bloqueio por domínio, categoria e horário, com lista de permitidos e SafeSearch.">{(props) => <WebEditor {...props} />}</PolicyWorkspace>; }
