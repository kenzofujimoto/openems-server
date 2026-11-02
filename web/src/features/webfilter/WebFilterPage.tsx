import { useState } from "react";
import { z } from "zod";
import { ErrorNotice } from "@/components/PageHeader";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader } from "@/components/ui/Card";
import { WEB_ACTIONS, type CategoryActions, type WebAction } from "@/components/ui/WebActionSelector";
import { Clock, Link2, SearchCheck, Shapes } from "lucide-react";
import { CategoryTable } from "./CategoryTable";
import { formatDateTime, formatNumber } from "@/lib/format";
import { useCategories } from "@/lib/queries";
import type { Profile } from "@/lib/management";
import { migrateDomainRules, normalizeDomainRows } from "@/lib/domainRules";
import { DomainRulesTable } from "./DomainRulesTable";
import { FIELD_CLASS, Field, lines, PolicyForm, PolicyWorkspace, record, strings, TextArea } from "@/features/policies/PolicyWorkspace";

const DAYS = [["mon", "Segunda"], ["tue", "Terça"], ["wed", "Quarta"], ["thu", "Quinta"], ["fri", "Sexta"], ["sat", "Sábado"], ["sun", "Domingo"]] as const;
const ENGINES = [["google", "Google"], ["bing", "Bing"], ["youtube", "YouTube"], ["duckduckgo", "DuckDuckGo"]] as const;
interface Window { days: string[]; from: string; to: string; blocked: string[]; category_actions?: CategoryActions }
function categoryActions(settings: Record<string, unknown>): CategoryActions {
  const actions: CategoryActions = Object.fromEntries(strings(settings.blocked_categories).map((id) => [id, "block"]));
  for (const [id, action] of Object.entries(record(settings.category_actions))) if (action === "allow" || action === "block" || action === "monitor" || action === "warn") actions[id] = action;
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
  const [domainRows, setDomainRows] = useState(() => migrateDomainRules(settings));
  const [actions, setActions] = useState(() => categoryActions(settings));
  const [monitorAll, setMonitorAll] = useState(settings.monitor_all === true);
  const [engines, setEngines] = useState(strings(safe.engines));
  const [youtube, setYoutube] = useState(typeof safe.youtube === "string" ? safe.youtube : "strict");
  const [timezone, setTimezone] = useState(typeof settings.timezone === "string" ? settings.timezone : "America/Sao_Paulo");
  const [windows, setWindows] = useState<Window[]>(() => Array.isArray(settings.scheduled) ? settings.scheduled.map((value) => { const window = record(value); const actions = categoryActions(window); return { days: strings(window.days), from: String(window.from ?? "08:00"), to: String(window.to ?? "18:00"), blocked: strings(window.blocked), ...(Object.keys(actions).length ? { category_actions: actions } : {}) }; }) : []);
  const valueOf = (id: string): WebAction => actions[id] ?? (monitorAll ? "monitor" : "allow");
  const totals: Record<WebAction, number> = { allow: 0, block: 0, monitor: 0, warn: 0 };
  for (const category of published) totals[valueOf(category.id)] += 1;
  const toggle = (values: string[], value: string) => values.includes(value) ? values.filter((item) => item !== value) : [...values, value];
  const updateWindow = (index: number, patch: Partial<Window>) => setWindows((values) => values.map((window, at) => at === index ? { ...window, ...patch } : window));
  const sections = { label: "Seções do filtro web", items: [

          { id: "categories", label: "Categorias", icon: Shapes, count: published.length, content: <>
            {categories.isError ? <ErrorNotice message="Não foi possível carregar as categorias." onRetry={() => void categories.refetch()} /> : null}
            {categories.data?.health && categories.data.health.status !== "current" ? <p role="note" className="rounded-lg bg-warning-soft p-3 text-sm text-warning">{categories.data.health.status === "stale" ? "As listas de categorias estão desatualizadas. Confira a publicação antes de aplicar novas regras." : "A classificação por categoria está indisponível ou vazia. Confira a publicação das listas antes de aplicar novas regras."}</p> : null}
            {categories.isSuccess && published.length === 0 ? <p className="rounded-lg border border-line bg-surface py-6 text-center text-sm text-ink-muted">Nenhuma categoria publicada no servidor.</p> : null}
            {published.length ? <CategoryTable title="Categorias de sites" categories={published} valueOf={valueOf} onChange={(ids, action) => setActions((current) => ({ ...current, ...Object.fromEntries(ids.map((id) => [id, action])) }))} readonly={readonly} /> : null}
            <div className="space-y-2 rounded-[var(--radius-card)] border border-line bg-surface p-4">
              <p className="text-sm text-ink-soft">Ordem de avaliação: <strong className="font-semibold text-ink">Filtro de URL estático</strong> (primeira regra que corresponder) → <strong className="font-semibold text-ink">Categoria</strong> (Bloquear prevalece sobre Avisar, Monitorar e Permitir) → sites sem categoria são permitidos. Permitir não registra navegação; Bloquear registra a tentativa; Monitorar permite e registra o domínio observado; Avisar mostra um aviso e deixa a pessoa continuar por 1 hora (registrado), em agentes com página de bloqueio HTTPS.</p>
              <label className="flex items-center gap-2 text-sm"><input type="checkbox" className="accent-brand" checked={monitorAll} onChange={(event) => setMonitorAll(event.target.checked)} />Monitorar todos os domínios observados pelo DNS</label>
              <p className="text-xs text-ink-muted">O registro DNS não representa todas as páginas visitadas: inclui consultas de aplicativos e pré-carregamento, e não contém URLs completas nem identifica a pessoa. A coleta depende da capacidade do agente; cache e conexões existentes reduzem a visibilidade.</p>
              {Object.keys(actions).some((id) => !published.some((category) => category.id === id)) && categories.isSuccess ? <p className="text-sm text-warning">Há ações para categorias não publicadas. As regras foram preservadas; confira a disponibilidade das listas antes de publicar.</p> : null}
              {categories.data?.attribution ? <p className="text-xs text-ink-muted">{categories.data.attribution}</p> : null}
            </div>
          </> },
          { id: "urls", label: "Filtro de URL estático", icon: Link2, count: domainRows.length, content: <DomainRulesTable rows={domainRows} onChange={setDomainRows} readonly={readonly} /> },
          { id: "safesearch", label: "SafeSearch", icon: SearchCheck, content: <Card><CardHeader title="SafeSearch" description="Força o modo seguro nos mecanismos selecionados." /><div className="space-y-3 p-5"><div className="flex flex-wrap gap-5">{ENGINES.map(([key, label]) => <label key={key} className="flex items-center gap-2 text-sm"><input type="checkbox" className="accent-brand" checked={engines.includes(key)} onChange={() => setEngines(toggle(engines, key))} />{label}</label>)}</div><label className="block max-w-sm text-sm">Restrição do YouTube<select className={`mt-1 ${FIELD_CLASS}`} value={youtube} onChange={(event) => setYoutube(event.target.value)}><option value="strict">Estrita</option><option value="moderate">Moderada</option></select></label></div></Card> },
          { id: "schedules", label: "Horários", icon: Clock, count: windows.length, content: <Card><CardHeader title="Horários" description="As regras dos períodos ativos se somam aos bloqueios permanentes." /><div className="space-y-4 p-5"><Field label="Fuso horário" value={timezone} onChange={setTimezone} />{windows.map((window, index) => <div key={index} className="space-y-3 rounded-lg border border-line p-4"><div className="flex flex-wrap gap-3">{DAYS.map(([day, label]) => <label key={day} className="flex items-center gap-1 text-sm"><input type="checkbox" className="accent-brand" aria-label={`${label} ${index + 1}`} checked={window.days.includes(day)} onChange={() => updateWindow(index, { days: toggle(window.days, day) })} />{label}</label>)}</div><div className="grid gap-3 sm:grid-cols-2"><Field type="time" label={`Início ${index + 1}`} value={window.from} onChange={(from) => updateWindow(index, { from })} /><Field type="time" label={`Fim ${index + 1}`} value={window.to} onChange={(to) => updateWindow(index, { to })} /></div><TextArea label={`Domínios no horário ${index + 1}`} value={window.blocked.join("\n")} onChange={(value) => updateWindow(index, { blocked: lines(value) })} />{published.length ? <CategoryTable title={`Categorias no horário ${index + 1}`} suffix={` no horário ${index + 1}`} categories={published} valueOf={(id) => window.category_actions?.[id] ?? valueOf(id)} onChange={(ids, action) => updateWindow(index, { category_actions: { ...window.category_actions, ...Object.fromEntries(ids.map((id) => [id, action])) } })} readonly={readonly} /> : null}<Button onClick={() => setWindows((values) => values.filter((_, at) => at !== index))}>Remover horário {index + 1}</Button></div>)}<Button onClick={() => setWindows((values) => [...values, { days: ["mon", "tue", "wed", "thu", "fri"], from: "08:00", to: "18:00", blocked: [] }])}>Adicionar horário</Button></div></Card> },
  ] };
  const aside = <>

        <Card><CardHeader title="Resumo do perfil" /><div className="space-y-3 p-5 text-sm">
          <div className="flex h-2 overflow-hidden rounded-full bg-idle-soft" aria-hidden="true">{WEB_ACTIONS.map(({ value, swatch }) => <span key={value} className={swatch} style={{ width: `${published.length ? (totals[value] / published.length) * 100 : 0}%` }} />)}</div>
          <dl className="space-y-1.5">{WEB_ACTIONS.map(({ value, label, swatch }) => <div key={value} className="flex items-center gap-2"><span aria-hidden="true" className={`size-2.5 rounded-sm ${swatch}`} /><dt className="text-ink-soft">{label}</dt><dd className="ml-auto font-semibold">{totals[value]}</dd></div>)}</dl>
          <dl className="space-y-1.5 border-t border-line pt-3">
            <div className="flex"><dt className="text-ink-soft">Regras de URL</dt><dd className="ml-auto font-semibold">{domainRows.length}</dd></div>
            <div className="flex"><dt className="text-ink-soft">SafeSearch</dt><dd className="ml-auto">{engines.length ? `${engines.length} mecanismo${engines.length === 1 ? "" : "s"}` : "Desligado"}</dd></div>
            <div className="flex"><dt className="text-ink-soft">Horários</dt><dd className="ml-auto">{windows.length || "Nenhum"}</dd></div>
            <div className="flex"><dt className="text-ink-soft">Monitoramento DNS geral</dt><dd className="ml-auto">{monitorAll ? "Ligado" : "Desligado"}</dd></div>
          </dl>
        </div></Card>
        <Card><CardHeader title="Base de categorias" description={categories.data?.version ? `Publicada em ${formatDateTime(categories.data.version)}` : "Listas abertas, atualizadas uma vez por dia"} /><div className="space-y-1.5 p-5 text-sm">
          <div className="flex"><span className="text-ink-soft">Categorias</span><span className="ml-auto font-semibold">{published.length}</span></div>
          <div className="flex"><span className="text-ink-soft">Domínios</span><span className="ml-auto font-semibold">{formatNumber(published.reduce((sum, category) => sum + category.count, 0))}</span></div>
        </div></Card>
  </>;
  return <PolicyForm profile={profile} vdom={vdom} section="web_filter" readonly={readonly} sections={sections} aside={aside} build={() => {
    const next: Record<string, unknown> = { ...settings, domain_rules: normalizeDomainRows(domainRows) };
    delete next.blocked;
    delete next.allowed;
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
  }} />;
}

export function WebFilterPage() { return <PolicyWorkspace title="Filtro web" description="Perfil por grupo: categorias, filtro de URL estático, SafeSearch e horários.">{(props) => <WebEditor {...props} />}</PolicyWorkspace>; }
