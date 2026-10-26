import { useState } from "react";
import { z } from "zod";
import { ErrorNotice } from "@/components/PageHeader";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader } from "@/components/ui/Card";
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
interface Window { days: string[]; from: string; to: string; blocked: string[]; blocked_categories?: string[] }
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
  const [selected, setSelected] = useState(strings(settings.blocked_categories));
  const [engines, setEngines] = useState(strings(safe.engines));
  const [youtube, setYoutube] = useState(typeof safe.youtube === "string" ? safe.youtube : "strict");
  const [timezone, setTimezone] = useState(typeof settings.timezone === "string" ? settings.timezone : "America/Sao_Paulo");
  const [windows, setWindows] = useState<Window[]>(() => Array.isArray(settings.scheduled) ? settings.scheduled.map((value) => { const window = record(value); return { days: strings(window.days), from: String(window.from ?? "08:00"), to: String(window.to ?? "18:00"), blocked: strings(window.blocked), ...(window.blocked_categories ? { blocked_categories: strings(window.blocked_categories) } : {}) }; }) : []);
  const toggle = (values: string[], value: string) => values.includes(value) ? values.filter((item) => item !== value) : [...values, value];
  const updateWindow = (index: number, patch: Partial<Window>) => setWindows((values) => values.map((window, at) => at === index ? { ...window, ...patch } : window));
  return <PolicyForm profile={profile} vdom={vdom} section="web_filter" readonly={readonly} build={() => {
    const next: Record<string, unknown> = { ...settings, blocked: validDomains(lines(blocked)), allowed: validDomains(lines(allowed)) };
    if (selected.length) next.blocked_categories = selected; else delete next.blocked_categories;
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
    <Card><CardHeader title="Domínios" description="Permitidos têm prioridade. Use *.example.com para o domínio e seus subdomínios." /><div className="grid gap-4 p-5 md:grid-cols-2"><TextArea label="Domínios bloqueados" value={blocked} onChange={setBlocked} /><TextArea label="Domínios permitidos" value={allowed} onChange={setAllowed} /></div></Card>
      {categories.isError ? <ErrorNotice message="Não foi possível carregar as categorias." onRetry={() => void categories.refetch()} /> : null}
      <Card>
        <CardHeader
          title="Categorias de sites"
          description={categories.data?.version ? `Listas publicadas em ${formatDateTime(categories.data.version)}` : "Listas abertas, atualizadas uma vez por dia"}
        />
        <div className="space-y-5 px-5 pt-4 pb-5">
          {categories.isSuccess && published.length === 0 ? (
            <p className="py-4 text-center text-sm text-ink-muted">Nenhuma categoria publicada no servidor.</p>
          ) : null}
          {byGroup(published).map(([group, items]) => (
            <section key={group}>
              <h3 className="text-xs font-medium tracking-wide text-ink-muted uppercase">{group}</h3>
              <ul className="mt-2 grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
                {items.map((category) => (
                  <li key={category.id} aria-label={category.label}
                    className="flex items-center justify-between gap-3 rounded-lg bg-canvas px-3 py-2 text-sm">
                    <label className="flex items-center gap-2 text-ink"><input type="checkbox" aria-label={`Bloquear ${category.label}`} checked={selected.includes(category.id)} onChange={() => setSelected(toggle(selected, category.id))} />{category.label}</label>
                    <span className="text-xs text-ink-muted">{formatNumber(category.count)} domínios</span>
                  </li>
                ))}
              </ul>
            </section>
          ))}
          {categories.data?.attribution ? <p className="text-xs text-ink-muted">{categories.data.attribution}</p> : null}
        </div>
      </Card>
    <Card><CardHeader title="SafeSearch" description="Força o modo seguro nos mecanismos selecionados." /><div className="space-y-3 p-5"><div className="flex flex-wrap gap-5">{ENGINES.map(([key, label]) => <label key={key} className="flex items-center gap-2 text-sm"><input type="checkbox" checked={engines.includes(key)} onChange={() => setEngines(toggle(engines, key))} />{label}</label>)}</div><label className="block max-w-sm text-sm">Restrição do YouTube<select className={`mt-1 ${FIELD_CLASS}`} value={youtube} onChange={(event) => setYoutube(event.target.value)}><option value="strict">Estrita</option><option value="moderate">Moderada</option></select></label></div></Card>
    <Card><CardHeader title="Horários" description="As regras dos períodos ativos se somam aos bloqueios permanentes." /><div className="space-y-4 p-5"><Field label="Fuso horário" value={timezone} onChange={setTimezone} />{windows.map((window, index) => <div key={index} className="space-y-3 rounded-xl border border-line p-4"><div className="flex flex-wrap gap-3">{DAYS.map(([day, label]) => <label key={day} className="flex items-center gap-1 text-sm"><input type="checkbox" aria-label={`${label} ${index + 1}`} checked={window.days.includes(day)} onChange={() => updateWindow(index, { days: toggle(window.days, day) })} />{label}</label>)}</div><div className="grid gap-3 sm:grid-cols-2"><Field type="time" label={`Início ${index + 1}`} value={window.from} onChange={(from) => updateWindow(index, { from })} /><Field type="time" label={`Fim ${index + 1}`} value={window.to} onChange={(to) => updateWindow(index, { to })} /></div><TextArea label={`Domínios no horário ${index + 1}`} value={window.blocked.join("\n")} onChange={(value) => updateWindow(index, { blocked: lines(value) })} /><div className="flex flex-wrap gap-3">{published.map((category) => <label key={category.id} className="flex items-center gap-1 text-sm"><input type="checkbox" aria-label={`${category.label} no horário ${index + 1}`} checked={window.blocked_categories?.includes(category.id) ?? false} onChange={() => updateWindow(index, { blocked_categories: toggle(window.blocked_categories ?? [], category.id) })} />{category.label}</label>)}</div><Button onClick={() => setWindows((values) => values.filter((_, at) => at !== index))}>Remover horário {index + 1}</Button></div>)}<Button onClick={() => setWindows((values) => [...values, { days: ["mon", "tue", "wed", "thu", "fri"], from: "08:00", to: "18:00", blocked: [] }])}>Adicionar horário</Button></div></Card>
  </PolicyForm>;
}

export function WebFilterPage() { return <PolicyWorkspace title="Filtro web" description="Bloqueio por domínio, categoria e horário, com lista de permitidos e SafeSearch.">{(props) => <WebEditor {...props} />}</PolicyWorkspace>; }
