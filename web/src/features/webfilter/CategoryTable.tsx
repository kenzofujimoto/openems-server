import { ChevronDown, ChevronRight, ChevronsDownUp, ChevronsUpDown, Search } from "lucide-react";
import { useEffect, useRef, useState } from "react";
import { Button } from "@/components/ui/Button";
import { WEB_ACTIONS, WebActionSelector, type WebAction } from "@/components/ui/WebActionSelector";
import { cn } from "@/lib/cn";
import { formatNumber } from "@/lib/format";
import type { Category } from "@/lib/schemas";

export function groupCategories(categories: Category[]): [string, Category[]][] {
  const groups = new Map<string, Category[]>();
  for (const category of categories) groups.set(category.group, [...(groups.get(category.group) ?? []), category]);
  return [...groups.entries()];
}

function Checkbox({ label, checked, mixed = false, onChange, disabled }: { label: string; checked: boolean; mixed?: boolean; onChange: (checked: boolean) => void; disabled?: boolean }) {
  const ref = useRef<HTMLInputElement>(null);
  useEffect(() => { if (ref.current) ref.current.indeterminate = mixed; }, [mixed]);
  return <input ref={ref} type="checkbox" aria-label={label} checked={checked} disabled={disabled} onChange={(event) => onChange(event.target.checked)} className="size-4 cursor-pointer accent-brand" />;
}

function Distribution({ counts }: { counts: Record<WebAction, number> }) {
  return <span className="ml-2 inline-flex gap-1" aria-hidden="true">
    {WEB_ACTIONS.filter(({ value }) => counts[value]).map(({ value, label, pill }) => <span key={value} title={label} className={cn("rounded px-1.5 text-[11px] font-medium", pill)}>{counts[value]} {label.toLowerCase()}</span>)}
  </span>;
}

/**
 * FortiGate-style category list: collapsible groups, multi-selection with a bulk action toolbar and one
 * action selector per category. `suffix` keeps accessible names unique when several tables are on screen.
 */
export function CategoryTable({ title, categories, valueOf, onChange, suffix = "", readonly }: {
  title: string; categories: Category[]; valueOf: (id: string) => WebAction; onChange: (ids: string[], action: WebAction) => void; suffix?: string; readonly: boolean;
}) {
  const [selected, setSelected] = useState<string[]>([]);
  const [collapsed, setCollapsed] = useState<string[]>([]);
  const [query, setQuery] = useState("");
  const filter = query.trim().toLocaleLowerCase("pt-BR");
  const groups = groupCategories(categories)
    .map(([group, items]) => [group, items.filter((item) => !filter || item.label.toLocaleLowerCase("pt-BR").includes(filter) || group.toLocaleLowerCase("pt-BR").includes(filter))] as const)
    .filter(([, items]) => items.length);
  const toggle = (ids: string[], on: boolean) => setSelected((current) => on ? [...new Set([...current, ...ids])] : current.filter((id) => !ids.includes(id)));
  const apply = (action: WebAction) => { onChange(selected, action); setSelected([]); };
  const label = (text: string) => `${text}${suffix}`;
  return <div className="overflow-hidden rounded-[var(--radius-card)] border border-line bg-surface">
    <div className="flex flex-wrap items-center gap-2 border-b border-line bg-surface-2 px-3 py-2.5" role="toolbar" aria-label={label("Ações em lote")}>
      <span className="mr-1 text-sm font-medium text-brand-ink" aria-live="polite">{selected.length ? `${selected.length} ${selected.length === 1 ? "selecionada" : "selecionadas"}` : "Nenhuma selecionada"}</span>
      {!readonly ? WEB_ACTIONS.map(({ value, label: actionLabel, icon: Icon, text }) => <Button key={value} size="sm" className={text} disabled={!selected.length} onClick={() => apply(value)} aria-label={label(`${actionLabel} selecionadas`)}><Icon aria-hidden="true" className="size-4" />{actionLabel}</Button>) : null}
      <span className="mx-1 h-5 w-px bg-line" aria-hidden="true" />
      <Button size="sm" variant="ghost" onClick={() => setCollapsed(collapsed.length ? [] : groups.map(([group]) => group))} aria-label={label(collapsed.length ? "Expandir todos os grupos" : "Recolher todos os grupos")}>
        {collapsed.length ? <ChevronsUpDown aria-hidden="true" className="size-4" /> : <ChevronsDownUp aria-hidden="true" className="size-4" />}{collapsed.length ? "Expandir tudo" : "Recolher tudo"}
      </Button>
      <label className="ml-auto flex h-8 min-w-52 items-center gap-2 rounded-md border border-line-strong bg-surface px-2.5 text-sm text-ink-muted">
        <Search aria-hidden="true" className="size-4" /><span className="sr-only">{label("Buscar categoria")}</span>
        <input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Buscar categoria" className="w-full bg-transparent text-ink outline-none" />
      </label>
    </div>
    <div className="overflow-x-auto">
      <table aria-label={title} className="w-full text-left text-sm">
        <thead className="text-xs text-ink-soft"><tr className="border-b border-line">
          <th scope="col" className="w-10 px-3 py-2"><span className="sr-only">Seleção</span></th>
          <th scope="col" className="px-2 py-2 font-semibold">Categoria</th>
          <th scope="col" className="px-2 py-2 font-semibold">Ação</th>
          <th scope="col" className="px-3 py-2 text-right font-semibold">Domínios na base</th>
        </tr></thead>
        {groups.map(([group, items]) => {
          const ids = items.map((item) => item.id);
          const chosen = ids.filter((id) => selected.includes(id)).length;
          const open = !collapsed.includes(group) || Boolean(filter);
          const counts: Record<WebAction, number> = { allow: 0, block: 0, monitor: 0, warn: 0 };
          for (const id of ids) counts[valueOf(id)] += 1;
          return <tbody key={group} className="border-b border-line last:border-b-0">
            <tr className="bg-surface-2">
              <td className="px-3 py-2"><Checkbox label={label(`Selecionar grupo ${group}`)} checked={chosen === ids.length} mixed={chosen > 0 && chosen < ids.length} onChange={(on) => toggle(ids, on)} disabled={readonly} /></td>
              <td colSpan={3} className="px-2 py-2">
                <button type="button" aria-expanded={open} onClick={() => setCollapsed((current) => current.includes(group) ? current.filter((item) => item !== group) : [...current, group])} className="inline-flex items-center gap-1.5 font-semibold text-ink">
                  {open ? <ChevronDown aria-hidden="true" className="size-4" /> : <ChevronRight aria-hidden="true" className="size-4" />}{group} <span className="font-medium text-ink-muted">({items.length})</span>
                </button>
                <Distribution counts={counts} />
              </td>
            </tr>
            {open ? items.map((category) => {
              const checked = selected.includes(category.id);
              return <tr key={category.id} aria-label={category.label} className={cn("border-t border-line", checked && "bg-brand-soft/60 shadow-[inset_3px_0_0_var(--color-brand)]")}>
                <td className="px-3 py-1.5"><Checkbox label={label(`Selecionar ${category.label}`)} checked={checked} onChange={(on) => toggle([category.id], on)} disabled={readonly} /></td>
                <td className="py-1.5 pr-2 pl-8 text-ink">{category.label}</td>
                <td className="px-2 py-1.5"><WebActionSelector compact label={label(category.label)} value={valueOf(category.id)} onChange={(action) => onChange([category.id], action)} /></td>
                <td className="px-3 py-1.5 text-right text-ink-soft tabular-nums">{formatNumber(category.count)}</td>
              </tr>;
            }) : null}
          </tbody>;
        })}
        {!groups.length ? <tbody><tr><td colSpan={4} className="px-3 py-6 text-center text-ink-muted">Nenhuma categoria encontrada.</td></tr></tbody> : null}
      </table>
    </div>
  </div>;
}
