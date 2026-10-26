import { useState } from "react";
import { ErrorNotice, InfoNotice, PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader } from "@/components/ui/Card";
import { Field, FIELD_CLASS, lines } from "@/features/policies/PolicyWorkspace";
import { useAssignmentRules, useProfiles, useRemoveAssignmentRule, useSaveAssignmentRule, type AssignmentRule, type Condition } from "@/lib/management";
import { useEndpoints, useIsAdmin } from "@/lib/queries";
import type { Endpoint } from "@/lib/schemas";
import { ConfirmDialog } from "./ConfirmDialog";

function empty(): AssignmentRule { return { id: "", target_vdom: "", priority: 100, enabled: true, conditions: [] }; }
function matches(endpoint: Endpoint, condition: Condition): boolean {
  if (condition.field === "host_tag") return typeof condition.value === "string" && endpoint.host_tags.includes(condition.value);
  const actual = endpoint[condition.field];
  if (condition.op === "in") return Array.isArray(condition.value) && condition.value.includes(actual);
  return typeof condition.value === "string" && (condition.op === "equals" ? actual === condition.value : condition.op === "contains" && actual.toLowerCase().includes(condition.value.toLowerCase()));
}

export function GroupsPage() {
  const rules = useAssignmentRules();
  const profiles = useProfiles();
  const endpoints = useEndpoints();
  const save = useSaveAssignmentRule();
  const remove = useRemoveAssignmentRule();
  const isAdmin = useIsAdmin();
  const [form, setForm] = useState<AssignmentRule>(empty);
  const [deleting, setDeleting] = useState<AssignmentRule | null>(null);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState("");
  const preview = endpoints.data?.filter((endpoint) => form.enabled && form.conditions.every((condition) => matches(endpoint, condition))) ?? [];
  function condition(index: number, patch: Partial<Condition>) { setForm((current) => ({ ...current, conditions: current.conditions.map((value, at) => at === index ? { ...value, ...patch } : value) })); }
  function edit(rule: AssignmentRule) { setForm(structuredClone(rule)); setError(""); setSaved(""); }
  return <div className="space-y-6">
    <PageHeader title="Grupos e regras" description="A primeira regra ativa em ordem de prioridade que atender todas as condições define o grupo." />
    {rules.isError ? <ErrorNotice message="Não foi possível carregar as regras." onRetry={() => void rules.refetch()} /> : null}
    <Card><CardHeader title="Grupos com perfil publicado" /><div className="flex flex-wrap gap-2 p-5">{profiles.data?.map((profile) => <span key={profile.vdom} className="rounded-lg bg-canvas px-3 py-2 text-sm">{profile.vdom} · v{profile.version}</span>)}{profiles.isError ? <ErrorNotice message="Não foi possível carregar os perfis." onRetry={() => void profiles.refetch()} /> : null}{profiles.isSuccess && !profiles.data.length ? <p className="text-sm text-ink-muted">Publique uma política para criar o perfil de um grupo.</p> : null}</div></Card>
    <Card className="overflow-x-auto"><CardHeader title="Regras de atribuição" /><table className="w-full text-left text-sm"><caption className="sr-only">Regras de atribuição</caption><thead className="border-y border-line bg-canvas"><tr>{["Prioridade", "Regra", "Grupo", "Condições", "Ativa", ...(isAdmin ? ["Ações"] : [])].map((label) => <th key={label} className="p-4 font-medium">{label}</th>)}</tr></thead><tbody className="divide-y divide-line">{rules.data?.map((rule) => <tr key={rule.id}><td className="p-4">{rule.priority}</td><td className="p-4">{rule.id}</td><td className="p-4">{rule.target_vdom}</td><td className="p-4">{rule.conditions.map((condition) => `${condition.field} ${condition.op} ${JSON.stringify(condition.value)}`).join(" E ") || "Todas as máquinas"}</td><td className="p-4">{rule.enabled ? "Sim" : "Não"}</td>{isAdmin ? <td className="p-4"><div className="flex gap-2"><Button size="sm" aria-label={`Editar regra ${rule.id}`} onClick={() => edit(rule)}>Editar</Button><Button size="sm" aria-label={`Excluir regra ${rule.id}`} onClick={() => { remove.reset(); setDeleting(rule); }}>Excluir</Button></div></td> : null}</tr>)}</tbody></table>{rules.isPending ? <p role="status" className="p-5">Carregando regras…</p> : rules.isSuccess && !rules.data.length ? <p className="p-5 text-sm text-ink-muted">Nenhuma regra cadastrada.</p> : null}</Card>
    {isAdmin ? <Card><CardHeader title="Editor de regra" action={<Button onClick={() => edit(empty())}>Nova regra</Button>} /><form className="space-y-4 p-5" onSubmit={(event) => {
      event.preventDefault(); setError(""); setSaved("");
      if (!form.id.trim() || !form.target_vdom.trim() || !Number.isInteger(form.priority) || form.priority < 0 || form.priority > 1_000_000) return setError("Informe identificador, grupo de destino e prioridade inteira entre 0 e 1000000.");
      if (form.conditions.some((value) => value.op === "in" ? !Array.isArray(value.value) || !value.value.length : typeof value.value !== "string" || !value.value)) return setError("Preencha o valor de todas as condições; use uma linha por item no operador 'em lista'.");
      save.mutate({ ...form, id: form.id.trim(), target_vdom: form.target_vdom.trim() }, { onSuccess: () => setSaved(`Regra ${form.id} salva.`) });
    }}><fieldset disabled={save.isPending} className="space-y-4"><div className="grid gap-4 sm:grid-cols-3"><Field label="Identificador da regra" value={form.id} onChange={(id) => setForm({ ...form, id })} /><Field label="Grupo de destino" value={form.target_vdom} onChange={(target_vdom) => setForm({ ...form, target_vdom })} /><Field label="Prioridade" type="number" value={String(form.priority)} onChange={(value) => setForm({ ...form, priority: Number(value) })} /></div><label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={form.enabled} onChange={(event) => setForm({ ...form, enabled: event.target.checked })} />Regra ativa</label>{form.conditions.map((value, index) => <div key={index} className="grid gap-3 rounded-xl border border-line p-4 sm:grid-cols-3"><label className="text-sm">Campo da condição {index + 1}<select className={`mt-1 ${FIELD_CLASS}`} value={value.field} onChange={(event) => { const field = event.target.value as Condition["field"]; condition(index, { field, op: field === "host_tag" ? "has_tag" : value.op === "has_tag" ? "contains" : value.op, value: field === "host_tag" ? "" : value.value }); }}>{["os", "hostname", "fctver", "vdom", "host_tag"].map((field) => <option key={field}>{field}</option>)}</select></label><label className="text-sm">Operador da condição {index + 1}<select className={`mt-1 ${FIELD_CLASS}`} value={value.op} onChange={(event) => { const op = event.target.value as Condition["op"]; condition(index, { op, value: op === "in" ? typeof value.value === "string" ? lines(value.value) : value.value : Array.isArray(value.value) ? value.value.join("\n") : value.value }); }}>{value.field === "host_tag" ? <option value="has_tag">Possui tag</option> : <><option value="equals">Igual a</option><option value="contains">Contém</option><option value="in">Em lista</option></>}</select></label><label className="text-sm">Valor da condição {index + 1}<textarea className={`mt-1 ${FIELD_CLASS}`} rows={2} value={Array.isArray(value.value) ? value.value.join("\n") : value.value} onChange={(event) => condition(index, { value: value.op === "in" ? event.target.value.split(/\r?\n/) : event.target.value })} /></label><Button size="sm" onClick={() => setForm((current) => ({ ...current, conditions: current.conditions.filter((_, at) => at !== index) }))}>Remover condição {index + 1}</Button></div>)}<Button onClick={() => setForm((current) => ({ ...current, conditions: [...current.conditions, { field: "os", op: "contains", value: "" }] }))}>Adicionar condição</Button></fieldset><InfoNotice>Prévia: {preview.length} endpoint(s) atendem esta regra isolada. Regras anteriores podem ter prioridade; a confirmação do grupo vem do agente.</InfoNotice>{error || save.isError ? <p role="alert" className="text-sm text-danger">{error || "Não foi possível salvar a regra. Confira os valores e tente de novo."}</p> : null}{saved ? <p role="status" className="text-sm text-rsm-green">{saved}</p> : null}<Button type="submit" variant="primary" disabled={save.isPending}>Salvar regra</Button></form></Card> : null}
    {deleting ? <ConfirmDialog title="Excluir regra" message={`Excluir ${deleting.id} recalcula o grupo das máquinas correspondentes.`} confirm="Confirmar exclusão da regra" pending={remove.isPending} error={remove.isError} onClose={() => setDeleting(null)} onConfirm={() => remove.mutate(deleting.id, { onSuccess: () => setDeleting(null) })} /> : null}
  </div>;
}
