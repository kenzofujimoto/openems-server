import { useState } from "react";
import { Button } from "@/components/ui/Button";
import { FIELD_CLASS } from "@/features/locations/LocationDialog";

const STORAGE_KEY = "openems.policy-group";
const MAX_NAME = 128;

/** The chosen group follows the administrator between policy pages in this browser tab. */
export function storedGroup(): string {
  try { return window.sessionStorage.getItem(STORAGE_KEY) || "Default"; } catch { return "Default"; }
}
function rememberGroup(vdom: string) {
  try { window.sessionStorage.setItem(STORAGE_KEY, vdom); } catch { /* Without storage the choice still applies to this page. */ }
}

interface Group { vdom: string; version: number | null }

export function GroupPicker({ published, value, onChange, readonly }: { published: Array<{ vdom: string; version: number }>; value: string; onChange: (vdom: string) => void; readonly: boolean }) {
  const [drafts, setDrafts] = useState<string[]>([]);
  const [query, setQuery] = useState("");
  const [creating, setCreating] = useState(false);
  const [name, setName] = useState("");
  const [error, setError] = useState("");
  const pending = [...drafts, value].filter((vdom, index, all) => all.indexOf(vdom) === index && !published.some((group) => group.vdom === vdom));
  const groups: Group[] = [...published.map(({ vdom, version }) => ({ vdom, version })), ...pending.map((vdom) => ({ vdom, version: null }))]
    .sort((a, b) => a.vdom.localeCompare(b.vdom, "pt-BR", { sensitivity: "base" }));
  const filter = query.trim().toLocaleLowerCase("pt-BR");
  const visible = groups.filter((group) => group.vdom.toLocaleLowerCase("pt-BR").includes(filter));
  const select = (vdom: string) => { rememberGroup(vdom); onChange(vdom); };
  const create = () => {
    const candidate = name.trim();
    const existing = groups.find((group) => group.vdom.localeCompare(candidate, "pt-BR", { sensitivity: "base" }) === 0);
    if (!candidate) return setError("Informe o nome do grupo.");
    if (candidate.length > MAX_NAME) return setError(`Use até ${MAX_NAME} caracteres.`);
    if (existing) return setError(`Já existe um grupo chamado ${existing.vdom}.`);
    setDrafts((current) => [...current, candidate]);
    setName(""); setError(""); setCreating(false); setQuery("");
    select(candidate);
  };
  const selected = groups.find((group) => group.vdom === value);
  return <div className="space-y-3">
    <div className="flex flex-wrap items-end gap-3">
      <label className="block w-full max-w-xs text-sm text-ink-soft">Buscar grupo<input className={`mt-1 ${FIELD_CLASS}`} value={query} onChange={(event) => setQuery(event.target.value)} /></label>
      {!readonly && !creating ? <Button onClick={() => setCreating(true)}>Novo grupo</Button> : null}
    </div>
    {creating ? <div className="flex flex-wrap items-end gap-3">
      <label className="block w-full max-w-xs text-sm text-ink-soft">Nome do novo grupo<input className={`mt-1 ${FIELD_CLASS}`} value={name} maxLength={MAX_NAME + 1} onChange={(event) => setName(event.target.value)} onKeyDown={(event) => { if (event.key === "Enter") { event.preventDefault(); create(); } }} /></label>
      <Button variant="primary" onClick={create}>Criar grupo</Button>
      <Button onClick={() => { setCreating(false); setName(""); setError(""); }}>Cancelar</Button>
    </div> : null}
    {error ? <p role="alert" className="text-sm text-danger">{error}</p> : null}
    <div role="radiogroup" aria-label="Grupo da política" className="flex flex-wrap gap-2">
      {visible.map((group) => <label key={group.vdom} className={`inline-flex cursor-pointer items-center gap-2 rounded-full border px-3 py-1.5 text-sm ${group.vdom === value ? "border-rsm-blue bg-rsm-blue-soft text-rsm-blue" : "border-line text-ink"}`}>
        <input type="radio" name="policy-group" className="sr-only" aria-label={group.vdom} checked={group.vdom === value} onChange={() => select(group.vdom)} />
        <span>{group.vdom}</span><span className="text-xs text-ink-soft">{group.version === null ? "novo" : `v${group.version}`}</span>
      </label>)}
      {!visible.length ? <p className="text-sm text-ink-soft">Nenhum grupo encontrado.</p> : null}
    </div>
    {selected?.version === null ? <p className="text-sm text-ink-soft">Grupo {selected.vdom} ainda não publicado: publique uma política para criar o primeiro perfil.</p> : null}
  </div>;
}
