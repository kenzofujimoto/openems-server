import * as Dialog from "@radix-ui/react-dialog";
import { ArrowDown, ArrowUp, Download, Pencil, Plus, Trash2, Upload, X } from "lucide-react";
import { useId, useState, type ReactNode } from "react";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader } from "@/components/ui/Card";
import { FIELD_CLASS } from "@/features/policies/PolicyWorkspace";
import { decodeDomainCsv, encodeDomainCsv, MAX_CSV_BYTES, normalizeDomainRow, normalizeDomainRows, type DomainRow } from "@/lib/domainRules";

const ACTIONS = {allow:"Permitir", block:"Bloquear", monitor:"Monitorar (log)"};
const TONES = {allow:"bg-rsm-green-soft text-rsm-green", block:"bg-danger-soft text-danger", monitor:"bg-rsm-blue-soft text-rsm-blue-dark"};
const PAGE_SIZE = 50;

function Modal({title, description, onClose, children}: {title:string; description:string; onClose:()=>void; children:ReactNode}) {
  const [returnFocus] = useState(() => document.activeElement instanceof HTMLElement ? document.activeElement : null);
  return <Dialog.Root open onOpenChange={(open) => { if (!open) onClose(); }}><Dialog.Portal>
    <Dialog.Overlay className="fixed inset-0 z-40 bg-rsm-navy/30" />
    <Dialog.Content onCloseAutoFocus={(event) => { event.preventDefault(); returnFocus?.focus(); }} className="fixed top-1/2 left-1/2 z-50 max-h-[90vh] w-[calc(100%-2rem)] max-w-xl -translate-x-1/2 -translate-y-1/2 overflow-y-auto rounded-2xl border border-line bg-surface p-6 text-ink shadow-xl">
      <div className="flex items-start justify-between gap-3"><div><Dialog.Title className="text-lg font-medium">{title}</Dialog.Title><Dialog.Description className="mt-1 text-sm text-ink-muted">{description}</Dialog.Description></div><Dialog.Close aria-label="Fechar" className="rounded p-1 focus-visible:outline-2 focus-visible:outline-rsm-blue"><X className="size-5" aria-hidden="true" /></Dialog.Close></div>
      {children}
    </Dialog.Content>
  </Dialog.Portal></Dialog.Root>;
}

export function DomainRulesTable({rows, onChange, readonly}: {rows:DomainRow[]; onChange:(rows:DomainRow[])=>void; readonly:boolean}) {
  const uploadId = useId();
  const [editing, setEditing] = useState<{index:number|null; row:DomainRow}|null>(null);
  const [preview, setPreview] = useState<DomainRow[]|null>(null);
  const [error, setError] = useState("");
  const [dialogError, setDialogError] = useState("");
  const [reading, setReading] = useState(false);
  const [page, setPage] = useState(0);
  const [search, setSearch] = useState("");
  const filtered = rows.map((row,index) => ({row,index})).filter(({row}) => row.domain.includes(search.trim().toLowerCase()));
  const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const currentPage = Math.min(page, pages - 1);
  const visible = filtered.slice(currentPage * PAGE_SIZE, (currentPage + 1) * PAGE_SIZE);
  const message = (error:unknown) => error instanceof Error ? error.message : "Não foi possível concluir a operação.";
  const move = (index:number, offset:number) => {
    const current = rows[index]; const adjacent = rows[index+offset];
    if (!current || !adjacent) { setError("Não foi possível mover essa regra. Confira a tabela."); return; }
    const next = [...rows]; [next[index], next[index+offset]] = [adjacent,current]; onChange(next);
  };
  const startEdit = (index:number|null) => {
    const row:DomainRow|undefined = index === null ? {domain:"",type:"simple",action:"block"} : rows[index];
    if (!row) { setError("Não foi possível editar essa regra. Confira a tabela."); return; }
    setDialogError(""); setEditing({index,row:{...row}});
  };
  return <Card>
    <CardHeader title="Domínios" description="A primeira regra correspondente define a ação. Mova as regras para ajustar a prioridade." />
    <div className="space-y-4 p-5">
      <div className="flex flex-wrap items-center gap-2">
        {!readonly ? <><Button onClick={() => startEdit(null)}><Plus className="size-4" aria-hidden="true" />Adicionar domínio</Button>
          <label htmlFor={uploadId} className="inline-flex cursor-pointer items-center gap-2 rounded-lg border border-line px-4 py-2 text-sm has-focus-visible:outline-2 has-focus-visible:outline-rsm-blue"><Upload className="size-4" aria-hidden="true" />Importar CSV<input id={uploadId} aria-label="Importar CSV" type="file" accept=".csv,text/csv" disabled={reading} className="sr-only" onChange={async (event) => {
            const file = event.target.files?.[0]; event.target.value = ""; if (!file) return;
            setError(""); setReading(true);
            try {
              if (file.size > MAX_CSV_BYTES) throw new Error("O CSV deve ter no máximo 2 MB.");
              const imported = decodeDomainCsv(await file.text());
              normalizeDomainRows([...rows, ...imported]); setPreview(imported);
            } catch (error) { setError(message(error)); } finally { setReading(false); }
          }} /></label></> : null}
        <Button onClick={() => {
          let url:string|undefined; setError("");
          try { url=URL.createObjectURL(new Blob([encodeDomainCsv(rows)], {type:"text/csv;charset=utf-8"})); const link=document.createElement("a"); link.href=url; link.download="openems-domain-rules.csv"; link.click(); }
          catch (error) { setError(message(error)); } finally { if (url) URL.revokeObjectURL(url); }
        }}><Download className="size-4" aria-hidden="true" />Exportar CSV</Button>
        <span className="text-sm text-ink-muted">{rows.length} {rows.length === 1 ? "regra" : "regras"}</span>
      </div>
      <p className="text-xs text-ink-muted">Simples inclui o domínio e www. Wildcard inclui o domínio e todos os subdomínios. Permitir não registra navegação; Bloquear registra a tentativa; Monitorar permite e registra a consulta DNS. CSV: domain,type,action — simple/wildcard e allow/block/monitor.</p>
      {reading ? <p role="status" className="text-sm text-ink-muted">Lendo CSV…</p> : null}
      {error ? <p role="alert" className="rounded-lg bg-danger-soft p-3 text-sm text-danger">{error}</p> : null}
      <label className="block max-w-sm text-sm text-ink-soft">Buscar domínio<input className={`mt-1 ${FIELD_CLASS}`} value={search} onChange={(event) => {setSearch(event.target.value); setPage(0);}} /></label>
      <div className="overflow-x-auto rounded-lg border border-line"><table aria-label="Regras de domínio" className="w-full text-left text-sm">
        <thead className="bg-canvas text-ink-soft"><tr>{["Ordem","Domínio","Tipo","Ação","Gerenciar"].map((label) => <th key={label} scope="col" className="px-3 py-3 font-medium">{label}</th>)}</tr></thead>
        <tbody className="divide-y divide-line">{visible.map(({row,index}) => <tr key={`${row.type}:${row.domain}`}>
          <td className="px-3 py-3 text-ink-muted">{index+1}</td><td className="px-3 py-3 font-medium text-ink">{row.domain}</td><td className="px-3 py-3 text-ink-soft">{row.type === "wildcard" ? "Wildcard" : "Simples"}</td><td className="px-3 py-3"><span className={`whitespace-nowrap rounded-full px-2 py-1 text-xs ${TONES[row.action]}`}>{ACTIONS[row.action]}</span></td>
          <td className="px-3 py-2"><div className="flex gap-1">{!readonly ? <>
            <Button size="sm" aria-label={`Mover ${row.domain} para cima`} disabled={index === 0} onClick={() => move(index,-1)}><ArrowUp className="size-4" aria-hidden="true" /></Button>
            <Button size="sm" aria-label={`Mover ${row.domain} para baixo`} disabled={index === rows.length-1} onClick={() => move(index,1)}><ArrowDown className="size-4" aria-hidden="true" /></Button>
            <Button size="sm" aria-label={`Editar ${row.domain}`} onClick={() => startEdit(index)}><Pencil className="size-4" aria-hidden="true" /></Button>
            <Button size="sm" aria-label={`Excluir ${row.domain}`} onClick={() => onChange(rows.filter((_,at) => at !== index))}><Trash2 className="size-4" aria-hidden="true" /></Button>
          </> : <span className="text-ink-muted">Somente leitura</span>}</div></td>
        </tr>)}{!visible.length ? <tr><td colSpan={5} className="px-3 py-8 text-center text-ink-muted">{rows.length ? "Nenhum domínio encontrado." : "Nenhuma regra. Adicione um domínio ou importe um CSV."}</td></tr> : null}</tbody>
      </table></div>
      {pages > 1 ? <nav aria-label="Páginas dos domínios" className="flex items-center gap-3"><Button disabled={currentPage === 0} onClick={() => setPage(currentPage-1)}>Anterior</Button><span className="text-sm text-ink-muted">Página {currentPage+1} de {pages}</span><Button disabled={currentPage === pages-1} onClick={() => setPage(currentPage+1)}>Próxima</Button></nav> : null}
    </div>
    {editing && !readonly ? <Modal title={editing.index === null ? "Adicionar domínio" : "Editar domínio"} description="A regra só é enviada aos agentes ao publicar a política." onClose={() => setEditing(null)}>
      <form className="mt-5 space-y-4" onSubmit={(event) => {
        event.preventDefault(); event.stopPropagation(); setDialogError("");
        try { const row=normalizeDomainRow(editing.row); const next=editing.index === null ? [...rows,row] : rows.map((value,index) => index === editing.index ? row : value); onChange(normalizeDomainRows(next)); setEditing(null); }
        catch (error) { setDialogError(message(error)); }
      }}>
        <label className="block text-sm">Domínio<input autoFocus className={`mt-1 ${FIELD_CLASS}`} value={editing.row.domain} maxLength={253} placeholder="example.com" onChange={(event) => setEditing({...editing,row:{...editing.row,domain:event.target.value}})} /></label>
        <div className="grid gap-4 sm:grid-cols-2"><label className="block text-sm">Tipo<select aria-label="Tipo" className={`mt-1 ${FIELD_CLASS}`} value={editing.row.type} onChange={(event) => setEditing({...editing,row:{...editing.row,type:event.target.value as DomainRow["type"]}})}><option value="simple">Simples (normal)</option><option value="wildcard">Wildcard</option></select></label>
          <label className="block text-sm">Ação<select aria-label="Ação" className={`mt-1 ${FIELD_CLASS}`} value={editing.row.action} onChange={(event) => setEditing({...editing,row:{...editing.row,action:event.target.value as DomainRow["action"]}})}>{Object.entries(ACTIONS).map(([action,label]) => <option key={action} value={action}>{label}</option>)}</select></label></div>
        {dialogError ? <p role="alert" className="text-sm text-danger">{dialogError}</p> : null}
        <div className="flex justify-end gap-2"><Button onClick={() => setEditing(null)}>Cancelar</Button><Button type="submit" variant="primary">Salvar domínio</Button></div>
      </form>
    </Modal> : null}
    {preview && !readonly ? <Modal title="Prévia da importação" description="Os registros serão adicionados ao fim da tabela. Revise a ordem antes de publicar." onClose={() => setPreview(null)}>
      <ul className="my-4 max-h-60 space-y-2 overflow-y-auto text-sm">{preview.slice(0,20).map((row) => <li key={`${row.type}:${row.domain}`}>{row.domain} · {row.type === "simple" ? "Simples" : "Wildcard"} · {ACTIONS[row.action]}</li>)}</ul>
      {preview.length > 20 ? <p className="mb-4 text-sm text-ink-muted">Mais {preview.length-20} registros validados. Total: {preview.length}.</p> : null}
      <div className="flex justify-end gap-2"><Button onClick={() => setPreview(null)}>Cancelar</Button><Button variant="primary" onClick={() => {
        try {onChange(normalizeDomainRows([...rows,...preview])); setPreview(null); setError("");} catch (error) {setError(message(error)); setPreview(null);}
      }}>Importar {preview.length} {preview.length === 1 ? "domínio" : "domínios"}</Button></div>
    </Modal> : null}
  </Card>;
}
