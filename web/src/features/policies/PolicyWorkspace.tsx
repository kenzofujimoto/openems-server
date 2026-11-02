import { createContext, useContext, useState, type ReactNode } from "react";
import { CircleCheck, GitCommitHorizontal, Layers, Monitor, Upload } from "lucide-react";
import { ErrorNotice, InfoNotice, PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/Button";
import { Card } from "@/components/ui/Card";
import { Tabs, type TabItem } from "@/components/ui/Tabs";
import { ApiError } from "@/lib/api";
import { useProfiles, usePublishProfile, type PolicyBody, type Profile } from "@/lib/management";
import { useEndpoints, useIsAdmin } from "@/lib/queries";
import { policyStatus } from "@/lib/status";
import { FIELD_CLASS } from "@/features/locations/LocationDialog";
import { GroupPicker, storedGroup } from "./GroupPicker";

export { FIELD_CLASS };
const ReloadContext = createContext(() => {});
export function lines(value: string): string[] { return [...new Set(value.split(/\r?\n/).map((item) => item.trim()).filter(Boolean))]; }
export function record(value: unknown): Record<string, unknown> { return value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {}; }
export function strings(value: unknown): string[] { return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string") : []; }
export function TextArea({ label, value, onChange, rows = 4 }: { label: string; value: string; onChange: (value: string) => void; rows?: number }) {
  return <label className="block text-sm text-ink-soft">{label}<textarea className={`mt-1 ${FIELD_CLASS}`} rows={rows} value={value} onChange={(event) => onChange(event.target.value)} /></label>;
}
export function Field({ label, value, onChange, type = "text" }: { label: string; value: string; onChange: (value: string) => void; type?: string }) {
  return <label className="block text-sm text-ink-soft">{label}<input className={`mt-1 ${FIELD_CLASS}`} type={type} value={value} onChange={(event) => onChange(event.target.value)} /></label>;
}

export function PolicyWorkspace({ title, description, children }: { title: string; description: string; children: (props: { profile: Profile | undefined; vdom: string; readonly: boolean }) => ReactNode }) {
  const profiles = useProfiles();
  const endpoints = useEndpoints();
  const [vdom, setVdom] = useState(storedGroup);
  const [revision, setRevision] = useState(0);
  const readonly = !useIsAdmin();
  const selected = profiles.data?.find((profile) => profile.vdom === vdom);
  const members = endpoints.data?.filter((endpoint) => endpoint.effective_vdom === vdom) ?? [];
  const confirmed = members.filter((endpoint) => policyStatus(endpoint) === "applied").length;
  return <div className="space-y-4">
    <PageHeader title={title} description={description} />
    {profiles.isError ? <ErrorNotice message="Não foi possível carregar as políticas." onRetry={() => void profiles.refetch()} /> : null}
    <Card aria-label="Política por grupo" className="px-4 py-3">
      <div className="mb-2 flex flex-wrap items-center gap-x-4 gap-y-1 text-[13px] text-ink-muted">
        <span className="inline-flex items-center gap-1.5 font-semibold text-ink"><Layers aria-hidden="true" className="size-4" />Perfil do grupo {vdom}</span>
        <span className="inline-flex items-center gap-1.5"><GitCommitHorizontal aria-hidden="true" className="size-4" />{selected ? `Versão publicada: v${selected.version}` : "Ainda sem versão publicada"}</span>
        {members.length ? <span className="inline-flex items-center gap-1.5"><Monitor aria-hidden="true" className="size-4" />{confirmed} de {members.length} endpoints confirmaram</span> : null}
      </div>
      {profiles.isSuccess ? <GroupPicker published={profiles.data} value={vdom} onChange={setVdom} readonly={readonly} /> : <p className="text-sm text-ink-soft">Carregando grupos…</p>}
    </Card>
    {profiles.isPending ? <p role="status">Carregando políticas…</p> : null}
    {profiles.isSuccess ? <ReloadContext.Provider value={() => setRevision((current) => current + 1)}><div key={`${vdom}:${revision}`}>{children({ profile: selected, vdom, readonly })}</div></ReloadContext.Provider> : null}
  </div>;
}

/** Serialized body that would be published; build errors count as a change so the bar stays visible. */
function snapshot(profile: Profile | undefined, section: string, build: () => Record<string, unknown>, extend?: (body: PolicyBody) => PolicyBody): string {
  try {
    const built: PolicyBody = { ...profile?.body, [section]: build() };
    return JSON.stringify(extend ? extend(built) : built);
  } catch { return "invalid"; }
}

export function PolicyForm({ profile, vdom, section, readonly, build, extend, children, sections, aside }: { profile: Profile | undefined; vdom: string; section: string; readonly: boolean; build: () => Record<string, unknown>; extend?: (body: PolicyBody) => PolicyBody; children?: ReactNode; sections?: { label: string; items: TabItem[] }; aside?: ReactNode }) {
  const publish = usePublishProfile();
  const profiles = useProfiles();
  const endpoints = useEndpoints();
  const [validation, setValidation] = useState("");
  const reload = useContext(ReloadContext);
  const current = snapshot(profile, section, build, extend);
  const [baseline, setBaseline] = useState(current);
  const dirty = current !== baseline || !profile;
  const conflict = publish.error instanceof ApiError && [409, 412].includes(publish.error.status);
  const unsupported = endpoints.data?.filter((endpoint) => endpoint.effective_vdom === vdom && endpoint.missing_capabilities.length) ?? [];
  return <form className="space-y-4" onSubmit={(event) => {
    event.preventDefault(); setValidation("");
    try {
      if (!vdom.trim() || vdom !== vdom.trim()) throw new Error("Informe um grupo sem espaços no início ou no fim.");
      const built: PolicyBody = { ...profile?.body, [section]: build() };
      const body = extend ? extend(built) : built;
      publish.mutate({ vdom, body, digest: profile?.digest }, { onSuccess: () => setBaseline(JSON.stringify(body)) });
    } catch (error) { setValidation(error instanceof Error ? error.message : "Confira os valores da política."); }
  }}>
    {sections ? <Tabs label={sections.label} items={sections.items} wrap={(panels) => <fieldset disabled={readonly || publish.isPending} className={aside ? "grid min-w-0 items-start gap-4 xl:grid-cols-[minmax(0,1fr)_17.5rem]" : "min-w-0"}>
      <div className="min-w-0">{children}{panels}</div>{aside ? <aside aria-label="Resumo do perfil" className="space-y-4">{aside}</aside> : null}
    </fieldset>} /> : <fieldset disabled={readonly || publish.isPending} className="min-w-0 space-y-4">{children}</fieldset>}
    {unsupported.length ? <InfoNotice>Há agentes sem suporte a parte da política: {unsupported.map((endpoint) => endpoint.devid).join(", ")}. Confira os avisos antes de publicar.</InfoNotice> : null}
    {validation || publish.isError ? <div role="alert" className="rounded-lg bg-danger-soft p-4 text-sm text-danger">{validation || (conflict ? "A política foi alterada por outro administrador. Recarregue antes de publicar." : "Não foi possível publicar a política. Confira os valores e tente de novo.")}{conflict ? <Button className="ml-3" onClick={() => { void profiles.refetch().then(() => reload()); }}>Recarregar política</Button> : null}</div> : null}
    {publish.data ? <div role="status" className="rounded-lg bg-success-soft p-4 text-sm text-success">Perfil {publish.data.vdom} v{publish.data.version} publicado; aguardando confirmação dos agentes.{publish.data.warnings.length ? <ul>{publish.data.warnings.map((warning) => <li key={warning.devid}>{warning.devid}: {warning.missing.join(", ")}</li>)}</ul> : null}</div> : null}
    {!readonly ? <div className="sticky bottom-0 z-20 -mx-6 flex flex-wrap items-center gap-3 border-t border-line bg-surface px-6 py-3 shadow-[0_-6px_18px_rgba(15,23,42,0.06)]">
      <p className="flex items-center gap-2 text-sm text-ink-soft">
        {dirty ? <><span aria-hidden="true" className="size-2 rounded-full bg-warning ring-4 ring-warning-soft" /><span><strong className="font-semibold text-ink">Alterações não publicadas</strong> no grupo {vdom}. Publicar cria uma nova versão; o estado muda para aplicada quando cada agente confirmar.</span></>
          : <><CircleCheck aria-hidden="true" className="size-4 text-success" />Sem alterações desde a versão publicada.</>}
      </p>
      <div className="ml-auto flex gap-2">
        {dirty && profile ? <Button onClick={() => { setValidation(""); reload(); }} disabled={publish.isPending}>Descartar alterações</Button> : null}
        <Button type="submit" variant="primary" disabled={publish.isPending || !vdom.trim()}><Upload aria-hidden="true" className="size-4" />{publish.isPending ? "Publicando…" : "Publicar política"}</Button>
      </div>
    </div> : null}
  </form>;
}

export function InventorySelector({ devid, onChange }: { devid: string; onChange: (devid: string) => void }) {
  const endpoints = useEndpoints();
  return <div className="mb-4"><label className="block max-w-sm text-sm text-ink-soft">Endpoint do inventário<select className={`mt-1 ${FIELD_CLASS}`} value={devid || endpoints.data?.[0]?.devid || ""} onChange={(event) => onChange(event.target.value)}>{endpoints.data?.map((endpoint) => <option key={endpoint.devid} value={endpoint.devid}>{endpoint.hostname || endpoint.devid}</option>)}</select></label>{endpoints.isError ? <ErrorNotice message="Não foi possível carregar os endpoints." onRetry={() => void endpoints.refetch()} /> : null}</div>;
}
