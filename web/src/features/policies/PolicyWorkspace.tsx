import { createContext, useContext, useState, type ReactNode } from "react";
import { ErrorNotice, InfoNotice, PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader } from "@/components/ui/Card";
import { ApiError } from "@/lib/api";
import { useProfiles, usePublishProfile, type PolicyBody, type Profile } from "@/lib/management";
import { useEndpoints, useIsAdmin } from "@/lib/queries";
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
  const [vdom, setVdom] = useState(storedGroup);
  const [revision, setRevision] = useState(0);
  const readonly = !useIsAdmin();
  const selected = profiles.data?.find((profile) => profile.vdom === vdom);
  return <div className="space-y-6">
    <PageHeader title={title} description={description} />
    <InfoNotice>Publicar cria uma nova versão. O estado só muda para aplicada quando cada agente confirmar. As outras seções do perfil são preservadas.</InfoNotice>
    {profiles.isError ? <ErrorNotice message="Não foi possível carregar as políticas." onRetry={() => void profiles.refetch()} /> : null}
    <Card><CardHeader title="Política por grupo" description={selected ? `Versão publicada: v${selected.version}` : "Um grupo novo recebe seu primeiro perfil ao publicar."} />
      <div className="p-5">{profiles.isSuccess ? <GroupPicker published={profiles.data} value={vdom} onChange={setVdom} readonly={readonly} /> : <p className="text-sm text-ink-soft">Carregando grupos…</p>}</div>
    </Card>
    {profiles.isPending ? <p role="status">Carregando políticas…</p> : null}
    {profiles.isSuccess ? <ReloadContext.Provider value={() => setRevision((current) => current + 1)}><div key={`${vdom}:${revision}`}>{children({ profile: selected, vdom, readonly })}</div></ReloadContext.Provider> : null}
  </div>;
}

export function PolicyForm({ profile, vdom, section, readonly, build, children }: { profile: Profile | undefined; vdom: string; section: string; readonly: boolean; build: () => Record<string, unknown>; children: ReactNode }) {
  const publish = usePublishProfile();
  const profiles = useProfiles();
  const endpoints = useEndpoints();
  const [validation, setValidation] = useState("");
  const reload = useContext(ReloadContext);
  const conflict = publish.error instanceof ApiError && [409, 412].includes(publish.error.status);
  const unsupported = endpoints.data?.filter((endpoint) => endpoint.effective_vdom === vdom && endpoint.missing_capabilities.length) ?? [];
  return <form className="space-y-5" onSubmit={(event) => {
    event.preventDefault(); setValidation("");
    try {
      if (!vdom.trim() || vdom !== vdom.trim()) throw new Error("Informe um grupo sem espaços no início ou no fim.");
      const body: PolicyBody = { ...profile?.body, [section]: build() };
      publish.mutate({ vdom, body, digest: profile?.digest });
    } catch (error) { setValidation(error instanceof Error ? error.message : "Confira os valores da política."); }
  }}>
    <fieldset disabled={readonly || publish.isPending} className="space-y-5">{children}</fieldset>
    {unsupported.length ? <InfoNotice>Há agentes sem suporte a parte da política: {unsupported.map((endpoint) => endpoint.devid).join(", ")}. Confira os avisos antes de publicar.</InfoNotice> : null}
    {validation || publish.isError ? <div role="alert" className="rounded-xl bg-danger-soft p-4 text-sm text-danger">{validation || (conflict ? "A política foi alterada por outro administrador. Recarregue antes de publicar." : "Não foi possível publicar a política. Confira os valores e tente de novo.")}{conflict ? <Button className="ml-3" onClick={() => { void profiles.refetch().then(() => reload()); }}>Recarregar política</Button> : null}</div> : null}
    {publish.data ? <div role="status" className="rounded-xl bg-rsm-green-soft p-4 text-sm text-rsm-green">Perfil {publish.data.vdom} v{publish.data.version} publicado; aguardando confirmação dos agentes.{publish.data.warnings.length ? <ul>{publish.data.warnings.map((warning) => <li key={warning.devid}>{warning.devid}: {warning.missing.join(", ")}</li>)}</ul> : null}</div> : null}
    {!readonly ? <Button type="submit" variant="primary" disabled={publish.isPending || !vdom.trim()}>{publish.isPending ? "Publicando…" : "Publicar política"}</Button> : null}
  </form>;
}

export function InventorySelector({ devid, onChange }: { devid: string; onChange: (devid: string) => void }) {
  const endpoints = useEndpoints();
  return <div className="mb-4"><label className="block max-w-sm text-sm text-ink-soft">Endpoint do inventário<select className={`mt-1 ${FIELD_CLASS}`} value={devid || endpoints.data?.[0]?.devid || ""} onChange={(event) => onChange(event.target.value)}>{endpoints.data?.map((endpoint) => <option key={endpoint.devid} value={endpoint.devid}>{endpoint.hostname || endpoint.devid}</option>)}</select></label>{endpoints.isError ? <ErrorNotice message="Não foi possível carregar os endpoints." onRetry={() => void endpoints.refetch()} /> : null}</div>;
}
