import { useState } from "react";
import { ErrorNotice, InfoNotice, PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader } from "@/components/ui/Card";
import {
  useDeleteLocationPolicy, useEndpoints, useIsAdmin, useLocationPolicies,
  useNetworkLocations, useProfileSummaries, useSaveLocationPolicy,
} from "@/lib/queries";
import type { NetworkLocation } from "@/lib/schemas";
import { DeleteLocationDialog, FIELD_CLASS, LocationDialog } from "./LocationDialog";

function signals(location: NetworkLocation): string {
  return [
    location.cidrs.length ? `${location.cidrs.length} faixa(s) local(is)` : "",
    location.gateway_macs.length ? "MAC do gateway" : "",
    location.dns_suffixes.length ? "Sufixo DNS" : "",
    location.public_cidrs.length ? "IP público" : "",
    location.probe ? "Certificado interno" : "",
  ].filter(Boolean).join(" · ");
}

function LocationMappings({ locations, isAdmin }: { locations: NetworkLocation[]; isAdmin: boolean }) {
  const mappings = useLocationPolicies();
  const profiles = useProfileSummaries();
  const endpoints = useEndpoints();
  const save = useSaveLocationPolicy();
  const remove = useDeleteLocationPolicy();
  const [group, setGroup] = useState("");
  const [local, setLocal] = useState("");
  const [inside, setInside] = useState("");
  const groups = [...new Set([...(profiles.data ?? []).map((item) => item.vdom), ...(endpoints.data ?? []).map((item) => item.effective_vdom)])].filter(Boolean).sort();
  const profileNames = (profiles.data ?? []).map((profile) => profile.vdom).sort();
  const selectedGroup = groups.includes(group) ? group : groups[0] || "";
  const selectedLocal = locations.some((location) => location.id === local) ? local : locations[0]?.id || "";
  const selectedInside = profileNames.includes(inside) ? inside : profileNames[0] || "";
  const locationName = (id: string) => locations.find((location) => location.id === id)?.name ?? id;
  return (
    <Card>
      <CardHeader title="Perfil dentro do local" description="O grupo mantém seu perfil normal fora da empresa. Para desligar o filtro dentro dela, escolha um perfil publicado sem bloqueios." />
      <div className="space-y-4 p-5">
        {mappings.isError ? <ErrorNotice message="Não foi possível carregar os mapeamentos." onRetry={() => void mappings.refetch()} /> : null}
        {mappings.isPending ? <p role="status" className="text-sm text-ink-muted">Carregando mapeamentos…</p> : null}
        {isAdmin ? (
          <>
            {profiles.isError || endpoints.isError ? <ErrorNotice message="Não foi possível carregar os grupos e perfis." onRetry={() => { void profiles.refetch(); void endpoints.refetch(); }} /> : null}
            <form aria-label="Perfil dentro do local" className="grid items-end gap-3 sm:grid-cols-2 xl:grid-cols-4" onSubmit={(event) => {
              event.preventDefault();
              if (selectedGroup && selectedLocal && selectedInside) save.mutate({ vdom: selectedGroup, location_id: selectedLocal, inside_vdom: selectedInside });
            }}>
              <label className="text-sm text-ink-soft">Grupo<select className={`mt-1 ${FIELD_CLASS}`} value={selectedGroup} onChange={(event) => setGroup(event.target.value)}>{groups.map((value) => <option key={value}>{value}</option>)}</select></label>
              <label className="text-sm text-ink-soft">Local<select className={`mt-1 ${FIELD_CLASS}`} value={selectedLocal} onChange={(event) => setLocal(event.target.value)}>{locations.map((location) => <option key={location.id} value={location.id}>{location.name}</option>)}</select></label>
              <label className="text-sm text-ink-soft">Perfil interno<select className={`mt-1 ${FIELD_CLASS}`} value={selectedInside} onChange={(event) => setInside(event.target.value)}>{profileNames.map((value) => <option key={value}>{value}</option>)}</select></label>
              <Button type="submit" variant="primary" disabled={save.isPending || mappings.isPending || mappings.isError || !selectedGroup || !selectedLocal || !selectedInside || profiles.isError || endpoints.isError}>{save.isPending ? "Salvando…" : "Salvar mapeamento"}</Button>
            </form>
            {save.isError || remove.isError ? <p role="alert" className="text-sm text-danger">Não foi possível alterar o mapeamento. Confira se o perfil ainda existe e tente de novo.</p> : null}
          </>
        ) : null}
        {mappings.isSuccess && !mappings.data.length ? <p className="text-sm text-ink-muted">Nenhum mapeamento: os grupos usam sempre a política de fora.</p> : null}
        {mappings.data?.length ? (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <caption className="sr-only">Perfis por grupo e local</caption>
              <thead className="border-b border-line text-ink-muted"><tr><th className="py-2 pr-3 font-medium">Grupo</th><th className="py-2 pr-3 font-medium">Local</th><th className="py-2 pr-3 font-medium">Perfil interno</th>{isAdmin ? <th className="py-2 text-right font-medium">Ações</th> : null}</tr></thead>
              <tbody className="divide-y divide-line">
                {mappings.data.map((mapping) => (
                  <tr key={`${mapping.vdom}:${mapping.location_id}`}><td className="py-3 pr-3">{mapping.vdom}</td><td className="py-3 pr-3">{locationName(mapping.location_id)}</td><td className="py-3 pr-3">{mapping.inside_vdom}</td>{isAdmin ? <td className="py-3 text-right"><Button size="sm" variant="ghost" disabled={remove.isPending} aria-label={`Remover mapeamento de ${mapping.vdom} em ${locationName(mapping.location_id)}`} onClick={() => remove.mutate(mapping)}>Remover</Button></td> : null}</tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : null}
      </div>
    </Card>
  );
}

export function LocationsPage() {
  const locations = useNetworkLocations();
  const isAdmin = useIsAdmin();
  const [editing, setEditing] = useState<NetworkLocation | null | undefined>(undefined);
  const [deleting, setDeleting] = useState<NetworkLocation | null>(null);
  return (
    <div className="space-y-6">
      <PageHeader title="Locais de rede" description="Políticas diferentes dentro e fora da empresa, com decisão no agente mesmo sem contato com o servidor." actions={isAdmin ? <Button variant="primary" disabled={locations.isPending || locations.isError} onClick={() => setEditing(null)}>Novo local</Button> : null} />
      <InfoNotice>O IP público de saída pode identificar um local sozinho. Os demais sinais exigem pelo menos dois tipos. Se mais de um local casar, vale o primeiro em ordem de nome. Sem confirmação, vale a política de fora.</InfoNotice>
      {locations.isError ? <ErrorNotice message="Não foi possível carregar os locais de rede." onRetry={() => void locations.refetch()} /> : null}
      <Card>
        <CardHeader title="Locais cadastrados" description="As definições são enviadas aos grupos que têm um perfil interno mapeado." />
        <div className="p-5">
          {locations.isPending ? <p role="status" className="text-sm text-ink-muted">Carregando locais…</p> : null}
          {locations.isSuccess && !locations.data.length ? <p className="text-sm text-ink-muted">Nenhum local cadastrado. Adicione os sinais de rede da empresa para começar.</p> : null}
          {locations.data?.length ? (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <caption className="sr-only">Locais de rede cadastrados</caption>
                <thead className="border-b border-line text-ink-muted"><tr><th className="py-2 pr-3 font-medium">Local</th><th className="py-2 pr-3 font-medium">Sinais</th>{isAdmin ? <th className="py-2 text-right font-medium">Ações</th> : null}</tr></thead>
                <tbody className="divide-y divide-line">
                  {locations.data.map((location) => (
                    <tr key={location.id}>
                      <td className="py-3 pr-3 font-medium text-ink">{location.name}<span className="mt-0.5 block font-mono text-xs text-ink-muted">{location.id}</span></td>
                      <td className="py-3 pr-3 text-ink-soft">{signals(location)}</td>
                      {isAdmin ? <td className="py-3 text-right"><div className="flex justify-end gap-1"><Button size="sm" variant="ghost" aria-label={`Editar ${location.name}`} onClick={() => setEditing(location)}>Editar</Button><Button size="sm" variant="ghost" aria-label={`Excluir ${location.name}`} onClick={() => setDeleting(location)}>Excluir</Button></div></td> : null}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : null}
        </div>
      </Card>
      {locations.data ? <LocationMappings locations={locations.data} isAdmin={isAdmin} /> : null}
      {isAdmin && editing !== undefined ? <LocationDialog key={editing?.id ?? "new"} location={editing} onClose={() => setEditing(undefined)} /> : null}
      {isAdmin && deleting ? <DeleteLocationDialog location={deleting} onClose={() => setDeleting(null)} /> : null}
    </div>
  );
}
