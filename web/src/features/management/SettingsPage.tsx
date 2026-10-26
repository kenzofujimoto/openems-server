import { useState } from "react";
import { useQueryClient } from "@tanstack/react-query";
import { z } from "zod";
import { ErrorNotice, InfoNotice, PageHeader } from "@/components/PageHeader";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader } from "@/components/ui/Card";
import { Field, FIELD_CLASS } from "@/features/policies/PolicyWorkspace";
import { ApiError, apiDownload, apiFetch } from "@/lib/api";
import { formatDateTime, formatNumber } from "@/lib/format";
import { useIsAdmin, useSession } from "@/lib/queries";
import { administratorSchema, createdInvitationSchema, useAdministrators, useInstaller, useInvitations, useSettings, type Administrator } from "@/lib/settings";
import { ConfirmDialog } from "./ConfirmDialog";

function Invitations() {
  const invitations = useInvitations(true);
  const installer = useInstaller(true);
  const [vdom, setVdom] = useState("Default");
  const [uses, setUses] = useState("1");
  const [ttl, setTtl] = useState("3600");
  const [token, setToken] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  const [revoking, setRevoking] = useState<string | null>(null);
  const [copied, setCopied] = useState("");
  async function generate(bundle: boolean) {
    setError(""); setCopied(""); setToken("");
    const payload = { vdom: vdom.trim(), max_uses: Number(uses), ttl_seconds: Number(ttl) };
    if (!payload.vdom || !Number.isInteger(payload.max_uses) || payload.max_uses < 1 || payload.max_uses > 1000 || !Number.isInteger(payload.ttl_seconds) || payload.ttl_seconds < 60 || payload.ttl_seconds > 86400) return setError("Informe grupo, de 1 a 1000 usos e validade de 60 a 86400 segundos.");
    setPending(true);
    try {
      if (bundle) await apiDownload("/api/v1/installers/windows/bundle", "openems-windows.zip", payload);
      else setToken((await apiFetch("/api/v1/enrollment/invitations", createdInvitationSchema, { method: "POST", json: payload })).invitation);
      await invitations.refetch();
    } catch (failure) { setError(failure instanceof ApiError && failure.status === 503 ? "O pacote exige um MSI e a URL pública do servidor configurados pelo operador." : "Não foi possível gerar o convite ou o pacote. Tente de novo."); }
    finally { setPending(false); }
  }
  async function revoke() {
    if (!revoking) return;
    setPending(true); setError("");
    try { await apiFetch(`/api/v1/enrollment/invitations/${encodeURIComponent(revoking)}`, z.object({ removed: z.string() }), { method: "DELETE" }); setRevoking(null); await invitations.refetch(); }
    catch { setError("Não foi possível revogar o convite."); }
    finally { setPending(false); }
  }
  return <>
    <Card><CardHeader title="Convites e instalador Windows" description="Convites são limitados em usos e validade. O token aparece uma vez e não fica guardado na lista." /><div className="space-y-4 p-5">
      <fieldset disabled={pending} className="grid gap-3 sm:grid-cols-3"><Field label="Grupo do convite" value={vdom} onChange={setVdom} /><Field label="Máximo de usos" type="number" value={uses} onChange={setUses} /><Field label="Validade em segundos" type="number" value={ttl} onChange={setTtl} /></fieldset>
      <div className="flex flex-wrap gap-2"><Button variant="primary" disabled={pending} onClick={() => void generate(false)}>Gerar convite</Button>{installer.data?.available ? <><a className="inline-flex h-10 items-center rounded-lg border border-line px-4 text-sm" href={installer.data.download_url}>Baixar MSI</a><Button disabled={pending} onClick={() => void generate(true)}>Baixar pacote configurado</Button></> : null}</div>
      {token ? <div className="rounded-xl bg-canvas p-4"><p className="text-sm">Guarde agora. Ao sair desta tela, o token desaparece.</p><code className="mt-2 block break-all text-sm">{token}</code><Button className="mt-3" onClick={() => { void navigator.clipboard.writeText(token).then(() => setCopied("Convite copiado."), () => setCopied("Não foi possível copiar. Selecione o token manualmente.")); }}>Copiar convite</Button>{copied ? <p role="status" className="mt-2 text-sm">{copied}</p> : null}</div> : null}
      {error ? <p role="alert" className="text-sm text-danger">{error}</p> : null}
      {installer.isPending ? <p role="status">Carregando instalador…</p> : installer.isError ? <ErrorNotice message="Não foi possível verificar o instalador." onRetry={() => void installer.refetch()} /> : installer.data?.available ? <p className="break-all text-xs text-ink-muted">{installer.data.filename} · {formatNumber(installer.data.size)} bytes · SHA-256 {installer.data.sha256}</p> : <p className="text-sm text-ink-muted">Nenhum MSI configurado no servidor. O operador deve publicar o artefato assinado; o painel não compila nem assina executáveis.</p>}
      {invitations.isError ? <ErrorNotice message="Não foi possível carregar os convites." onRetry={() => void invitations.refetch()} /> : null}
      <ul className="divide-y divide-line">{invitations.data?.map((invitation) => <li key={invitation.id} className="flex flex-wrap items-center justify-between gap-3 py-3 text-sm"><span>{invitation.vdom} · {invitation.remaining} uso(s) restantes · Expira {formatDateTime(invitation.expires_at)}</span><Button size="sm" aria-label={`Revogar convite de ${invitation.vdom}`} onClick={() => { setError(""); setRevoking(invitation.id); }}>Revogar</Button></li>)}</ul>{invitations.isSuccess && !invitations.data.length ? <p className="text-sm text-ink-muted">Nenhum convite ativo.</p> : null}
    </div></Card>
    {revoking ? <ConfirmDialog title="Revogar convite" message="O convite não poderá cadastrar novas máquinas. Cadastros existentes continuam válidos." confirm="Confirmar revogação" pending={pending} error={Boolean(error)} onClose={() => setRevoking(null)} onConfirm={() => void revoke()} /> : null}
  </>;
}

function Administrators() {
  const administrators = useAdministrators(true);
  const session = useSession().data;
  const client = useQueryClient();
  const [editing, setEditing] = useState<Administrator | null>(null);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState<"viewer" | "admin">("viewer");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState("");
  const [deleting, setDeleting] = useState<Administrator | null>(null);
  function edit(value: Administrator | null) { setEditing(value); setUsername(value?.username ?? ""); setRole(value?.role === "admin" ? "admin" : "viewer"); setPassword(""); setError(""); setSaved(""); }
  async function save() {
    setError(""); setSaved("");
    if (!username.trim() || (!editing && !password)) return setError("Informe usuário e senha inicial.");
    setPending(true);
    try {
      await apiFetch(editing ? `/api/v1/admins/${encodeURIComponent(editing.username)}` : "/api/v1/admins", administratorSchema, { method: editing ? "PUT" : "POST", json: editing ? { role, ...(password ? { password } : {}) } : { username: username.trim(), password, role } });
      setPassword(""); setSaved("Administrador salvo.");
      await client.invalidateQueries({ queryKey: ["administrators"] });
    } catch (failure) { setError(failure instanceof ApiError && failure.status === 409 ? "O usuário já existe ou esta alteração removeria o último administrador." : "Não foi possível salvar. Confira a senha e as permissões."); }
    finally { setPending(false); }
  }
  async function remove() {
    if (!deleting) return;
    setPending(true); setError("");
    try { await apiFetch(`/api/v1/admins/${encodeURIComponent(deleting.username)}`, z.object({ removed: z.string() }), { method: "DELETE" }); setDeleting(null); await administrators.refetch(); }
    catch { setError("Não foi possível excluir. A própria conta, o superadministrador e o último administrador são protegidos."); }
    finally { setPending(false); }
  }
  return <><Card><CardHeader title="Administradores e papéis" description="Leitores consultam o painel; administradores alteram políticas. Senhas nunca aparecem na lista." action={<Button onClick={() => edit(null)}>Novo administrador</Button>} /><div className="space-y-4 p-5">
    {administrators.isError ? <ErrorNotice message="Não foi possível carregar os administradores." onRetry={() => void administrators.refetch()} /> : null}
    <ul className="divide-y divide-line">{administrators.data?.map((administrator) => <li key={administrator.username} className="flex flex-wrap items-center justify-between gap-3 py-3 text-sm"><span>{administrator.username} · {administrator.role === "viewer" ? "Leitor" : administrator.role === "superadmin" ? "Superadministrador" : "Administrador"}</span>{administrator.role !== "superadmin" ? <div className="flex gap-2"><Button size="sm" aria-label={`Editar administrador ${administrator.username}`} onClick={() => edit(administrator)}>Editar</Button><Button size="sm" disabled={administrator.username === session?.username} aria-label={`Excluir administrador ${administrator.username}`} onClick={() => { setError(""); setDeleting(administrator); }}>Excluir</Button></div> : null}</li>)}</ul>
    <form className="space-y-4" onSubmit={(event) => { event.preventDefault(); void save(); }}><fieldset disabled={pending} className="grid gap-3 sm:grid-cols-3"><label className="text-sm">Novo usuário<input autoComplete="off" className={`mt-1 ${FIELD_CLASS}`} disabled={Boolean(editing)} value={username} onChange={(event) => setUsername(event.target.value)} /></label><label className="text-sm">{editing ? "Nova senha (opcional)" : "Senha inicial"}<input type="password" autoComplete="new-password" className={`mt-1 ${FIELD_CLASS}`} value={password} onChange={(event) => setPassword(event.target.value)} /></label><label className="text-sm">Papel<select className={`mt-1 ${FIELD_CLASS}`} value={role} onChange={(event) => setRole(event.target.value as "viewer" | "admin")}><option value="viewer">Leitor</option><option value="admin">Administrador</option></select></label></fieldset>{error && !deleting ? <p role="alert" className="text-sm text-danger">{error}</p> : null}{saved ? <p role="status" className="text-sm text-rsm-green">{saved}</p> : null}<Button type="submit" variant="primary" disabled={pending}>{editing ? "Salvar administrador" : "Criar administrador"}</Button></form>
  </div></Card>{deleting ? <ConfirmDialog title="Excluir administrador" message={`Remover o acesso de ${deleting.username}?`} confirm="Confirmar exclusão do administrador" pending={pending} error={Boolean(error)} onClose={() => setDeleting(null)} onConfirm={() => void remove()} /> : null}</>;
}

function IdentityProvider() {
  const [prefix, setPrefix] = useState("Default");
  const [metadata, setMetadata] = useState("");
  const [pending, setPending] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");
  return <Card><CardHeader title="Provedor de identidade SAML" description="Importe o XML de metadados obtido diretamente do provedor. O servidor valida o documento e seus endereços." /><form className="space-y-4 p-5" onSubmit={(event) => {
    event.preventDefault(); setPending(true); setError(""); setMessage("");
    void apiFetch("/fct_saml/parse_remote_metadata", z.object({ prefix: z.string(), idp_entity_id: z.string(), sso_url: z.string() }), { method: "POST", json: { prefix: prefix.trim(), metadata } }).then((result) => { setMessage(`Provedor importado: ${result.idp_entity_id}`); setMetadata(""); }, (failure: unknown) => setError(failure instanceof ApiError && failure.status === 503 ? "SAML não está configurado neste servidor." : "Não foi possível importar. Confira o XML e as permissões.")).finally(() => setPending(false));
  }}><fieldset disabled={pending} className="space-y-3"><Field label="Grupo SAML" value={prefix} onChange={setPrefix} /><label className="block text-sm">Metadados XML do provedor<textarea className={`mt-1 font-mono ${FIELD_CLASS}`} rows={5} value={metadata} onChange={(event) => setMetadata(event.target.value)} maxLength={512000} /></label></fieldset>{message ? <p role="status" className="text-sm text-rsm-green">{message}</p> : null}{error ? <p role="alert" className="text-sm text-danger">{error}</p> : null}<div className="flex flex-wrap items-center gap-3"><Button type="submit" disabled={pending || !prefix.trim() || !metadata.trim()}>Importar provedor SAML</Button><a className="text-sm text-rsm-blue-dark underline" href={`/fct_saml/${encodeURIComponent(prefix.trim() || "Default")}/metadata`}>Metadados públicos do servidor</a></div></form></Card>;
}

export function SettingsPage() {
  const settings = useSettings();
  const isAdmin = useIsAdmin();
  return <div className="space-y-6"><PageHeader title="Configurações" description="Cadastro de agentes, acesso administrativo e parâmetros operacionais." />
    {settings.isError ? <ErrorNotice message="Não foi possível carregar as configurações." onRetry={() => void settings.refetch()} /> : null}
    <Card><CardHeader title="Servidor" /><dl className="grid gap-4 p-5 text-sm sm:grid-cols-3"><div><dt className="text-ink-muted">Versão</dt><dd className="mt-1">{settings.data?.server_version ?? "—"}</dd></div><div><dt className="text-ink-muted">Retenção de eventos</dt><dd className="mt-1">{settings.data ? `${settings.data.event_retention_days} dias` : "—"}</dd></div><div><dt className="text-ink-muted">Origem das configurações</dt><dd className="mt-1">Ambiente do servidor</dd></div></dl></Card>
    <InfoNotice>A retenção e o instalador são configurados pelo operador do servidor. Códigos e liberações de desinstalação ficam na página de endpoints.</InfoNotice>
    {isAdmin ? <><Invitations /><Administrators /><IdentityProvider /></> : null}
  </div>;
}
