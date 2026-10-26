import { useState } from "react";
import { ErrorNotice, InfoNotice } from "@/components/PageHeader";
import { Button } from "@/components/ui/Button";
import { Card, CardHeader } from "@/components/ui/Card";
import { formatDateTime } from "@/lib/format";
import { useInventory, type Application, type Profile, type UsbDevice } from "@/lib/management";
import { useEndpoints } from "@/lib/queries";
import { FIELD_CLASS, Field, InventorySelector, lines, PolicyForm, PolicyWorkspace, record, strings, TextArea } from "./PolicyWorkspace";

interface ExecutionRule { id: string; kind: "hash" | "publisher" | "path" | "name"; value: string; sample_path?: string }
interface UsbRule { id: string; action: "allow" | "block" | "read_only"; class?: "storage"; vid?: string; pid?: string; serial?: string; instance_id?: string }
type Props = { profile: Profile | undefined; vdom: string; readonly: boolean };
const hasControl = (text: string) => [...text].some((character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127);
const absolute = (path: string) => /^(?:[a-z]:[\\/]|\/)/i.test(path) && !hasControl(path);
function nextId(prefix: string, rules: { id: string }[]) { let index = 1; while (rules.some((rule) => rule.id === `${prefix}-${index}`)) index++; return `${prefix}-${index}`; }

function useDeviceInventory() {
  const endpoints = useEndpoints();
  const [selected, select] = useState("");
  const devid = selected || endpoints.data?.[0]?.devid || "";
  return { devid, select, inventory: useInventory(devid) };
}

function ApplicationEditor({ profile, vdom, readonly }: Props) {
  const settings = record(profile?.body.app_control);
  const [blocked, setBlocked] = useState(strings(settings.blocked).join("\n"));
  const [network, setNetwork] = useState(strings(settings.network_blocked).join("\n"));
  const [rules, setRules] = useState<ExecutionRule[]>(() => Array.isArray(settings.execution_rules) ? settings.execution_rules.map((item) => { const rule = record(item); return { id: String(rule.id), kind: String(rule.kind) as ExecutionRule["kind"], value: String(rule.value), ...(rule.sample_path ? { sample_path: String(rule.sample_path) } : {}) }; }) : []);
  const { devid, select, inventory } = useDeviceInventory();
  function addApplication(application: Application, kind: ExecutionRule["kind"]) {
    const value = kind === "hash" ? application.sha256 : kind === "publisher" ? application.publisher : kind === "path" ? application.path : application.path.split(/[\\/]/).at(-1) ?? application.name;
    setRules((current) => [...current, { id: nextId("app", current), kind, value, sample_path: application.path }]);
  }
  function update(index: number, patch: Partial<ExecutionRule>) { setRules((current) => current.map((rule, at) => at === index ? { ...rule, ...patch } : rule)); }
  return <><InventorySelector devid={devid} onChange={select} /><PolicyForm {...{ profile, vdom, readonly }} section="app_control" build={() => {
    const processes = lines(blocked);
    if (processes.some((name) => /[\\/:*?"<>|]/.test(name) || hasControl(name))) throw new Error("Informe apenas nomes de processos, sem caminho, na lista de encerramento.");
    const paths = lines(network);
    if (paths.some((path) => !absolute(path))) throw new Error("Informe caminhos absolutos para o bloqueio de rede.");
    for (const rule of rules) {
      if (!rule.value.trim()) throw new Error("Preencha o valor de todas as regras de execução.");
      if (rule.kind === "hash" && !/^[a-f0-9]{64}$/i.test(rule.value)) throw new Error("O hash deve ser SHA-256 com 64 dígitos hexadecimais.");
      if (rule.kind === "path" ? !absolute(rule.value) : !rule.sample_path || !absolute(rule.sample_path)) throw new Error("Regras por hash, editor e nome precisam do caminho absoluto de uma amostra local; caminhos também devem ser absolutos.");
    }
    const next: Record<string, unknown> = { ...settings, blocked: processes };
    if (rules.length) next.execution_rules = rules.map((rule) => ({ ...rule, value: rule.kind === "hash" ? rule.value.toLowerCase() : rule.value })); else delete next.execution_rules;
    if (paths.length) next.network_blocked = paths; else delete next.network_blocked;
    return next;
  }}>
    <InfoNotice>O bloqueio antes da execução exige suporte ao App Control no Windows. O caminho da amostra deve existir na máquina protegida; use o inventário dela para escolher o arquivo. As capacidades e falhas de aplicação aparecem na ficha do endpoint.</InfoNotice>
    <Card><CardHeader title="Regras de execução" description="Negação por hash, editor verificado, caminho ou nome original. O agente confirma somente depois de aplicar." /><div className="space-y-4 p-5">{rules.map((rule, index) => <div key={rule.id} className="grid gap-3 rounded-xl border border-line p-4 sm:grid-cols-2"><label className="text-sm">Tipo da regra {index + 1}<select className={`mt-1 ${FIELD_CLASS}`} value={rule.kind} onChange={(event) => update(index, { kind: event.target.value as ExecutionRule["kind"] })}><option value="hash">SHA-256</option><option value="publisher">Editor</option><option value="path">Caminho</option><option value="name">Nome original</option></select></label><Field label={`Valor da regra ${index + 1}`} value={rule.value} onChange={(value) => update(index, { value })} /><Field label={`Amostra local da regra ${index + 1}`} value={rule.sample_path ?? ""} onChange={(sample_path) => update(index, { sample_path })} /><Button onClick={() => setRules((current) => current.filter((_, at) => at !== index))}>Remover regra {index + 1}</Button></div>)}<Button onClick={() => setRules((current) => [...current, { id: nextId("app", current), kind: "hash", value: "", sample_path: "" }])}>Adicionar regra de execução</Button></div></Card>
    <Card><CardHeader title="Rede e encerramento" description="O bloqueio de rede não impede abrir o aplicativo. Encerramento periódico é uma proteção complementar." /><div className="grid gap-4 p-5 md:grid-cols-2"><TextArea label="Aplicativos sem acesso à rede" value={network} onChange={setNetwork} /><TextArea label="Processos a encerrar" value={blocked} onChange={setBlocked} /></div></Card>
    <Card><CardHeader title="Inventário de aplicativos" description="Dados da última coleta do agente, incluindo aplicativos instalados e em execução." /><div className="p-5">{inventory.isPending && devid ? <p role="status">Carregando inventário…</p> : null}{inventory.isError ? <ErrorNotice message="Não foi possível carregar o inventário." onRetry={() => void inventory.refetch()} /> : null}{inventory.isSuccess && !inventory.data.applications.length ? <p className="text-sm text-ink-muted">O agente ainda não informou aplicativos.</p> : null}<div className="space-y-3">{inventory.data?.applications.map((application, index) => <article key={`${application.path}:${index}`} className="rounded-xl border border-line p-4 text-sm"><p className="font-medium">{application.name} {application.version}{application.running ? " · Em execução" : ""}</p><p className="mt-1 break-all text-ink-muted">{application.path}</p><p className="mt-1 text-ink-soft">{application.publisher || "Editor não verificado"}</p><code className="mt-1 block break-all text-xs text-ink-muted">{application.sha256 || "Hash indisponível"}</code><div className="mt-3 flex flex-wrap gap-2"><Button size="sm" disabled={!application.sha256} aria-label={`Bloquear hash de ${application.name}`} onClick={() => addApplication(application, "hash")}>Bloquear hash</Button><Button size="sm" disabled={!application.publisher} aria-label={`Bloquear editor de ${application.name}`} onClick={() => addApplication(application, "publisher")}>Bloquear editor</Button><Button size="sm" aria-label={`Bloquear nome de ${application.name}`} onClick={() => addApplication(application, "name")}>Bloquear nome</Button><Button size="sm" aria-label={`Bloquear rede de ${application.name}`} onClick={() => setNetwork((current) => [...new Set([...lines(current), application.path])].join("\n"))}>Bloquear rede</Button></div></article>)}</div></div></Card>
  </PolicyForm></>;
}

function UsbEditor({ profile, vdom, readonly }: Props) {
  const settings = record(profile?.body.usb_control);
  const [defaultAction, setDefaultAction] = useState(String(settings.default_action ?? "allow"));
  const [rules, setRules] = useState<UsbRule[]>(() => Array.isArray(settings.rules) ? settings.rules.map((item) => { const rule = record(item); return { id: String(rule.id), action: String(rule.action) as UsbRule["action"], ...Object.fromEntries(["class", "vid", "pid", "serial", "instance_id"].filter((key) => typeof rule[key] === "string").map((key) => [key, rule[key]])) }; }) : []);
  const { devid, select, inventory } = useDeviceInventory();
  function update(index: number, patch: Partial<UsbRule>) { setRules((current) => current.map((rule, at) => at === index ? { ...rule, ...patch } : rule)); }
  function allow(device: UsbDevice) { setRules((current) => [...current, { id: nextId("usb", current), action: "allow", ...(device.vid ? { vid: device.vid } : {}), ...(device.pid ? { pid: device.pid } : {}), ...(device.serial ? { serial: device.serial } : { instance_id: device.instance_id }) }]); }
  function move(index: number, delta: number) { setRules((current) => { const next = [...current]; const other = index + delta; const item = next[index]; const neighbor = next[other]; if (item && neighbor) { next[index] = neighbor; next[other] = item; } return next; }); }
  return <><InventorySelector devid={devid} onChange={select} /><PolicyForm {...{ profile, vdom, readonly }} section="usb_control" build={() => {
    const normalized = rules.map((rule) => ({ id: rule.id, action: rule.action, ...Object.fromEntries(["class", "vid", "pid", "serial", "instance_id"].filter((key) => Boolean(rule[key as keyof UsbRule])).map((key) => [key, rule[key as keyof UsbRule]])) }));
    for (const rule of rules) {
      if (!rule.class && !rule.vid && !rule.pid && !rule.serial && !rule.instance_id) throw new Error("Cada regra USB precisa de ao menos um seletor. Use a ação padrão para todos os dispositivos de armazenamento.");
      if ([rule.vid, rule.pid].some((value) => value && !/^[a-f0-9]{4}$/i.test(value))) throw new Error("VID e PID devem ter quatro dígitos hexadecimais.");
    }
    return { ...settings, default_action: defaultAction, rules: normalized };
  }}>
    <InfoNotice>Somente armazenamento USB é controlado: teclado e mouse não entram nessas regras. A primeira regra que corresponder a todos os seus seletores vence. Os demais dispositivos seguem a ação padrão.</InfoNotice>
    <Card><CardHeader title="Armazenamento removível" /><div className="space-y-4 p-5"><label className="block max-w-sm text-sm">Ação padrão para armazenamento<select className={`mt-1 ${FIELD_CLASS}`} value={defaultAction} onChange={(event) => setDefaultAction(event.target.value)}><option value="allow">Permitir</option><option value="block">Bloquear</option><option value="read_only">Somente leitura</option></select></label>{rules.map((rule, index) => <div key={rule.id} className="space-y-3 rounded-xl border border-line p-4"><div className="grid gap-3 sm:grid-cols-2"><label className="text-sm">Ação da regra USB {index + 1}<select className={`mt-1 ${FIELD_CLASS}`} value={rule.action} onChange={(event) => update(index, { action: event.target.value as UsbRule["action"] })}><option value="allow">Permitir</option><option value="block">Bloquear</option><option value="read_only">Somente leitura</option></select></label><label className="text-sm">Classe da regra USB {index + 1}<select className={`mt-1 ${FIELD_CLASS}`} value={rule.class ?? ""} onChange={(event) => update(index, { class: event.target.value ? "storage" : undefined })}><option value="">Qualquer armazenamento</option><option value="storage">Armazenamento USB</option></select></label>{(["vid", "pid", "serial", "instance_id"] as const).map((key) => <Field key={key} label={`${{ vid: "VID", pid: "PID", serial: "Serial", instance_id: "Instância" }[key]} da regra USB ${index + 1}`} value={rule[key] ?? ""} onChange={(value) => update(index, { [key]: value })} />)}</div><div className="flex flex-wrap gap-2"><Button size="sm" disabled={index === 0} onClick={() => move(index, -1)}>Subir regra USB {index + 1}</Button><Button size="sm" disabled={index === rules.length - 1} onClick={() => move(index, 1)}>Descer regra USB {index + 1}</Button><Button size="sm" onClick={() => setRules((current) => current.filter((_, at) => at !== index))}>Remover regra USB {index + 1}</Button></div></div>)}<Button onClick={() => setRules((current) => [...current, { id: nextId("usb", current), action: "allow", class: "storage" }])}>Adicionar regra USB</Button></div></Card>
    <Card><CardHeader title="Inventário USB" description="Histórico informado pelo agente. Dados de primeira e última conexão permanecem disponíveis quando o dispositivo é retirado." /><div className="p-5">{inventory.isPending && devid ? <p role="status">Carregando inventário…</p> : null}{inventory.isError ? <ErrorNotice message="Não foi possível carregar o inventário." onRetry={() => void inventory.refetch()} /> : null}{inventory.isSuccess && !inventory.data.usb_devices.length ? <p className="text-sm text-ink-muted">O agente ainda não informou dispositivos USB.</p> : null}<div className="space-y-3">{inventory.data?.usb_devices.map((device) => <article key={device.instance_id} className="rounded-xl border border-line p-4 text-sm"><p className="font-medium">{device.product || device.instance_id} · {device.present ? "Conectado" : "Desconectado"}</p><p className="mt-1 text-ink-soft">{device.manufacturer} · VID {device.vid || "—"} / PID {device.pid || "—"} · Serial {device.serial || "—"}</p><p className="mt-1 break-all text-xs text-ink-muted">{device.instance_id}</p><p className="mt-1 text-xs text-ink-muted">{device.drive_letters.join(", ") || "Sem unidade"} · Primeira: {formatDateTime(device.first_seen)} · Última: {formatDateTime(device.last_seen)}</p><Button className="mt-3" size="sm" aria-label={`Permitir ${device.product || device.instance_id}`} disabled={device.class !== "storage"} onClick={() => allow(device)}>Criar exceção de permissão</Button></article>)}</div></div></Card>
  </PolicyForm></>;
}

export function ApplicationsPage() { return <PolicyWorkspace title="Controle de aplicativos" description="Regras de execução, bloqueio de rede e inventário de aplicativos.">{(props) => <ApplicationEditor {...props} />}</PolicyWorkspace>; }
export function UsbPage() { return <PolicyWorkspace title="Controle de USB" description="Regras de permitir, bloquear ou limitar a leitura de armazenamento removível.">{(props) => <UsbEditor {...props} />}</PolicyWorkspace>; }
