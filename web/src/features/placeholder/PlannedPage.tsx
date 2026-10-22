import { Construction } from "lucide-react";
import { PageHeader } from "@/components/PageHeader";
import { Card } from "@/components/ui/Card";

export interface PlannedModule {
  title: string;
  phase: string;
  summary: string;
  items: string[];
}

export function PlannedPage({ module }: { module: PlannedModule }) {
  return (
    <div className="space-y-6">
      <PageHeader title={module.title} description={module.summary} />
      <Card className="p-6">
        <div className="flex items-center gap-3">
          <span className="grid size-10 place-items-center rounded-xl bg-rsm-blue-soft text-rsm-blue-dark">
            <Construction aria-hidden="true" className="size-5" />
          </span>
          <div>
            <p className="font-medium text-ink">Em desenvolvimento</p>
            <p className="text-sm text-ink-muted">Entrega {module.phase} do roadmap v2</p>
          </div>
        </div>
        <ul className="mt-5 grid gap-2 sm:grid-cols-2">
          {module.items.map((item) => (
            <li key={item} className="rounded-lg bg-canvas px-3 py-2 text-sm text-ink-soft">{item}</li>
          ))}
        </ul>
      </Card>
    </div>
  );
}

export const PLANNED = {
  web: {
    title: "Filtro web",
    phase: "F2",
    summary: "Bloqueio por domínio, curinga, categoria e horário, com página de bloqueio em HTTP e HTTPS.",
    items: ["Listas de bloqueio e de permitidos", "Curingas (*.exemplo.com)", "Categorias de sites", "Horários por regra", "SafeSearch forçado", "Antiburla de DNS over HTTPS"],
  },
  apps: {
    title: "Controle de aplicativos",
    phase: "F3",
    summary: "Bloqueio antes da execução por hash, editor ou caminho, e bloqueio de rede por aplicativo.",
    items: ["Inventário de aplicativos", "Regras por hash e editor", "Bloqueio de rede por app", "Encerramento como último recurso"],
  },
  usb: {
    title: "Controle de USB",
    phase: "F4",
    summary: "Inventário de dispositivos e regras por classe, fabricante (VID/PID) e número de série.",
    items: ["Inventário estilo USBDeview", "Permitir, bloquear ou somente leitura", "Regras por VID, PID e serial", "Eventos de dispositivo bloqueado"],
  },
  locations: {
    title: "Locais de rede",
    phase: "F6",
    summary: "Política diferente dentro e fora da empresa, com detecção por mais de um sinal de rede.",
    items: ["Faixas de IP local", "IP público do escritório", "Gateway e sufixo DNS", "Perfil interno e externo por grupo"],
  },
  events: {
    title: "Eventos",
    phase: "F2–F5",
    summary: "Histórico de bloqueios, erros de política e tentativas de adulteração.",
    items: ["Filtros por tipo e endpoint", "Exportação para SIEM", "Retenção configurável", "Detalhe por ocorrência"],
  },
  groups: {
    title: "Grupos e regras",
    phase: "F7",
    summary: "Grupos de política e regras de atribuição com múltiplas condições.",
    items: ["Editor de regras", "Prioridade e ativação", "Prévia dos endpoints afetados", "Publicação de perfis"],
  },
  audit: {
    title: "Auditoria",
    phase: "F7",
    summary: "Registro de todas as ações administrativas.",
    items: ["Filtros por usuário e ação", "Detalhe dos metadados", "Exportação"],
  },
  settings: {
    title: "Configurações",
    phase: "F1, F5, F7",
    summary: "Convites de cadastro, instaladores do agente e administradores.",
    items: ["Convites de cadastro", "Download do instalador", "Administradores e papéis", "Códigos de desinstalação"],
  },
} satisfies Record<string, PlannedModule>;
