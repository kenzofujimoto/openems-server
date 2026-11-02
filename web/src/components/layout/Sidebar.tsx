import { Link } from "@tanstack/react-router";
import * as Dialog from "@radix-ui/react-dialog";
import { useState, type ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import { Activity, AppWindow, Globe, LayoutDashboard, MapPin, Menu, Monitor, ScrollText, Settings, Usb, Users, X } from "lucide-react";
import { BrandLogo } from "@/components/brand/BrandMark";
import { Button } from "@/components/ui/Button";
import { summarize } from "@/lib/status";
import { useEndpoints } from "@/lib/queries";

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
}

const SECTIONS: Array<{ title: string; items: NavItem[] }> = [
  {
    title: "Monitoramento",
    items: [
      { to: "/", label: "Visão geral", icon: LayoutDashboard },
      { to: "/endpoints", label: "Endpoints", icon: Monitor },
      { to: "/events", label: "Eventos", icon: Activity },
    ],
  },
  {
    title: "Perfis de segurança",
    items: [
      { to: "/policies/web", label: "Filtro web", icon: Globe },
      { to: "/policies/apps", label: "Controle de aplicativos", icon: AppWindow },
      { to: "/policies/usb", label: "Dispositivos USB", icon: Usb },
      { to: "/policies/locations", label: "Locais de rede", icon: MapPin },
    ],
  },
  {
    title: "Administração",
    items: [
      { to: "/groups", label: "Grupos e regras", icon: Users },
      { to: "/audit", label: "Auditoria", icon: ScrollText },
      { to: "/settings", label: "Configurações", icon: Settings },
    ],
  },
];

function CoverageCard() {
  const { data } = useEndpoints();
  if (!data || data.length === 0) return null;
  const summary = summarize(data);
  const percent = Math.round((summary.applied / summary.total) * 100);
  return (
    <div className="rounded-lg border border-night-700 bg-night-800 p-3 text-xs text-night-300">
      <div className="flex items-center justify-between">
        <span className="font-medium text-white">Cobertura da política</span>
        <span className="font-semibold text-white">{percent}%</span>
      </div>
      <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-night-700" aria-hidden="true">
        <div className="h-full rounded-full bg-signal" style={{ width: `${percent}%` }} />
      </div>
      <p className="mt-2">{summary.applied} de {summary.total} confirmaram a política</p>
    </div>
  );
}

export function Sidebar() {
  return (
    <aside className="sticky top-14 hidden h-[calc(100vh-3.5rem)] w-60 shrink-0 flex-col bg-night text-night-300 lg:flex">
      <nav aria-label="Principal" className="flex-1 overflow-y-auto px-2.5 pt-3">
        {SECTIONS.map((section) => (
          <div key={section.title} className="mb-4">
            <p className="px-2.5 pb-1.5 text-[10.5px] font-semibold tracking-[0.08em] text-night-400 uppercase">{section.title}</p>
            <ul className="space-y-0.5">
              {section.items.map((item) => (
                <li key={item.to}>
                  <Link
                    to={item.to}
                    activeOptions={{ exact: item.to === "/" }}
                    className="flex h-8 items-center gap-2.5 rounded-md px-2.5 text-[13px] text-night-300 hover:bg-night-800 hover:text-white data-[status=active]:bg-night-700 data-[status=active]:text-white data-[status=active]:shadow-[inset_3px_0_0_var(--color-signal)]"
                  >
                    <item.icon aria-hidden="true" className="size-4" />
                    {item.label}
                  </Link>
                </li>
              ))}
            </ul>
          </div>
        ))}
      </nav>
      <div className="p-2.5">
        <CoverageCard />
      </div>
    </aside>
  );
}

export function TopBar({ children }: { children: ReactNode }) {
  return (
    <header className="sticky top-0 z-30 flex h-14 items-center gap-4 border-b border-night-700 bg-night px-4 text-white">
      <MobileNavigation />
      <BrandLogo inverted className="lg:w-56" />
      <div className="ml-auto flex items-center gap-2">{children}</div>
    </header>
  );
}

export function MobileNavigation() {
  const [open, setOpen] = useState(false);
  return <Dialog.Root open={open} onOpenChange={setOpen}><Dialog.Trigger asChild><Button size="sm" variant="ghost" className="text-night-300 hover:bg-night-800 hover:text-white lg:hidden" aria-label="Abrir navegação"><Menu aria-hidden="true" className="size-5" /></Button></Dialog.Trigger><Dialog.Portal><Dialog.Overlay className="fixed inset-0 z-40 bg-night/40" /><Dialog.Content className="fixed inset-y-0 left-0 z-50 w-72 overflow-y-auto border-r border-line bg-surface p-5 shadow-xl"><div className="mb-5 flex items-center justify-between"><Dialog.Title className="font-medium">Navegação</Dialog.Title><Dialog.Close asChild><Button size="sm" variant="ghost" aria-label="Fechar navegação"><X aria-hidden="true" className="size-5" /></Button></Dialog.Close></div><Dialog.Description className="sr-only">Selecione uma seção do painel.</Dialog.Description><nav aria-label="Navegação móvel">{SECTIONS.map((section) => <div key={section.title} className="mb-5"><p className="mb-2 text-xs text-ink-muted">{section.title}</p><ul className="space-y-1">{section.items.map((item) => <li key={item.to}><Link to={item.to} onClick={() => setOpen(false)} className="flex items-center gap-3 rounded-lg px-2 py-2 text-sm hover:bg-canvas"><item.icon aria-hidden="true" className="size-4" />{item.label}</Link></li>)}</ul></div>)}</nav></Dialog.Content></Dialog.Portal></Dialog.Root>;
}
