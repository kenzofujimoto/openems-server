import { Link } from "@tanstack/react-router";
import type { LucideIcon } from "lucide-react";
import { Activity, AppWindow, Globe, LayoutDashboard, MapPin, Monitor, ScrollText, Settings, Usb, Users } from "lucide-react";
import { summarize } from "@/lib/status";
import { useEndpoints } from "@/lib/queries";

interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
}

const SECTIONS: Array<{ title: string; items: NavItem[] }> = [
  {
    title: "Geral",
    items: [
      { to: "/", label: "Visão geral", icon: LayoutDashboard },
      { to: "/endpoints", label: "Endpoints", icon: Monitor },
      { to: "/events", label: "Eventos", icon: Activity },
    ],
  },
  {
    title: "Políticas",
    items: [
      { to: "/policies/web", label: "Filtro web", icon: Globe },
      { to: "/policies/apps", label: "Aplicativos", icon: AppWindow },
      { to: "/policies/usb", label: "USB", icon: Usb },
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
    <div className="rounded-xl border border-line bg-surface p-3.5">
      <div className="flex items-center justify-between text-xs">
        <span className="font-medium text-ink-soft">Cobertura de política</span>
        <span className="text-ink-muted">{percent}%</span>
      </div>
      <div className="mt-2 h-1.5 overflow-hidden rounded-full bg-canvas" aria-hidden="true">
        <div className="h-full rounded-full bg-rsm-green" style={{ width: `${percent}%` }} />
      </div>
      <p className="mt-2 text-xs text-ink-muted">{summary.applied} de {summary.total} confirmaram a política</p>
    </div>
  );
}

export function Sidebar() {
  return (
    <aside className="sticky top-0 hidden h-screen w-64 shrink-0 flex-col border-r border-line bg-surface lg:flex">
      <div className="flex items-center gap-3 px-5 py-5">
        <img src={`${import.meta.env.BASE_URL}brand/rsm-logo.png`} alt="RSM" className="h-8 w-auto" />
        <span className="border-l border-line pl-3 text-xs leading-tight text-ink-muted">Endpoint<br />Management</span>
      </div>
      <nav aria-label="Principal" className="flex-1 overflow-y-auto px-3">
        {SECTIONS.map((section) => (
          <div key={section.title} className="mb-5">
            <p className="px-2 pb-1.5 text-[11px] font-medium tracking-wide text-ink-muted uppercase">{section.title}</p>
            <ul className="space-y-0.5">
              {section.items.map((item) => (
                <li key={item.to}>
                  <Link
                    to={item.to}
                    activeOptions={{ exact: item.to === "/" }}
                    className="flex items-center gap-2.5 rounded-lg px-2 py-2 text-sm text-ink-soft hover:bg-canvas hover:text-ink data-[status=active]:bg-rsm-blue-soft data-[status=active]:font-medium data-[status=active]:text-rsm-blue-dark"
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
      <div className="p-3">
        <CoverageCard />
      </div>
    </aside>
  );
}
