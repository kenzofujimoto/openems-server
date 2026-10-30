import { QueryClientProvider, type QueryClient } from "@tanstack/react-query";
import {
  createRootRoute,
  createRoute,
  createRouter,
  Outlet,
  RouterProvider,
  type RouterHistory,
} from "@tanstack/react-router";
import { useState } from "react";
import { MobileNavigation, Sidebar } from "@/components/layout/Sidebar";
import { ThemeToggle } from "@/components/layout/ThemeToggle";
import { UserMenu } from "@/components/layout/UserMenu";
import { ErrorNotice } from "@/components/PageHeader";
import { LoginPage } from "@/features/auth/LoginPage";
import { DashboardPage } from "@/features/dashboard/DashboardPage";
import { EndpointDetailPage } from "@/features/endpoints/EndpointDetailPage";
import { EndpointsPage } from "@/features/endpoints/EndpointsPage";
import { LocationsPage } from "@/features/locations/LocationsPage";
import { ApplicationsPage, UsbPage } from "@/features/policies/ControlsPages";
import { EventsPage, AuditPage } from "@/features/management/RecordsPages";
import { GroupsPage } from "@/features/management/GroupsPage";
import { SettingsPage } from "@/features/management/SettingsPage";
import { WebFilterPage } from "@/features/webfilter/WebFilterPage";
import { useSession } from "@/lib/queries";

function Shell() {
  const session = useSession();
  if (session.isPending) {
    return <div className="grid min-h-screen place-items-center text-sm text-ink-muted">Carregando…</div>;
  }
  if (session.isError) {
    return (
      <div className="mx-auto mt-24 max-w-md px-4">
        <ErrorNotice message="Não foi possível conectar ao servidor." onRetry={() => void session.refetch()} />
      </div>
    );
  }
  if (session.data === null) return <LoginPage />;
  return (
    <div className="flex min-h-screen">
      <Sidebar />
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-16 items-center justify-between border-b border-line bg-surface px-6">
          <MobileNavigation />
          <div className="ml-auto flex items-center gap-3"><ThemeToggle /><UserMenu session={session.data} /></div>
        </header>
        <main className="mx-auto w-full max-w-[1400px] flex-1 px-6 py-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}

function buildRouter(history?: RouterHistory) {
  const root = createRootRoute({ component: Shell });
  const tree = root.addChildren([
    createRoute({ getParentRoute: () => root, path: "/", component: DashboardPage }),
    createRoute({ getParentRoute: () => root, path: "/endpoints", component: EndpointsPage }),
    createRoute({ getParentRoute: () => root, path: "/endpoints/$devid", component: EndpointDetailPage }),
    createRoute({ getParentRoute: () => root, path: "/events", component: EventsPage }),
    createRoute({ getParentRoute: () => root, path: "/policies/web", component: WebFilterPage }),
    createRoute({ getParentRoute: () => root, path: "/policies/apps", component: ApplicationsPage }),
    createRoute({ getParentRoute: () => root, path: "/policies/usb", component: UsbPage }),
    createRoute({ getParentRoute: () => root, path: "/policies/locations", component: LocationsPage }),
    createRoute({ getParentRoute: () => root, path: "/groups", component: GroupsPage }),
    createRoute({ getParentRoute: () => root, path: "/audit", component: AuditPage }),
    createRoute({ getParentRoute: () => root, path: "/settings", component: SettingsPage }),
  ]);
  // Production is served under /panel/; tests drive a memory history at "/".
  return createRouter({ routeTree: tree, history, basepath: history ? "/" : import.meta.env.BASE_URL });
}

export function App({ queryClient, history }: { queryClient: QueryClient; history?: RouterHistory }) {
  const [router] = useState(() => buildRouter(history));
  return (
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  );
}
