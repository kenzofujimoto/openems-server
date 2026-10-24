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
import { Sidebar } from "@/components/layout/Sidebar";
import { UserMenu } from "@/components/layout/UserMenu";
import { ErrorNotice } from "@/components/PageHeader";
import { LoginPage } from "@/features/auth/LoginPage";
import { DashboardPage } from "@/features/dashboard/DashboardPage";
import { EndpointsPage } from "@/features/endpoints/EndpointsPage";
import { PLANNED, PlannedPage, type PlannedModule } from "@/features/placeholder/PlannedPage";
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
        <header className="flex h-16 items-center justify-end border-b border-line bg-surface px-6">
          <UserMenu session={session.data} />
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
  const planned = (path: string, module: PlannedModule) =>
    createRoute({ getParentRoute: () => root, path, component: () => <PlannedPage module={module} /> });
  const tree = root.addChildren([
    createRoute({ getParentRoute: () => root, path: "/", component: DashboardPage }),
    createRoute({ getParentRoute: () => root, path: "/endpoints", component: EndpointsPage }),
    planned("/events", PLANNED.events),
    createRoute({ getParentRoute: () => root, path: "/policies/web", component: WebFilterPage }),
    planned("/policies/apps", PLANNED.apps),
    planned("/policies/usb", PLANNED.usb),
    planned("/policies/locations", PLANNED.locations),
    planned("/groups", PLANNED.groups),
    planned("/audit", PLANNED.audit),
    planned("/settings", PLANNED.settings),
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
