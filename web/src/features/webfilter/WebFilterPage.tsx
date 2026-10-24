import { Construction } from "lucide-react";
import { ErrorNotice, PageHeader } from "@/components/PageHeader";
import { Card, CardHeader } from "@/components/ui/Card";
import { PLANNED } from "@/features/placeholder/PlannedPage";
import { formatDateTime, formatNumber } from "@/lib/format";
import { useCategories } from "@/lib/queries";
import type { Category } from "@/lib/schemas";

function byGroup(categories: Category[]): [string, Category[]][] {
  const groups = new Map<string, Category[]>();
  for (const category of categories) groups.set(category.group, [...(groups.get(category.group) ?? []), category]);
  return [...groups.entries()];
}

export function WebFilterPage() {
  const categories = useCategories();
  const published = categories.data?.categories ?? [];
  return (
    <div className="space-y-6">
      <PageHeader title="Filtro web" description={PLANNED.web.summary} />
      {categories.isError ? <ErrorNotice message="Não foi possível carregar as categorias." onRetry={() => void categories.refetch()} /> : null}
      <Card>
        <CardHeader
          title="Categorias de sites"
          description={categories.data?.version ? `Listas publicadas em ${formatDateTime(categories.data.version)}` : "Listas abertas, atualizadas uma vez por dia"}
        />
        <div className="space-y-5 px-5 pt-4 pb-5">
          {categories.isSuccess && published.length === 0 ? (
            <p className="py-4 text-center text-sm text-ink-muted">Nenhuma categoria publicada no servidor.</p>
          ) : null}
          {byGroup(published).map(([group, items]) => (
            <section key={group}>
              <h3 className="text-xs font-medium tracking-wide text-ink-muted uppercase">{group}</h3>
              <ul className="mt-2 grid gap-2 sm:grid-cols-2 xl:grid-cols-3">
                {items.map((category) => (
                  <li key={category.id} aria-label={category.label}
                    className="flex items-center justify-between gap-3 rounded-lg bg-canvas px-3 py-2 text-sm">
                    <span className="text-ink">{category.label}</span>
                    <span className="text-xs text-ink-muted">{formatNumber(category.count)} domínios</span>
                  </li>
                ))}
              </ul>
            </section>
          ))}
          {categories.data?.attribution ? <p className="text-xs text-ink-muted">{categories.data.attribution}</p> : null}
        </div>
      </Card>
      <Card className="flex items-center gap-3 p-6">
        <span className="grid size-10 place-items-center rounded-xl bg-rsm-blue-soft text-rsm-blue-dark">
          <Construction aria-hidden="true" className="size-5" />
        </span>
        <p className="text-sm text-ink-soft">A escolha de categorias, regras e horários por política chega com o editor de políticas (F7).</p>
      </Card>
    </div>
  );
}
