import type { LucideIcon } from "lucide-react";
import { ArrowDownRight, ArrowUpRight } from "lucide-react";
import { useId } from "react";
import { cn } from "@/lib/cn";
import type { Delta } from "@/lib/format";

interface KpiCardProps {
  label: string;
  value: string;
  icon: LucideIcon;
  delta?: Delta;
  caption?: string;
  /** For metrics where growth is bad (errors, blocks of risky traffic). */
  invertTone?: boolean;
}

export function KpiCard({ label, value, icon: Icon, delta, caption, invertTone = false }: KpiCardProps) {
  const labelId = useId();
  const good = delta ? (delta.tone === "flat" ? null : (delta.tone === "up") !== invertTone) : null;
  return (
    <section role="group" aria-labelledby={labelId} className="rounded-[var(--radius-card)] border border-line bg-surface p-5">
      <div className="flex items-center gap-2.5">
        <span className="grid size-8 place-items-center rounded-lg bg-rsm-blue-soft text-rsm-blue-dark">
          <Icon aria-hidden="true" className="size-4" />
        </span>
        <h3 id={labelId} className="text-sm font-medium text-ink-soft">{label}</h3>
      </div>
      <p className="mt-4 text-[28px] leading-none font-medium tracking-tight text-ink">{value}</p>
      <div className="mt-3 flex min-h-5 items-center gap-2 text-xs whitespace-nowrap text-ink-muted">
          {delta ? (
            <span
              data-tone={delta.tone}
              data-good={good === null ? "neutral" : String(good)}
              className={cn(
                "inline-flex items-center gap-0.5 rounded-md px-1.5 py-0.5 font-medium",
                good === null && "bg-canvas text-ink-soft",
                good === true && "bg-rsm-green-soft text-rsm-green",
                good === false && "bg-danger-soft text-danger",
              )}
            >
              {delta.tone === "up" ? <ArrowUpRight aria-hidden="true" className="size-3" /> : null}
              {delta.tone === "down" ? <ArrowDownRight aria-hidden="true" className="size-3" /> : null}
              {delta.text}
            </span>
          ) : null}
          {delta && caption ? <span>{caption}</span> : null}
      </div>
    </section>
  );
}
