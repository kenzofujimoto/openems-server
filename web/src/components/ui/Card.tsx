import type { HTMLAttributes, ReactNode } from "react";
import { cn } from "@/lib/cn";

export function Card({ className, ...props }: HTMLAttributes<HTMLElement>) {
  return <section className={cn("rounded-[var(--radius-card)] border border-line bg-surface", className)} {...props} />;
}

export function CardHeader({ title, description, action }: { title: string; description?: ReactNode; action?: ReactNode }) {
  return (
    <header className="flex items-start justify-between gap-4 px-5 pt-5">
      <div className="min-w-0">
        <h2 className="text-[15px] font-medium text-ink">{title}</h2>
        {description ? <p className="mt-0.5 text-[13px] text-ink-muted">{description}</p> : null}
      </div>
      {action}
    </header>
  );
}
