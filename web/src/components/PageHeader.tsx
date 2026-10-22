import type { ReactNode } from "react";

export function PageHeader({ title, description, actions }: { title: string; description?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="flex flex-wrap items-end justify-between gap-4">
      <div>
        <h1 className="text-2xl font-medium tracking-tight text-ink">{title}</h1>
        {description ? <div className="mt-1 text-sm text-ink-muted">{description}</div> : null}
      </div>
      {actions}
    </div>
  );
}

export function InfoNotice({ children }: { children: ReactNode }) {
  return <div className="rounded-xl bg-rsm-blue-soft px-4 py-3 text-sm text-rsm-blue-dark">{children}</div>;
}

export function ErrorNotice({ message, onRetry }: { message: string; onRetry: () => void }) {
  return (
    <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl bg-danger-soft px-4 py-3 text-sm text-danger">
      <span>{message}</span>
      <button type="button" onClick={onRetry} className="font-medium underline underline-offset-2">Tentar de novo</button>
    </div>
  );
}
