import { useId, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/cn";

/** `free` panels are passed to `wrap` separately, so they can stay outside a disabled fieldset (read-only tools). */
export interface TabItem { id: string; label: string; icon?: LucideIcon; count?: number; content: ReactNode; free?: boolean }

/**
 * Profile sections. Inactive panels stay mounted (hidden) so unsaved edits survive switching tabs.
 * `wrap` places the panels in a container (a disabled fieldset, for example) while the tab list stays usable.
 */
export function Tabs({ label, items, initial, wrap = (panels, free) => <>{panels}{free}</> }: { label: string; items: TabItem[]; initial?: string; wrap?: (panels: ReactNode, free: ReactNode) => ReactNode }) {
  const base = useId();
  const [active, setActive] = useState(initial ?? items[0]?.id ?? "");
  const refs = useRef<Record<string, HTMLButtonElement | null>>({});
  const move = (event: KeyboardEvent, index: number) => {
    const offset = event.key === "ArrowRight" ? 1 : event.key === "ArrowLeft" ? -1 : 0;
    const target = event.key === "Home" ? items[0] : event.key === "End" ? items.at(-1) : offset ? items[(index + offset + items.length) % items.length] : undefined;
    if (!target) return;
    event.preventDefault();
    setActive(target.id);
    refs.current[target.id]?.focus();
  };
  const panel = (item: TabItem) => (
    <div key={item.id} role="tabpanel" id={`${base}-${item.id}-panel`} aria-labelledby={`${base}-${item.id}-tab`} hidden={item.id !== active} className="min-w-0 space-y-4">
      {item.content}
    </div>
  );
  return (
    <div>
      <div role="tablist" aria-label={label} className="mb-4 flex gap-1 overflow-x-auto border-b border-line">
        {items.map((item, index) => {
          const selected = item.id === active;
          return (
            <button
              key={item.id}
              ref={(node) => { refs.current[item.id] = node; }}
              type="button"
              role="tab"
              id={`${base}-${item.id}-tab`}
              aria-selected={selected}
              aria-controls={`${base}-${item.id}-panel`}
              tabIndex={selected ? 0 : -1}
              onClick={() => setActive(item.id)}
              onKeyDown={(event) => move(event, index)}
              className={cn(
                "-mb-px flex items-center gap-2 border-b-2 px-3.5 py-2.5 text-sm font-medium whitespace-nowrap",
                selected ? "border-brand text-brand-ink" : "border-transparent text-ink-soft hover:text-ink",
              )}
            >
              {item.icon ? <item.icon aria-hidden="true" className="size-4" /> : null}
              {item.label}
              {item.count !== undefined ? (
                <span aria-hidden="true" className={cn("rounded-full px-1.5 text-[11px]", selected ? "bg-brand-soft text-brand-ink" : "bg-idle-soft text-ink-soft")}>{item.count}</span>
              ) : null}
            </button>
          );
        })}
      </div>
      {wrap(items.filter((item) => !item.free).map(panel), items.filter((item) => item.free).map(panel))}
    </div>
  );
}
