import { useId } from "react";
import { Ban, CircleCheck, Eye, TriangleAlert, type LucideIcon } from "lucide-react";
import { cn } from "@/lib/cn";

/** warn shows a warning page where the person may continue for an hour (agent capability web-filter:warn). */
export type WebAction = "allow" | "block" | "monitor" | "warn";
export type CategoryActions = Record<string, WebAction>;

/** Shared meaning and colors of the web actions; the brand color never stands for an action. */
export const WEB_ACTIONS: ReadonlyArray<{ value: WebAction; label: string; icon: LucideIcon; text: string; pill: string; tone: string; swatch: string }> = [
  { value: "allow", label: "Permitir", icon: CircleCheck, text: "text-allow", pill: "bg-allow-soft text-allow", swatch: "bg-allow", tone: "peer-checked:border-allow peer-checked:bg-allow-soft peer-checked:text-allow" },
  { value: "block", label: "Bloquear", icon: Ban, text: "text-block", pill: "bg-block-soft text-block", swatch: "bg-block", tone: "peer-checked:border-block peer-checked:bg-block-soft peer-checked:text-block" },
  { value: "monitor", label: "Monitorar", icon: Eye, text: "text-monitor", pill: "bg-monitor-soft text-monitor", swatch: "bg-monitor", tone: "peer-checked:border-monitor peer-checked:bg-monitor-soft peer-checked:text-monitor" },
  { value: "warn", label: "Avisar", icon: TriangleAlert, text: "text-warning", pill: "bg-warning-soft text-warning", swatch: "bg-warning", tone: "peer-checked:border-warning peer-checked:bg-warning-soft peer-checked:text-warning" },
];

/** Segmented radio group; arrow keys move between the actions of one category. */
export function WebActionSelector({ label, value, onChange, compact = false }: { label: string; value: WebAction; onChange: (value: WebAction) => void; compact?: boolean }) {
  const name = useId();
  return <div role="radiogroup" aria-label={`Ação para ${label}`} className={cn("flex flex-wrap", compact ? "gap-1" : "gap-1.5")}>
    {WEB_ACTIONS.map(({ value: action, label: actionLabel, icon: Icon, tone }) => <label key={action} className="cursor-pointer">
      <input type="radio" name={name} value={action} aria-label={`${actionLabel} ${label}`} checked={value === action} onChange={() => onChange(action)} className="peer sr-only" />
      <span className={cn("flex items-center gap-1.5 rounded-md border border-line text-xs text-ink-soft peer-checked:font-medium peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-brand peer-disabled:cursor-not-allowed peer-disabled:opacity-60", compact ? "px-2 py-1" : "px-2.5 py-2", tone)}><Icon className={compact ? "size-3.5" : "size-4"} aria-hidden="true" />{actionLabel}</span>
    </label>)}
  </div>;
}
