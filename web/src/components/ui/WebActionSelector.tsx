import { useId } from "react";
import { CircleCheck, Eye, ShieldBan } from "lucide-react";
import { cn } from "@/lib/cn";

export type WebAction = "allow" | "block" | "monitor";
export type CategoryActions = Record<string, WebAction>;

const ACTIONS = [
  { value: "allow", label: "Permitir", icon: CircleCheck, tone: "peer-checked:border-rsm-green peer-checked:bg-rsm-green-soft peer-checked:text-rsm-green" },
  { value: "block", label: "Bloquear", icon: ShieldBan, tone: "peer-checked:border-danger peer-checked:bg-danger-soft peer-checked:text-danger" },
  { value: "monitor", label: "Monitorar", icon: Eye, tone: "peer-checked:border-rsm-blue peer-checked:bg-rsm-blue-soft peer-checked:text-rsm-blue-dark" },
] as const;

export function WebActionSelector({ label, value, onChange }: { label: string; value: WebAction; onChange: (value: WebAction) => void }) {
  const name = useId();
  return <div role="radiogroup" aria-label={`Ação para ${label}`} className="flex flex-wrap gap-1.5">
    {ACTIONS.map(({ value: action, label: actionLabel, icon: Icon, tone }) => <label key={action} className="cursor-pointer">
      <input type="radio" name={name} value={action} aria-label={`${actionLabel} ${label}`} checked={value === action} onChange={() => onChange(action)} className="peer sr-only" />
      <span className={cn("flex items-center gap-1.5 rounded-lg border border-line px-2.5 py-2 text-xs text-ink-soft peer-checked:font-medium peer-focus-visible:outline-2 peer-focus-visible:outline-offset-2 peer-focus-visible:outline-rsm-blue peer-disabled:cursor-not-allowed peer-disabled:opacity-60", tone)}><Icon className="size-4" aria-hidden="true" />{actionLabel}</span>
    </label>)}
  </div>;
}
