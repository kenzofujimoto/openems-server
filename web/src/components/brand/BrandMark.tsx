import { cn } from "@/lib/cn";
import { BRAND } from "@/lib/brand";

/** OpenEMS mark: a protected perimeter (hexagon) with three endpoints; the cyan node is the agent confirming policy. */
export function BrandMark({ className }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" fill="none" aria-hidden="true" className={cn("size-7 shrink-0", className)}>
      <path d="M16 2.5 27.5 9v14L16 29.5 4.5 23V9L16 2.5Z" fill="#4f46e5" />
      <path d="M16 2.5 27.5 9v14L16 29.5V2.5Z" fill="#3730a3" />
      <path d="M16 11 10.5 20h11L16 11Z" stroke="#fff" strokeWidth="1.4" strokeLinejoin="round" opacity=".85" />
      <circle cx="16" cy="11" r="2.6" fill="#fff" />
      <circle cx="10.5" cy="20" r="2.6" fill="#fff" />
      <circle cx="21.5" cy="20" r="2.6" fill="#22d3ee" />
    </svg>
  );
}

export function BrandLogo({ className, inverted = false }: { className?: string; inverted?: boolean }) {
  if (BRAND.id === "rsm") {
    return (
      <span className={cn("inline-flex items-center gap-3", className)}>
        <span className={cn("inline-flex rounded-md", inverted && "bg-white px-2 py-1")}>
          <img src={`${import.meta.env.BASE_URL}brand/rsm-logo.png`} alt="RSM" className="h-7 w-auto" />
        </span>
        <span className={cn("border-l pl-3 text-xs leading-tight", inverted ? "border-night-600 text-night-300" : "border-line text-ink-muted")}>Endpoint<br />Management</span>
      </span>
    );
  }
  return (
    <span className={cn("inline-flex items-center gap-2.5", className)} aria-label="OpenEMS">
      <BrandMark />
      <span aria-hidden="true" className={cn("text-[17px] font-semibold tracking-tight", inverted ? "text-white" : "text-ink")}>
        Open<span className={inverted ? "font-medium text-signal" : "font-medium text-brand"}>EMS</span>
      </span>
    </span>
  );
}
