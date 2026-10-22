export type DeltaTone = "up" | "down" | "flat";

export interface Delta {
  text: string;
  tone: DeltaTone;
}

export function formatDelta(current: number, previous: number): Delta {
  if (previous === 0) return current === 0 ? { text: "0%", tone: "flat" } : { text: "novo", tone: "up" };
  const percent = Math.round(((current - previous) / previous) * 100);
  if (percent === 0) return { text: "0%", tone: "flat" };
  return percent > 0 ? { text: `+${percent}%`, tone: "up" } : { text: `${percent}%`, tone: "down" };
}

const numberFormat = new Intl.NumberFormat("pt-BR");

export function formatNumber(value: number): string {
  return numberFormat.format(value);
}

export function relativeTime(iso: string | null, now: number = Date.now()): string {
  if (!iso) return "—";
  const time = Date.parse(iso);
  if (Number.isNaN(time)) return "—";
  const seconds = Math.max(0, Math.round((now - time) / 1000));
  if (seconds < 60) return "agora";
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `há ${minutes} min`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `há ${hours} h`;
  return `há ${Math.round(hours / 24)} d`;
}

export function formatDateTime(iso: string | null): string {
  if (!iso) return "—";
  const time = Date.parse(iso);
  if (Number.isNaN(time)) return "—";
  return new Intl.DateTimeFormat("pt-BR", { dateStyle: "short", timeStyle: "short" }).format(time);
}
