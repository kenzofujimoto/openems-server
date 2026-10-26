import { Moon, Sun } from "lucide-react";
import { useEffect, useState } from "react";
import { Button } from "@/components/ui/Button";

export function ThemeToggle() {
  const [{ theme, storageError }, setPreference] = useState<{ theme: "light" | "dark"; storageError: boolean }>(() => {
    try { return { theme: localStorage.getItem("openems-theme") === "dark" ? "dark" : "light", storageError: false }; }
    catch { return { theme: "light", storageError: true }; }
  });
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
  }, [theme]);
  return <div className="flex items-center gap-2"><Button size="sm" variant="ghost" aria-label={theme === "light" ? "Ativar modo escuro" : "Ativar modo claro"} onClick={() => { const next = theme === "light" ? "dark" : "light"; try { localStorage.setItem("openems-theme", next); setPreference({ theme: next, storageError: false }); } catch { setPreference({ theme: next, storageError: true }); } }}>{theme === "light" ? <Moon aria-hidden="true" className="size-4" /> : <Sun aria-hidden="true" className="size-4" />}</Button>{storageError ? <span className="text-xs text-ink-muted">Preferência válida nesta sessão.</span> : null}</div>;
}
