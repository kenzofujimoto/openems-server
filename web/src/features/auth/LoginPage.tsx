import { useState, type FormEvent } from "react";
import { Button } from "@/components/ui/Button";
import { ApiError } from "@/lib/api";
import { useLogin } from "@/lib/queries";

function loginMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 401) return "Usuário ou senha inválidos.";
    if (error.status === 429) return "Muitas tentativas. Aguarde alguns minutos.";
  }
  return "Não foi possível entrar. Tente de novo.";
}

export function LoginPage() {
  const login = useLogin();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");

  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    login.mutate({ username, password });
  }

  return (
    <main className="grid min-h-screen place-items-center bg-canvas px-4">
      <div className="w-full max-w-sm">
        <div className="mb-8 flex flex-col items-center gap-3">
          <img src={`${import.meta.env.BASE_URL}brand/rsm-logo.png`} alt="RSM" className="h-12 w-auto" />
          <p className="text-sm text-ink-muted">Endpoint Management</p>
        </div>
        <form onSubmit={submit} className="rounded-[var(--radius-card)] border border-line bg-surface p-6" noValidate>
          <h1 className="text-xl font-medium text-ink">Entrar</h1>
          <p className="mt-1 text-sm text-ink-muted">Use sua conta de administrador.</p>
          <label className="mt-6 block text-sm font-medium text-ink-soft" htmlFor="username">Usuário</label>
          <input
            id="username"
            autoComplete="username"
            required
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            className="mt-1.5 h-10 w-full rounded-lg border border-line px-3 text-sm outline-none focus:border-rsm-blue"
          />
          <label className="mt-4 block text-sm font-medium text-ink-soft" htmlFor="password">Senha</label>
          <input
            id="password"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            className="mt-1.5 h-10 w-full rounded-lg border border-line px-3 text-sm outline-none focus:border-rsm-blue"
          />
          {login.isError ? (
            <p role="alert" className="mt-4 rounded-lg bg-danger-soft px-3 py-2 text-sm text-danger">{loginMessage(login.error)}</p>
          ) : null}
          <Button type="submit" variant="primary" className="mt-6 w-full" disabled={login.isPending}>
            Entrar
          </Button>
        </form>
      </div>
    </main>
  );
}
