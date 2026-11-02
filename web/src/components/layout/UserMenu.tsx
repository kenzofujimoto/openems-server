import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { ChevronDown, LogOut } from "lucide-react";
import type { Session } from "@/lib/schemas";
import { useLogout } from "@/lib/queries";

const ROLE_LABEL: Record<Session["role"], string> = {
  viewer: "Leitor",
  admin: "Administrador",
  superadmin: "Superadministrador",
};

export function UserMenu({ session }: { session: Session }) {
  const logout = useLogout();
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger className="flex items-center gap-2.5 rounded-lg py-1 pr-2 pl-1 text-left text-white hover:bg-night-800">
        <span aria-hidden="true" className="grid size-7 place-items-center rounded-md bg-brand text-xs font-semibold text-white uppercase">
          {session.username.slice(0, 2)}
        </span>
        <span className="hidden text-sm leading-tight sm:block">
          <span className="block font-medium text-white">{session.username}</span>
          <span className="block text-xs text-night-300">{ROLE_LABEL[session.role]}</span>
        </span>
        <ChevronDown aria-hidden="true" className="size-4 text-night-300" />
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content align="end" sideOffset={6} className="min-w-44 rounded-xl border border-line bg-surface p-1 shadow-lg">
          <DropdownMenu.Item
            onSelect={() => logout.mutate()}
            className="flex cursor-pointer items-center gap-2 rounded-lg px-2.5 py-2 text-sm text-ink outline-none data-[highlighted]:bg-canvas"
          >
            <LogOut aria-hidden="true" className="size-4" />
            Sair
          </DropdownMenu.Item>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}
