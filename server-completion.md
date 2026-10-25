# Backend das fases F3, F4 e F7

Autorizado junto ao restante do roadmap; implementação sem alterar o servidor instalado.

1. Acrescentar validação de `usb_control.default_action/rules`, `app_control.execution_rules/network_blocked` e vetores compartilhados; testes inválidos devem falhar antes do código.
2. Receber inventário autenticado por dispositivo e eventos de controle; persistir em memória/PostgreSQL, integrar eventos/estatísticas e expirar dados pelo prazo configurado (migração 006).
3. Acrescentar publicação condicional de perfis (`If-Match`) para evitar sobrescrever edição concorrente; clientes antigos continuam compatíveis.
4. Expor administradores e convites: criação sem sobrescrita silenciosa, proteção do superadministrador/último escritor, convites listados só por hash e revogáveis.
5. Expor configurações somente leitura e instalador confiável fornecido pelo operador, autenticado, sem registrar convite ou senha.
6. Rodar contratos focados, verificar PostgreSQL em banco descartável e coordenar a suíte completa com o agente principal.

Riscos e limites: inventário e eventos podem conter dados pessoais; os dados ficam limitados em tamanho, com retenção e acesso auditado. Nenhum campo recebido entra em shell/SQL. O pacote do instalador precisa existir no servidor por configuração explícita; sem artefato retorna indisponível. Novos controles continuam dependentes das capacidades efetivamente anunciadas pelo agente.
