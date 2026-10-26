# Administração e privilégios

As interfaces são `/panel/` (React; parcial), `/console/` (legada, ainda necessária para parte dos fluxos) e `/api/v1/*`. A autenticação é feita por sessão revogável, com cookie e proteção CSRF para mutações.

| Papel | Leitura | Escrita | Importação de IdP |
| --- | --- | --- | --- |
| `viewer` | Sim | Não | Não |
| `admin` | Sim | Sim | Sim |
| `superadmin` | Sim | Sim | Sim |

**Importante:** no código atual, `admin` e `superadmin` possuem a mesma matriz de privilégios em `app/auth.py`. Não presumir permissões especiais adicionais.

## Rotina de administração

1. Criar contas e controlar privilégios com acesso mínimo.
2. Criar convites com limite de uso, TTL e grupo definido.
3. Registrar dispositivos, conferir `effective_vdom` e capacidades.
4. Publicar perfis com `POST /api/v1/profiles/{vdom}`.
5. Criar regras habilitadas com prioridades e múltiplas condições AND.
6. Comparar perfil desejado vs. aplicado e investigar `last_error`, sem tomar `online` como sucesso.
7. Revisar auditoria, tentativas de adulteração e relatórios DNS respeitando LGPD.

## Ações sensíveis

Geração de códigos de desinstalação, liberação da frota inteira (`scope="*"`), rotação de credenciais, revogação de dispositivos e alteração de IdP requerem controle de mudança e verificação posterior. A liberação de remoção propagada pelo servidor pode permitir remoção sem código após sincronização.

Consulte [endpoints](endpoint-management.md), [desinstalação](uninstall-management.md), [API](../reference/api.md), [identidade](../security/identity-and-trust.md).
