# Configuração

Fontes: `docker-compose.yml`, `app/api.py:build`, `agent-rs/src/config.rs`, `agent-rs/installer/openems-agent.wxs`.

## Servidor

| Variável | Finalidade | Observação |
| --- | --- | --- |
| `POSTGRES_PASSWORD` | Banco do Compose | Obrigatória |
| `OPENEMS_DATABASE_URL` | DSN PostgreSQL | Obrigatória no Compose |
| `OPENEMS_REDIS_URL` | Fila/replay | Compose define endpoint interno |
| `OPENEMS_ADMIN` | Bootstrap `usuário:senha` | Obrigatória no Compose; não há default |
| `OPENEMS_SESSION_SECRET` | Assinatura das sessões | Ao menos 32 caracteres com PostgreSQL |
| `OPENEMS_ENROLLMENT_TOKEN` | Convite inicial | Ao menos 32 caracteres |
| `OPENEMS_ENROLLMENT_VDOM` | Grupo inicial | `Default` |
| `OPENEMS_ENROLLMENT_USES` | Usos do convite inicial | Padrão Compose 1 |
| `OPENEMS_BASE_URL` | Origem pública da API/SAML | HTTPS fora de loopback |
| `OPENEMS_CATEGORIES_DIR` | Manifesto e dados de categorias | Volume no Compose |
| `OPENEMS_UT1_URL` | Fonte de listas | Sem valor padrão; licença a confirmar |
| `OPENEMS_EVENT_RETENTION_DAYS` | Retenção de eventos | 30 dias; limite 1–365 |
| `OPENEMS_UNINSTALL_MASTER_KEY` | Segredo mestre de remoção | Opcional; ao menos 32 bytes, persistente |
| `OPENEMS_LAB_MODE` | Facilidades apenas em loopback | Não habilitar em produção |
| `OPENEMS_RECORD` | Captura JSONL de laboratório | Desativado normalmente; dados sensíveis |

`deploy/new-env.ps1` gera valores aleatórios. `-Force` preserva chave-mestra de remoção, mas troca outras credenciais: não executar sem plano.

## Agente Rust (`agent.json`)

~~~json
{
  "server": "https://ems.exemplo.net",
  "devid": "VM-LAB-01",
  "vdom": "Default",
  "interval": 15,
  "block_page": false,
  "block_page_https": false,
  "dns_filter": false,
  "anti_bypass": false
}
~~~

Além dos obrigatórios `server` e `devid`: `invitation`, `device_token`, `state_path`, `hosts_path`, `authority_path`, `block_page_port` (80), `block_page_https_port` (443), `dns_port` (53), `dry_run` e `allow_insecure_http`. Arquivo valida tipos e rejeita campos desconhecidos. O segredo `device_token` não deve ser impresso.

## MSI

Propriedades documentadas em `openems-agent.wxs`: `SERVER`, `INVITATION`, `VDOM`, `DEVID`, `HOSTSFILE`, `BLOCKPAGE`, `BLOCKPAGEHTTPS`, `DNSFILTER`, `ANTIBYPASS` e `UNINSTALLCODE`. `INVITATION` e `UNINSTALLCODE` possuem metadados Hidden no instalador, mas isso não impede vazamento por inventário de comandos/processos.

Referências: [CLI](agent-cli.md), [MSI](../deployment/windows-agent.md) e [identidade](../security/identity-and-trust.md).
