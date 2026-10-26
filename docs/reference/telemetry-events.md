# Eventos e telemetria

Fontes: `app/events.py`, `app/schemas.py`, `app/api.py`, `agent-rs/src/events.rs`.

## Bloqueios web

`POST /fct/api/public/v1/events/` envia `client_id`, `events[]` (até 5.000) e `dropped`. Cada linha inclui `hour`, `domain`, `reason` (valores `rule`, `category` ou `doh`), `category` opcional, `count` (1–100.000). O agente deduplica tentativas DNS repetidas e agrega eventos por hora: **não** é contagem de visitas ou URLs completas.

## Antiadulteração

`POST /fct/api/public/v1/tamper/` envia no máximo 200 linhas com `at`, `kind` e `detail` (até 200 caracteres). Tipos definidos: `dns_rule_restored`, `wfp_restored`, `browser_policy_restored`, `hosts_restored`, `service_config_restored`, `watchdog_restored`, `service_started_by_watchdog`, `unexpected_exit`, `uninstall_code_rejected`, `uninstall_without_secret`. A API valida timestamp e limites antes de persistir.

## Leitura

| Rota | Resultado |
| --- | --- |
| `GET /api/v1/events?limit=50` | Web/tamper ordenados, limite 1–500 |
| `GET /api/v1/stats/overview` | Bloqueios por dia, top domínios e período anterior para `blocks` |
| `GET /api/v1/categories` | Manifesto, categoria e atribuição |
| `GET /api/v1/audit?limit=100` | Trilha de alterações administrativas |

Os campos de `apps` e `usb` do overview permanecem zero até existir telemetria real. Leituras da visão de eventos/overview são auditadas uma vez por administrador/rota/hora **em memória do processo**; não é bloqueio de leitura centralizado entre todas as instâncias.

## Retenção

`OPENEMS_EVENT_RETENTION_DAYS`: padrão 30, permitido 1–365. Expurgo do store de eventos não elimina automaticamente capturas de laboratório, backups, exports e logs externos. Combinação domínio/endpoint pode constituir dado pessoal.

Ver [LGPD](../security/privacy-lgpd.md) e [monitoramento](../operations/monitoring.md).
