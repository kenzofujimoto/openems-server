# Monitoramento operacional

Fonte: `app/api.py`, `app/events.py`, `agent-rs/src/events.rs` e `app/audit.py`.

## Indicadores observáveis

| Indicador | Fonte | Interpretação |
| --- | --- | --- |
| `online` / `last_seen` | `GET /api/v1/endpoints/index` | Status registrado e contato nos últimos 90 s; não é ping |
| `desired_profile` / `applied_digest` | `GET /api/v1/endpoints/detail` | Convergência da política |
| `last_error` / `last_applied` | Ficha do endpoint | Falhas e último ACK de aplicação |
| `missing_capabilities` | Ficha/publicação | Perfil exige algo que o agente não anuncia |
| Bloqueios web | `GET /api/v1/stats/overview` | Agregados DNS; não representam URLs acessadas |
| Eventos de adulteração | `GET /api/v1/events` | Watchdog, WFP, DNS, remoção etc. |
| Auditoria administrativa | `GET /api/v1/audit` | Rastreio de mutações e leituras selecionadas |

Os valores `apps` e `usb` no overview não representam inventário: permanecem zero na fase atual.

## Alertas sugeridos (não implementados automaticamente)

- Dispositivo sem contato além do intervalo esperado da política de operação.
- Perfil desejado e aplicado divergentes após janela de sincronização.
- `last_error` persistente, falha de obtenção de categorias ou eventos `dropped`.
- Muitos eventos de recuperação de DNS/WFP/watchdog na mesma máquina.
- Erros de TLS, login/SAML ou ausência de persistência PostgreSQL/Redis.
- Volume de eventos acima de retenção, crescimento de banco, expiração de certificado.

Definir limites e SLIs com dados reais da frota; o repositório **não** fornece SLO, RTO ou RPO oficiais. Validar se os logs do servidor, proxy e Windows Service são coletados sem segredos.

## Diagnóstico rápido

~~~bash
docker compose ps
docker compose logs --tail 200 server
docker compose logs --tail 100 postgres redis
~~~

Interpretar rejeições `401`/`403` e `409`/`422` conforme contrato de API. Não imprimir `Authorization`, `Cookie`, convite ou `uninstall.json`. Ver [erros](troubleshooting.md) e [eventos](../reference/telemetry-events.md).
