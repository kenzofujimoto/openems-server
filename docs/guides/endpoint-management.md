# Operação de endpoints

## Estado na API

`GET /api/v1/endpoints/detail?devid=...` devolve identificadores, versão, sistema, `last_seen`, `online`, grupo original/efetivo, perfil desejado, `applied_digest`, `config_version`, `last_error`, `last_applied`, tags e `missing_capabilities`. O indicador `online` considera último contato em até **90 s** e status registrado — não equivale a verificação de rede em tempo real.

| Tarefa | Endpoint |
| --- | --- |
| Listar/contar | `GET /api/v1/endpoints/index` e `/count` |
| Detalhar | `GET /api/v1/endpoints/detail?devid=...` |
| Convite | `POST /api/v1/enrollment/invitations` |
| Trocar credencial | `POST /api/v1/endpoints/credentials/rotate` |
| Revogar | `POST /api/v1/endpoints/revoke` |
| Publicar perfil | `POST /api/v1/profiles/{vdom}` |
| Atribuição por regras | `POST/GET/DELETE /api/v1/assignment_rules` |

## Convergência

~~~mermaid
flowchart TD
  Desired[Perfil desejado por regra] --> Compare{Grupo, versão e digest iguais ao aplicado?}
  Compare -->|Sim| OK[Confirmado por ACK]
  Compare -->|Não| Check[Verificar last_seen e last_error]
  Check --> Offline{Agente offline?}
  Offline -->|Sim| Cached[Última política válida em cache]
  Offline -->|Não| Error[Inspecionar capacidade, autenticação, aplicação e logs]
~~~

Endpoint revogado não se desinstala automaticamente, e políticas já cacheadas podem persistir até remoção autorizada. A publicação pode devolver `warnings` quando a capacidade requerida não é anunciada pelo agente. Mover o dispositivo de grupo com versão coincidente exige comparar também digest e grupo.

Ver [ciclo](../architecture/agent-lifecycle.md) e [monitoramento](../operations/monitoring.md).
