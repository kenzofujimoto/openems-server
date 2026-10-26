# Primeiro cadastro do endpoint

Novo dispositivo consome convite com validade e limite de uso. O identificador `devid` não é uma credencial; `client_id` e `device_token` representam o cadastro.

~~~mermaid
sequenceDiagram
  participant Admin as Admin
  participant API as FastAPI
  participant Agent as Agente
  Admin->>API: POST /api/v1/enrollment/invitations
  API-->>Admin: convite + validade + usos
  Admin-->>Agent: Convite no provisionamento autorizado
  Agent->>API: POST /fct/api/public/v1/register/
  API-->>Agent: client_id + device_token
  Agent->>API: GET /fct/api/public/v1/config/assigned/
  API-->>Agent: grupo + versão + digest + body
  Agent->>Agent: Validar e aplicar a política
  Agent->>API: POST /fct/api/public/v1/config/ack/
~~~

## Procedimento

1. Iniciar servidor HTTPS e autenticar como administrador.
2. Solicitar `POST /api/v1/enrollment/invitations` com `{"vdom":"Default","max_uses":1,"ttl_seconds":3600}`. O usuário `viewer` não pode criar convites.
3. Entregar convite por meio seguro ao provisionamento da VM. Nunca armazenar convite, token de dispositivo ou cookies em tickets/logs.
4. Instalar o MSI com `SERVER`, `DEVID`, `VDOM` e `INVITATION`.
5. Consultar `GET /api/v1/endpoints/detail?devid=...` e conferir `effective_vdom`, `desired_profile`, `applied_digest`, `config_version`, `last_error` e `missing_capabilities`.

A presença na lista **não comprova** aplicação: o ACK só deve confirmar enforcement realizado. Se o mesmo `devid` já existir, o servidor exige prova de posse; cadastro revogado não é reutilizável. Há também convite inicial `OPENEMS_ENROLLMENT_TOKEN` com usos definidos por `OPENEMS_ENROLLMENT_USES`, criado no startup e válido por um dia.

Referências: `app/service.py`, `app/enrollment.py`, `app/api.py`, [ciclo de vida](../architecture/agent-lifecycle.md).
