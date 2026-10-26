# Modelo de dados e persistência

A API usa abstrações em `app/stores.py`, `app/enrollment.py`, `app/sessions.py`, `app/events.py`, `app/uninstall_codes.py`, `app/queue.py`. Migrações SQL em `migrations/001_initial.sql` a `004_uninstall.sql`, coordenadas por `app/migrations.py`.

~~~mermaid
erDiagram
  ENDPOINT ||--o{ BLOCK_EVENT : reports
  ENDPOINT ||--o{ TAMPER_EVENT : reports
  ENDPOINT }o--|| PROFILE : assigned_effectively
  ASSIGNMENT_RULE }o--|| PROFILE : targets_group
  ENDPOINT ||--o| UNINSTALL_STATE : keyed_by_client_id
  ADMIN ||--o{ AUDIT : performs
  ENDPOINT {
    string devid PK
    string client_id
    string credential_hash
    string vdom
    int config_version
    string applied_digest
    datetime last_seen
  }
  PROFILE {
    string vdom PK
    int version
    json body
  }
  ASSIGNMENT_RULE {
    string id PK
    int priority
    boolean enabled
  }
  BLOCK_EVENT {
    string devid
    datetime hour
    string domain
    string reason
    int count
  }
  TAMPER_EVENT {
    string devid
    datetime at
    string kind
  }
  UNINSTALL_STATE {
    string client_id PK
    int counter
    boolean secret_acked
  }
  ADMIN {
    string username
    string role
  }
  AUDIT {
    datetime ts
    string actor
    string action
  }
~~~

**Diagrama conceitual, não DDL:** entidades foram simplificadas e relações como perfil efetivo são calculadas por regra, não necessariamente chave estrangeira. Para colunas, restrições e índices reais, consultar as migrações e stores.

| Dependência | Uso |
| --- | --- |
| PostgreSQL | Endpoints, perfis, regras, IdPs, auditoria, eventos, estado de desinstalação e migrações |
| Redis | Filas, replay SAML e sessões/limites conforme configuração do servidor |
| Volume `categories` | Manifesto e arquivos versionados por digest |
| Estado local do agente | Cadastro, última política, cache de categorias, autoridade e estado de remoção |
| Memória | Implementações de referência para testes, não recomendadas para múltiplas réplicas |

Uma alteração de `client_id` afeta identidade, estado de desinstalação e segredo derivado. Não reescreva registros diretamente no banco para contornar a API. Ver [backup](../operations/backup-restore.md) e [atualização](../deployment/upgrades.md).
