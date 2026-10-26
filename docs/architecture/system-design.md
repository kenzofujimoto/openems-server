# Arquitetura do sistema

Implementação em [app/](../../app), [agent-rs/](../../agent-rs), [web/](../../web), [agent/](../../agent), [migrations/](../../migrations) e [deploy/](../../deploy). Diagramas expressam relações lógicas, não garantem isolamento de rede configurado.

## C4 — Contexto

~~~mermaid
flowchart LR
  Operator[Administrador / operador] -->|Navegador, HTTPS| OpenEMS[OpenEMS]
  Endpoint[Dispositivo Windows] <-->|HTTPS, políticas e telemetria| OpenEMS
  IdP[IdP SAML opcional] <-->|SAML 2.0| OpenEMS
  Lists[Fonte de listas aberta opcional] -->|Atualização de categorias| OpenEMS
~~~

## C4 — Contêineres

~~~mermaid
flowchart TB
  subgraph HostServidor[Host do servidor]
    Proxy[Proxy TLS / nginx opcional]
    API[FastAPI / app]
    Panel[React estático /panel]
    Legacy[Console legado /console]
    DB[(PostgreSQL 16)]
    Redis[(Redis 7)]
    Category[(Volume de categorias)]
    Worker[Atualizador categorias opt-in]
    Proxy --> API
    API --> DB
    API --> Redis
    API --> Category
    Worker --> Category
    API --> Panel
    API --> Legacy
  end
  Admin[Navegador admin] --> Proxy
  Agent[Serviço Rust no endpoint] --> Proxy
  Agent --> OS[APIs Windows / DNS / WFP / serviço]
~~~

O frontend React é compilado no `Dockerfile` e servido pela API a partir de `app/panel_dist`. A imagem de runtime não inclui Node. O backend implementa `create_app` em `app/api.py` e usa `EmsService` para regras de negócio.

## C4 — Componentes do backend

~~~mermaid
flowchart LR
  HTTP[app/api.py] --> Auth[auth / sessions]
  HTTP --> Service[service.py]
  HTTP --> Event[events / audit]
  HTTP --> SAML[saml / replay]
  Service --> Rules[rules / policy validation]
  Service --> Stores[stores / enrollment]
  Stores --> DB[(PostgreSQL)]
  Service --> Queue[queue]
  Queue --> Redis[(Redis)]
  Event --> DB
  SAML --> Redis
~~~

## Componentes do agente

~~~mermaid
flowchart TB
  Runtime[runtime.rs / service.rs] --> Client[api.rs]
  Runtime --> Policy[policy.rs]
  Runtime --> State[state.rs / config.rs]
  Policy --> DNS[dns.rs / nrpt.rs]
  Policy --> Hosts[hosts.rs]
  Policy --> Apps[processes.rs]
  DNS --> TLS[blockpage / authority]
  Runtime --> Anti[hardening / wfp / browser_policy]
  Runtime --> Events[events.rs]
  Runtime --> Removal[removal.rs / tamper.rs]
~~~

## Limites

- A gestão central não faz enforcement diretamente na rede do colaborador. A política é entregue ao agente, que age localmente.
- Servidor indisponível não equivale necessariamente a política ausente: há cache offline, sujeito ao estado local íntegro.
- O suporte do Linux nos testes do binário Rust não implica implementação de serviço e enforcement equivalente ao Windows.
- O projeto não valida incompatibilidades com VPN, drivers e EDR de terceiros em todos os cenários.

Ver [ciclo de vida](agent-lifecycle.md), [comunicação](communications.md) e [dados](data-model.md).
