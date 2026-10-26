# ADR-0001 — Backend Python e agente Rust

**Status:** registrado a partir da implementação e do `roadmap-v2.md`; documentação retrospectiva, não uma nova decisão.

## Contexto

Aplicação de políticas no endpoint precisa funcionar offline, inicializar com o Windows e operar sem instalar o interpretador Python nas estações. Administração, APIs e armazenamento precisam continuar testáveis e iteráveis.

## Decisão

- Servidor: Python/FastAPI com persistência PostgreSQL e Redis.
- Agente Windows: Rust e Windows Service, MSI com WiX 5.0.2.
- Agente Python permanece como referência de contrato.
- Política deve ser normalizada de forma idêntica nas duas linguagens usando vetores compartilhados.
- Painel React é servido pela API depois do build.

## Consequências

Benefícios: runtime nativo no endpoint, separação entre política e enforcement, contratos cruzados. Custos: complexidade de integração Windows, autorização de instalação, CA local, recuperação, testes por SO e assinatura. O uso de Rust não implica disponibilidade de driver de kernel ou compatibilidade macOS/Linux.

## Evidência

`agent-rs/Cargo.toml`, `agent-rs/installer/openems-agent.wxs`, `contract/policy-vectors.json`, `app/api.py`, `Dockerfile` e `roadmap-v2.md`.

Novos ADRs devem informar contexto, decisão, alternativas, efeitos sobre segurança/operação e testes exigidos.
