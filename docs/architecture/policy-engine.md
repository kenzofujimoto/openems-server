# Motor de políticas

Códigos: `agent/policy.py` (contrato), `agent-rs/src/policy.rs` (paridade), `app/rules.py` (atribuição), `agent-rs/src/dns.rs` e `agent-rs/src/processes.rs` (aplicação).

## Seleção do perfil

Regras habilitadas são avaliadas por **prioridade crescente**; a primeira cujas condições são verdadeiras define o grupo efetivo. Condições de uma regra são combinadas por AND. Sem match, aplica-se o grupo do cadastro. Uma mudança de grupo pode exigir nova aplicação mesmo com número de versão igual.

~~~mermaid
flowchart TD
  E[Endpoint registrado] --> R[Ordenar regras habilitadas por prioridade]
  R --> M{Primeira regra AND verdadeira?}
  M -->|Sim| G[Grupo alvo]
  M -->|Não| D[Grupo original]
  G --> P[Buscar perfil efetivo]
  D --> P
  P --> V{Perfil disponível?}
  V -->|Sim| C[Validar body e digest]
  V -->|Não| U[Unassigned explícito]
  C --> L[Aplicar localmente]
  L --> A{Enforcement OK?}
  A -->|Sim| ACK[ACK sucesso com grupo, versão e digest]
  A -->|Não| ERR[ACK falha com erro; não afirmar sucesso]
~~~

## Política local

O esquema é documentado em [policy-schema.md](../reference/policy-schema.md). O filtro web suporta domínios explícitos, curingas, permitidos, categorias e janelas. A regra `allowed` vence uma regra de bloqueio correspondente. SafeSearch é reescrita de resolução e não deve ser confundido com evento de bloqueio.

## Modos de enforcement

- `hosts`: entradas explícitas gerenciadas; não representa todas as consultas DNS e não oferece a mesma visibilidade de categorias.
- `dns_filter`: resolvedor local, NRPT Windows, wildcard e eventos DNS; requer `DNSFILTER=1`.
- `anti_bypass`: configurações de navegador e WFP para reduzir evasão; tem limites operacionais e de aplicações.
- Aplicativos: encerramento por nome de processo; **não** equivale a WDAC ou bloqueio pré-execução.

## Paridade e alteração

Qualquer mudança de normalização/digest deve regenerar `contract/policy-vectors.json` com `tools/gen_policy_vectors.py` e passar em `tests/test_policy_vectors.py` e `agent-rs/tests/policy_vectors.rs`. O ACK não pode afirmar estado aplicado antes da execução do enforcement.
