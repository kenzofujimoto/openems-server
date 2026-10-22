# Handoff — roadmap v2

Estado em 2026-10-22. O plano completo de cada fase, com critérios de aceite, está em `roadmap-v2.md`.

## Andamento por fase

| Fase | Estado | O que falta |
|---|---|---|
| F1 — Agente nativo (Windows) | Quase pronta. Agente Rust em `agent-rs/` com paridade do agente Python (testes de contrato em `tests/test_native_agent.py`), serviço com recuperação, MSI (WiX 5) testado em runner Windows real. | Componente da sessão do usuário (tarefa no logon, notificações). Assinatura de código (depende de certificado da RSM). MSI sem propriedade para ligar a página de bloqueio (hoje: `openems-agent.exe configure --block-page`). |
| F2 — Filtro web completo | Não iniciada. **Próxima.** | Tudo. Prioridade do usuário: página de bloqueio em HTTPS em qualquer navegador (CA local por máquina + servidor local HTTPS com certificado por SNI; ver riscos no roadmap). |
| F3 — Controle de aplicativos | Não iniciada. Hoje só encerra o processo pelo nome. | Tudo. |
| F4 — USB | Não iniciada. | Tudo. |
| F5 — Antiadulteração | Parcial: serviço automático no boot com reinício após falha. | ACL do serviço, watchdog, código de desinstalação, componente no logon. |
| F6 — Dentro/fora da empresa | Não iniciada. | Tudo. |
| F7 — Painel novo | Parcial. React em `web/`, servido em `/panel/` (a raiz já redireciona). Visão geral, endpoints com detalhe e login prontos. | Editores de política, regras, convites e auditoria (hoje ainda pelo console antigo em `/console/`). Rotas de servidor `/api/v1/stats/overview` e `/api/v1/events` (o painel usa mocks até elas existirem; contrato em `web/src/mocks/data.ts`). Remover o console antigo ao final. |
| F8 — macOS e Linux | Não iniciada (o agente Rust já compila e passa nos testes de contrato no Linux, no CI). | Serviço, empacotamento e recursos de cada sistema. Mac exige teste manual e Apple Developer ID. |
| F9 — Android e iOS | Não iniciada; precisa de especificação própria. | — |

## Combinados de trabalho

- **CI só no fim.** O usuário pediu um único PR com CI ao final de todas as fases, para economizar minutos. O CI roda apenas em push na `main`, em PR e por disparo manual. Commits enviados direto para a `main` levam `[skip ci]` na mensagem.
- **TDD** (ver `CLAUDE.md` do usuário): testes que falham primeiro, commit `test(scope): ...`, depois implementação.
- **Paridade de política:** qualquer mudança em `agent/policy.py` exige regenerar `contract/policy-vectors.json` com `python tools/gen_policy_vectors.py`; o Rust (`agent-rs/tests/policy_vectors.rs`) e o Python (`tests/test_policy_vectors.py`) leem os mesmos vetores.
- **Testes que instalam serviço ou MSI** só rodam em runner descartável do CI (`OPENEMS_SERVICE_TESTS=1`), nunca na máquina de desenvolvimento.

## Como verificar localmente

```bash
python -m pytest -q -m "not windows_only"
```
```bash
cd agent-rs && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test && cargo build --release
```
```bash
cd web && npm run lint && npm run typecheck && npm run test:coverage && npm run build
```

Os testes de contrato do agente nativo usam o binário em `agent-rs/target/` (defina `OPENEMS_REQUIRE_NATIVE_AGENT=1` para falhar em vez de pular). Os contratos PostgreSQL e Redis precisam de `OPENEMS_TEST_DSN` e `OPENEMS_TEST_REDIS`.

## Ambiente de teste do usuário (esta máquina)

- Servidor real via `docker compose up -d --build`, com `.env` gerado por `deploy/new-env.ps1` (segredos só no `.env`, que não vai para o git).
- Agente instalado pelo MSI e depois substituído pelo build de `agent-rs/target/release` (a versão do MSI não tinha as correções de log e recadastro). Página de bloqueio ligada.
- Validado pelo usuário: cadastro, política aplicada e confirmada, bloqueio de site, encerramento do Bloco de Notas, página de bloqueio em HTTP.
- Ainda não testado pelo usuário: resiliência (servidor parado, processo morto, reinício da máquina) e desinstalação.
