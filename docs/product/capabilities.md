# Matriz de capacidades

| Área | Implementação observada | Situação |
| --- | --- | --- |
| Registro por convite e autenticação de dispositivo | `app/service.py`, `app/enrollment.py` | Implementado; homologação externa pendente |
| Grupos, regras e prioridade | `app/rules.py`, `app/api.py` | API operacional; editor React incompleto |
| Perfil/versionamento/digest/ACK | `app/service.py`, `agent-rs/src/runtime.rs` | Implementado, testado por contratos |
| Cache offline | `agent-rs/src/runtime.rs` | Implementado; Sandbox de resiliência |
| Bloqueio por hosts | `agent-rs/src/hosts.rs` | Modo de referência |
| DNS local, wildcard e allowlist | `agent-rs/src/dns.rs`, `nrpt.rs` | Implementado; Sandbox, opt-in |
| SafeSearch/horários | `agent-rs/src/policy.rs` | Implementado; Sandbox, opt-in |
| Anti-bypass WFP/DoH/políticas do navegador | `wfp.rs`, `browser_policy.rs` | Parcial conforme SO/navegador; Sandbox |
| Página de bloqueio HTTPS e CA local | `https_blockpage.rs`, `authority.rs` | Implementado; limites TLS/pinning |
| Listas por categoria e cache | `categories.rs`, `tools/update_categories.py` | Implementado; licença e fonte ainda por validar |
| Eventos web/antiadulteração | `app/events.py`, `agent-rs/src/events.rs` | Implementado; dados agregados |
| Código de remoção, liberação, gerador offline | `app/uninstall_codes.py`, `agent-rs/src/removal.rs` | Implementado; Sandbox 11/11 |
| Controle de aplicações | `agent-rs/src/processes.rs` | Encerramento por nome; sem bloqueio pré-execução |
| Controle USB | Placeholder `web/src/features/placeholder` | Não implementado |
| Perfil dentro/fora da rede | `roadmap-v2.md` | Não implementado |
| Painel React | `web/src/` | Parcial; legado `/console/` ainda existe |
| Agentes Linux/macOS/Android/iOS | Roadmap e testes de contrato Rust em Linux | Não suportados como gestão completa |

**Legenda:** implementado significa código presente e exercícios específicos; não significa homologação de produção. Consulte [matriz de validação](../validation/test-matrix.md) antes de afirmar cobertura. Os dados de tela com mocks não substituem backend real.
