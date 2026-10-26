# Documentação técnica do OpenEMS

**Escopo:** estado do repositório `main` em 2026-10-25 (commit `19ef954`), auditado em 2026-10-26. Os links deste conjunto descrevem o código existente, não certificam suporte de produção. [Status atualizado desta revisão](status.md).

## Produto e escopo

- [Visão geral](product/overview.md)
- [Requisitos e limites](product/requirements.md)
- [Matriz de capacidades](product/capabilities.md)
- [Fases e roadmap](product/roadmap.md)

## Arquitetura

- [Sistema — C4 contexto/contêineres/componentes](architecture/system-design.md)
- [Ciclo de vida do agente](architecture/agent-lifecycle.md)
- [Avaliação e distribuição de políticas](architecture/policy-engine.md)
- [Persistência e entidades](architecture/data-model.md)
- [Comunicação e limites de confiança](architecture/communications.md)
- [Decisões arquiteturais](architecture/adr/0001-core-and-agent.md)

## Colocar em funcionamento

- [Quickstart isolado](getting-started/quickstart.md)
- [Ambiente de desenvolvimento](getting-started/development.md)
- [Primeiro cadastro de endpoint](getting-started/first-enrollment.md)
- [Servidor Docker/TLS](deployment/server-docker.md)
- [Agente Windows/MSI](deployment/windows-agent.md)
- [Atualizações](deployment/upgrades.md)
- [Checklist de produção](deployment/production-checklist.md)

## Administração e referência

- [Administração e papéis](guides/administration.md)
- [Gerenciamento de endpoints](guides/endpoint-management.md)
- [Filtro web](guides/web-filtering.md)
- [Desinstalação controlada](guides/uninstall-management.md)
- [API HTTP](reference/api.md)
- [Variáveis e opções](reference/configuration.md)
- [Esquema de política](reference/policy-schema.md)
- [CLI Rust e MSI](reference/agent-cli.md)
- [Eventos e telemetria](reference/telemetry-events.md)

## Segurança, operação e qualidade

- [Modelo de ameaças](security/threat-model.md)
- [Identidades, sessões, certificados](security/identity-and-trust.md)
- [Proteção no endpoint](security/endpoint-protection.md)
- [Privacidade e LGPD](security/privacy-lgpd.md)
- [Licenças e proveniência](security/licensing.md)
- [Monitoramento](operations/monitoring.md)
- [Diagnóstico](operations/troubleshooting.md)
- [Backup/restore](operations/backup-restore.md)
- [Recuperação de desastre](operations/disaster-recovery.md)
- [Testes](development/testing.md)
- [CI/CD](development/ci-cd.md)
- [Releases](development/release-process.md)
- [Matriz de validação](validation/test-matrix.md)
- [Índice de evidências](validation/evidence-index.md)
- [Interoperabilidade](validation/interoperability.md)

**Fonte de verdade:** código, contratos e evidências versionadas. `roadmap-v2.md` e `HANDOFF.md` são histórico de planejamento/execução; uma funcionalidade descrita neles não é considerada pronta sem evidência compatível.
