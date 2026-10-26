# Estado técnico da revisão

**Base:** `main@19ef954`, 2026-10-25; revisão documental de 2026-10-26. O avanço posterior deve atualizar este documento junto ao código. Não foram executados novos testes de sistema para esta documentação.

| Fase | Estado | Evidência principal | Limitações |
| --- | --- | --- | --- |
| F1 agente Rust Windows | Parcial | `agent-rs/`, suíte nativa, `validation/sandbox-msi-2026-10-23.json` e resiliência | Notificações no logon, assinatura, segundo dispositivo físico |
| F2 filtro web | Parcial | DNS/HTTPS, SafeSearch, anti-bypass, categorias e bloqueios com evidências em `validation/` | Firefox/Chrome e VPNs em maior variedade; LGPD/lista UT1; editor React incompleto |
| F3 aplicativos | Básico | Encerramento por nome de processo | Bloqueio antes de executar, inventário, firewall por app não implementados |
| F4 USB | Planejado | Placeholder React | Sem enforcement/inventário real |
| F5 antiadulteração | Parcial | Sandbox tamper 11 verificações e uninstall 11/11 | Componente no logon, reboot com serviço desativado em registro |
| F6 redes internas/externas | Planejado | Roadmap | Sem detecção por múltiplos sinais |
| F7 console React | Parcial | Login, visão geral, endpoints/detalhes, filtro web informativo | Editor, grupos, auditoria, configurações e eventos completos ainda não migrados |
| F8 Linux/macOS | Planejado | Contratos Rust multiplataforma | Sem serviços/pacotes e controles completos de SO |
| F9 Android/iOS | Planejado | Escopo no roadmap | Sem implementação |

### Não confundir

- **Presente no código**: módulo, rota ou teste existe.
- **Validado em testes automatizados**: verificador específico executou; não implica eficiência em SO real.
- **Validado em Windows Sandbox**: roteiro e artefato JSON atestam cenário simulado/descartável, com escopo delimitado.
- **Homologado em produção**: requer aprovação da organização, testes reais, assinatura, observabilidade e controle de mudança; **não demonstrado**.

Exemplos de lacunas: o `README.md` antigo dizia `admin/changeme`, mas `docker-compose.yml` exige `OPENEMS_ADMIN` e `POSTGRES_PASSWORD`; também descrevia tokens administrativos persistidos em `localStorage`, enquanto `app/api.py` usa cookie revogável e CSRF. A versão anterior foi substituída.

Referências: [roadmap](product/roadmap.md), [capabilities](product/capabilities.md), [matriz](validation/test-matrix.md), [evidências](validation/evidence-index.md).
