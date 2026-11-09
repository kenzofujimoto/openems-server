# Documentação do OpenEMS

Referência de aceites atualizada em 09/11/2026. Os documentos de planejamento na raiz preservam decisões e evidências históricas; não são uma declaração de paridade com FortiGate/FortiGuard.

| Necessidade | Documento atual |
|---|---|
| Executar o servidor e o painel | [README](../README.md) |
| Estado implementado e pendências | [HANDOFF](../HANDOFF.md) |
| Testar em homologação, Sandbox e VMs | [ACCEPTANCE](../ACCEPTANCE.md) |
| Fechar os gates da candidata Windows | [Plano de fechamento](../windows-release-completion.md) |
| Reproduzir controles em VM descartável | [Guia de VM](vm-acceptance-guide.md) |
| Categorias, exceções e comparação FortiGuard | [Filtro web e compatibilidade](web-filter-compatibility.md) |
| Permitir/Bloquear/Monitorar e lacunas | [Plano das ações de filtro web](web-filter-actions-plan.md) |
| Matriz de testes das novas ações | [Aceite das ações web](web-filter-actions-acceptance.md) |
| Roteiro do notebook com pendrive, Chrome e Firefox | [Aceite na segunda máquina](second-machine-acceptance.md) |
| Revisão de segurança e scanners | [Revisão de 27/10/2026](security-review-2026-10-27.md) |
| Contrato de política, capacidades e eventos | [Web action contract](web-filter-actions-contract.md) |
| Fontes, licença e limites das categorias | [Auditoria de fontes](category-source-audit.md) |
| Extensão opcional e integração pendente | [Browser visibility](../browser-extension/README.md) |
| Objetivos e limites por fase | [Roadmap desktop](../roadmap-v2.md) |
| Suporte Linux e geração de pacotes | [Linux](../deploy/linux/SUPPORT.md) |
| Limites e pré-requisitos macOS | [macOS](../deploy/macos/SUPPORT.md) |
| Contrato de interoperabilidade | [SPEC-INTEROP](../SPEC-INTEROP.md) |
| Agente Python de referência | [Agente de referência](../agent/README.md) |

## Estado atual

- Windows: agente Rust e MSI, filtro web, componente de sessão, proteção do serviço, locais de rede, USB e controles de aplicativos implementados. O par MSI `ec50572` passou no [catálogo8/8](../validation/catalog-vm-ec50572-acceptance-review-2026-11-06.json), [USB físico8/8](../validation/usb-vm-5354a16-run26-review-2026-11-08.json), [sessão/upgrade/reboot8/8](../validation/windows-session-ec50572-review-2026-11-09.json) e [locais8/8](../validation/windows-locations-ec50572-review-2026-11-09.json), com limpeza verificada. [CI, Security e CodeQL passaram em7e84493](../validation/windows-ci-7e84493-review-2026-11-09.json). Applications por editor e aceite global dos navegadores continuam pendentes; alcance e falhas preservadas em HANDOFF/ACCEPTANCE.
- Painel: React com políticas, categorias, exceções por domínio, horários, SafeSearch, inventários, eventos, grupos/regras e administração.
- Categorias: 27 IDs UT1, dependentes da publicação das listas no servidor, com estado de saúde. Sem uso da base ou dos IDs proprietários FortiGuard.
- Eventos web: bloqueios e monitoramentos DNS separados, agregados por máquina/domínio/hora, com deduplicação de lotes e descartes separados. Não representam histórico completo de páginas visitadas.
- Permitir/Bloquear/Monitorar: implementado com seletor acessível e compatibilidade explícita de agentes. Aceites históricos em Sandbox e Chrome/Firefox físicos com MSI `18cd811` estão no [roteiro da segunda máquina](second-machine-acceptance.md). A regressão da candidata `ec50572` continua pendente.
- Extensão Chrome/Firefox: pacotes separados e testes de contrato; broker nativo e aceite real pendentes. Inativa sem pareamento, coleta desligada por padrão.
- Linux: implementação/pacotes aguardam aceite em VM. macOS permanece incompleto em Network Extension/Endpoint Security. F9 excluída.

Na transferência entre máquinas, arquivos ignorados (`.env`, `.venv`, builds, certificados e estado local) não acompanham o clone. Não transferir CA privada nem credenciais de um endpoint para outro.
