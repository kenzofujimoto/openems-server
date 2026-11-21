# Documentação do OpenEMS

[Início rápido](../README.md) · [Contribuição](../CONTRIBUTING.md) · [Política de segurança](../SECURITY.md)

## Instalar e homologar

| Quero… | Onde consultar |
| --- | --- |
| Executar o servidor e abrir o painel | [README do projeto](../README.md) |
| Preparar um piloto nesta máquina Windows | [Piloto local](local-windows-pilot.md) |
| Testar USB e WDAC em uma VM Windows descartável | [Guia de VM](vm-acceptance-guide.md) |
| Repetir os testes de USB e navegadores em outra máquina | [Aceite na segunda máquina](second-machine-acceptance.md) |
| Instalar o agente nativo em Linux | [Suporte Linux](../deploy/linux/SUPPORT.md) |
| Preparar o pacote e revisar os requisitos no macOS | [Suporte macOS](../deploy/macos/SUPPORT.md) |

## Entender políticas e componentes

| Quero… | Onde consultar |
| --- | --- |
| Entender o filtro web e a compatibilidade com FortiGuard | [Filtro web e compatibilidade](web-filter-compatibility.md) |
| Definir precedência entre regras de domínio | [Regras ordenadas de domínio](ordered-domain-rules.md) |
| Aplicar e testar Permitir, Bloquear e Monitorar | [Contrato das ações web](web-filter-actions-contract.md) · [Roteiro de aceite](web-filter-actions-acceptance.md) |
| Conferir a origem, as licenças e a cobertura de categorias | [Auditoria de fontes](category-source-audit.md) |
| Desenvolver a extensão opcional para Chrome e Firefox | [Extensão e integração com o agente](../browser-extension/README.md) |
| Ler as interfaces observadas no protocolo EMS | [Especificação de interoperabilidade](../SPEC-INTEROP.md) |
| Consultar o agente Python de referência | [Agente de referência](../agent/README.md) |

## Acompanhar validação e mudanças

- [Roadmap desktop](../roadmap-v2.md) reúne as fases e o escopo do projeto.
- [Matriz de aceite](../ACCEPTANCE.md) e [handoff técnico](../HANDOFF.md) registram o histórico. Acompanhe a validação do candidato Windows no [PR #13](https://github.com/kenzofujimoto/openems-server/pull/13).
- [Ferramentas e gates de segurança](security-tooling.md) explica as verificações locais e no CI.

## Homologação Windows atual

O par MSI ec50572 passou nos aceites de catálogo, USB físico, aplicativos, sessão, upgrade, reboot e locais. A comparação final de raízes dos navegadores segue em investigação. A matriz reúne o alcance e os hashes de cada rodada. [Matriz atual](../ACCEPTANCE.md) · [Plano de fechamento](../windows-release-completion.md)
