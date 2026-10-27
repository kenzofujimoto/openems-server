# Documentação do OpenEMS

Referência atualizada em 27/10/2026. Os documentos de planejamento na raiz preservam decisões e evidências históricas; não são uma declaração de paridade com FortiGate/FortiGuard.

| Necessidade | Documento atual |
|---|---|
| Executar o servidor e o painel | [README](../README.md) |
| Estado implementado e pendências | [HANDOFF](../HANDOFF.md) |
| Testar em homologação, Sandbox e VMs | [ACCEPTANCE](../ACCEPTANCE.md) |
| Categorias, exceções e comparação FortiGuard | [Filtro web e compatibilidade](web-filter-compatibility.md) |
| Proposta Permitir/Bloquear/Monitorar e lacunas | [Plano das ações de filtro web](web-filter-actions-plan.md) |
| Objetivos e limites por fase | [Roadmap desktop](../roadmap-v2.md) |
| Suporte Linux e geração de pacotes | [Linux](../deploy/linux/SUPPORT.md) |
| Limites e pré-requisitos macOS | [macOS](../deploy/macos/SUPPORT.md) |
| Contrato de interoperabilidade | [SPEC-INTEROP](../SPEC-INTEROP.md) |
| Agente Python de referência | [Agente de referência](../agent/README.md) |

## Estado atual

- Windows: agente Rust e MSI, filtro web, componente de sessão, proteção do serviço, locais de rede, USB e controles de aplicativos implementados. O alcance de cada aceite está em HANDOFF/ACCEPTANCE.
- Painel: React com políticas, categorias, exceções por domínio, horários, SafeSearch, inventários, eventos, grupos/regras e administração.
- Categorias: 21 agrupamentos UT1, dependentes da publicação das listas no servidor. Sem uso da base ou dos IDs proprietários FortiGuard.
- Eventos web atuais: tentativas de bloqueio observadas pelo resolvedor DNS, agregadas por máquina/domínio/hora. Não representam histórico completo de páginas visitadas.
- Permitir/Bloquear/Monitorar: proposta documentada; o painel atual ainda usa checkboxes de bloqueio. Monitoramento de acessos permitidos não está implementado.
- Linux: implementação/pacotes aguardam aceite em VM. macOS permanece incompleto em Network Extension/Endpoint Security. F9 excluída.

Na transferência entre máquinas, arquivos ignorados (`.env`, `.venv`, builds, certificados e estado local) não acompanham o clone. Não transferir CA privada nem credenciais de um endpoint para outro.
