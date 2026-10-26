# Visão geral

OpenEMS é uma plataforma de gerenciamento de políticas para endpoints com servidor central e execução local. Seu objetivo é administrar dispositivos mesmo fora da rede corporativa sem depender de VPN para aplicar as regras **já sincronizadas**.

## Problema atendido

Uma rede corporativa pode filtrar conteúdo pelo firewall na sede, mas dispositivos remotos não passam necessariamente por ele. O OpenEMS distribui perfis centralizados; no Windows, o agente Rust aplica bloqueios locais e armazena o último perfil válido para operar durante indisponibilidade do servidor.

## Público e componentes

| Papel | Interação |
| --- | --- |
| Administrador | Cadastra endpoints, atribui grupos, publica perfis, analisa eventos e autoriza remoção |
| Analista de SI | Observa estados, logs de bloqueio e eventos de adulteração |
| Operador de infraestrutura | Instala/atualiza serviço, banco, certificado e executa recuperação |
| Contribuidor | Usa testes, fixtures de contratos, Sandbox e ADRs |

## Limites de produto

O OpenEMS **não** fornece equivalência funcional integral ao FortiClient EMS. Integrações com componentes proprietários, VPN, ZTNA, FortiGuard, controle de USB e bloqueio pré-execução não estão comprovadas como disponíveis. O painel React ainda é parcial. Código aberto não equivale a solução certificada para compliance.

## Fluxo resumido

~~~mermaid
flowchart LR
  Admin[Administrador] --> Web[Console /panel ou /console]
  Web --> API[FastAPI]
  API --> DB[(PostgreSQL)]
  API --> Q[(Redis)]
  Agent[Windows: serviço Rust] <-->|HTTPS: cadastro, perfil, ACK, eventos| API
  Agent --> Local[DNS / hosts / processos / watchdog]
~~~

Consulte [arquitetura](../architecture/system-design.md), [matriz](capabilities.md), [requisitos](requirements.md).
