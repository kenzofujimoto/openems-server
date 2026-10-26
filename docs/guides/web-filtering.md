# Filtragem web no Windows

Implementação: `agent-rs/src/dns.rs`, `policy.rs`, `nrpt.rs`, `wfp.rs`, `browser_policy.rs`, `categories.rs`, `authority.rs`. Requer configuração explícita e teste de compatibilidade.

~~~mermaid
flowchart TD
  Browser[Consulta DNS] --> NRPT[Windows: NRPT para resolvedor local]
  NRPT --> Local[Resolvedor OpenEMS 127.0.0.1:53]
  Local --> Policy{Política}
  Policy -->|Permitido| Forward[Upstream DNS atual]
  Policy -->|Bloqueado| Answer[Loopback / resposta de bloqueio]
  Answer --> Blockpage[Página HTTP/HTTPS se ativada]
  Local --> Events[Log agregado por hora]
  Events --> Server[API autenticada]
~~~

## Recursos

| Recurso | Condição | Observação |
| --- | --- | --- |
| `hosts` | Sem `dns_filter` | Lista explícita; não enxerga todas as consultas |
| `DNSFILTER=1` | Opt-in | DNS loopback, wildcard, allowlist, categorias/horários |
| `ANTIBYPASS=1` | Exige `DNSFILTER=1` | WFP, controles de navegador e bloqueios DNS/DoT/DoH definidos |
| `BLOCKPAGE=1` | Opt-in | Página HTTP local |
| `BLOCKPAGEHTTPS=1` | Opt-in | CA e TLS local; domínios com pinning podem falhar |

Regras permanentes e janelas ativas são unificadas; `allowed` vence bloqueios correspondentes e categoria. SafeSearch redireciona resolução para provedores suportados; não é bloqueio DNS contabilizado. Categorias dependem de manifesto válido, cache e licença da fonte UT1.

## Limites

O agente não faz inspeção TLS de sites permitidos; a CA é local e não sai da máquina. Falha do resolvedor/NRPT pode causar indisponibilidade de DNS. VPNs, DoH próprio, portais cativos e políticas empresariais de navegador exigem testes específicos. Eventos contam tentativas de resolução agregadas, **não** URLs completas ou visitas confirmadas.

Veja [schema](../reference/policy-schema.md), [telemetria](../reference/telemetry-events.md) e [privacidade](../security/privacy-lgpd.md).
