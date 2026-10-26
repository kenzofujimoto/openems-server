# Matriz de validação da implementação

**Base:** arquivos JSON versionados em `validation/` até 2026-10-25. Esta revisão documental **não executou novamente** o produto.

| Área | Evidência versionada | Lacuna antes de produção |
| --- | --- | --- |
| DNS local, wildcard, NRPT | `sandbox-dns-2026-10-23.json` | Endpoint físico, VPN e navegadores variados |
| Anti-bypass / WFP / DoH | `sandbox-antibypass-2026-10-23.json` | Combinações adicionais de cliente e rede |
| SafeSearch e janelas | `sandbox-safesearch-2026-10-23.json` | Diferentes navegadores, timezone e políticas reais |
| HTTPS, confiança e certificados | `sandbox-trust-2026-10-22.json`, `sandbox-edge-https-2026-10-22.json` | Pinning, Chrome/Firefox, endpoints variados |
| Categorias/cache/log de bloqueios | `sandbox-categories-2026-10-24.json`, `sandbox-blocklog-2026-10-24.json` | Postgres real, licença UT1, avaliação LGPD |
| MSI/resiliência | `sandbox-msi-2026-10-23.json`, `sandbox-resilience-2026-10-23.json` | Assinatura, rollout corporativo |
| Antiadulteração | `sandbox-tamper-2026-10-25.json` | Reboot com serviço desabilitado no registro e EDR real |
| Códigos de remoção | `sandbox-uninstall-2026-10-25.json` (11 verificações aprovadas) | Custódia de chaves, disaster recovery real |
| React | Testes Vitest/MSW | Completar F7 e integrar backend real |
| Compatibilidade com FortiClient oficial | `SPEC-INTEROP.md` | Captura autorizada e teste com cliente oficial |

## Classificação

- `implementado`: existe código.
- `testado em unidade/contrato`: caminho específico passou em teste.
- `aceito em Windows Sandbox`: cenário declarado no JSON e suas fixtures passou.
- `homologado em produção`: exige piloto, segurança, legalidade, assinatura, monitoramento e aceite independente; **não demonstrado**.

Toda evidência deve registrar data, OS/versão, escopo, commit/hash, condições, ações, rollback, checks executados, falhas e `not_validated`. Fonte primária: [índice de evidências](evidence-index.md).
