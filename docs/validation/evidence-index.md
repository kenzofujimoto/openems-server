# Índice de evidências verificáveis

Os artefatos originais permanecem em [`validation/`](../../validation). Cada JSON descreve `passed`, `scope`, ambiente, versão/commit, `checks` e `not_validated`. Não foram reexecutados no âmbito desta documentação.

| Data | Evidência | Escopo |
| --- | --- | --- |
| 2026-10-22 | `host-chrome-https-2026-10-22.json`, `sandbox-edge-https-2026-10-22.json`, `sandbox-trust-2026-10-22.json` | HTTPS e confiança local |
| 2026-10-23 | `sandbox-dns-2026-10-23.json`, `sandbox-antibypass-2026-10-23.json` | DNS e anti-bypass |
| 2026-10-23 | `sandbox-safesearch-2026-10-23.json` | SafeSearch e horários |
| 2026-10-23 | `sandbox-msi-2026-10-23.json`, `sandbox-resilience-2026-10-23.json` | MSI e recuperação |
| 2026-10-24 | `sandbox-categories-2026-10-24.json`, `sandbox-blocklog-2026-10-24.json` | Taxonomia e bloqueios |
| 2026-10-25 | `sandbox-tamper-2026-10-25.json` | ACL, watchdog e adulteração |
| 2026-10-25 | `sandbox-uninstall-2026-10-25.json` | 11 verificações de remoção e rollback |

O caso `sandbox-uninstall` registra `passed: true` e 11 checks. Isso é evidência de **laboratório simulado**; não inclui aprovação para todos os endpoints físicos, dependências de rede corporativa ou recuperação global.

A planilha histórica em `HANDOFF.md` e os planos de recortes em arquivos raiz fornecem contexto, mas não substituem os relatórios `validation/*.json`. Para validar claims, abrir diretamente o JSON correspondente e considerar também as pendências.

Veja [matriz](test-matrix.md) e [status](../status.md).
