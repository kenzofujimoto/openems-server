# Interoperabilidade — clean-room

O OpenEMS implementa contratos próprios sob rotas `/fct/api/public/v1/*`, mas isso **não garante** que um FortiClient oficial registre, aceite políticas ou opere corretamente com esse servidor.

| Evidência | Significado | Situação |
| --- | --- | --- |
| Observado | Endpoint, string ou comportamento de ambiente licenciado | Parcial |
| Inferido | Hipótese baseada em observações | Não é compatibilidade comprovada |
| A capturar | Formato exato, cabeçalhos, sequência, TLS/cadência | Pendente |
| Implementado | API JSON do agente próprio Rust/Python | Testável internamente |

A especificação [SPEC-INTEROP.md](../../SPEC-INTEROP.md) enumera pendências: corpos de registro/refresh, keepalive, avatar em chunks, config push, autenticação da porta 8013, certificados e pinning. Uma captura futura deve ser feita **apenas** em laboratório autorizado com software licenciado, usando versões identificadas e dados redigidos. Não copiar código/binário/assets proprietários para o repositório.

Cada descoberta deve registrar versão, método/path, request/response sanitizados, cabeçalhos, timestamps, erro, hipótese concorrente e teste que diferencia hipótese de observação. Revisar termos de licença e jurídico antes de distribuir artefatos de interoperabilidade.

Ver [proveniência](../security/licensing.md).
