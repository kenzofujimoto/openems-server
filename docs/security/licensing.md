# Licença, marcas e interoperabilidade

O código fonte está sob [MIT](../../LICENSE). Isso **não** implica direito de redistribuir todo conteúdo, dados, marcas, imagens e dependências presentes no repositório.

| Item | Cuidados |
| --- | --- |
| Código próprio | Preservar licença e atribuição MIT |
| Identidade visual RSM | Há ativos em `agent-rs/assets` e `web/public/brand`; verificar autorização formal antes de distribuir genericamente |
| Fontes | A fonte comercial Prelo não tem direito automático de redistribuição; verificar o uso de Noto Sans e licença |
| UT1 | Confirmar fonte oficial, URL, versão, licença e obrigações de atribuição/compartilhamento; não presumir CC BY-SA 4.0 apenas pelo handoff |
| Rust, npm, Python, WiX | Verificar licenças individualmente, produzir SBOM por release |
| Interoperabilidade FortiClient/EMS | Especificação clean-room com itens observados/inferidos/pendentes; nenhuma garantia de compatibilidade com binários oficiais |

A [SPEC-INTEROP.md](../../SPEC-INTEROP.md) foi criada para comportamento observável, sem transportar código proprietário. Capturas futuras devem ocorrer apenas em ambiente licenciado, autorizado, sem redistribuir credenciais/ativos. Leis de interoperabilidade e contratos variam por jurisdição: obter revisão jurídica antes de anunciar compatibilidade ou distribuir pacotes.

Gate pré-release: autorização de marca, inventário de dependências, licença das listas de domínio, cadeia de proveniência de dados, revisão jurídica e teste de compatibilidade. Ver [interoperabilidade](../validation/interoperability.md).
