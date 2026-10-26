# Processo de release

1. Fixar versão e compatibilidade servidor/agente/painel. Revisar explicitamente `agent-rs/Cargo.toml` e `Version` do MSI; não presumir sincronização automática.
2. Atualizar CHANGELOG, estado de funcionalidades, README, referências API/política, ADRs e dependências.
3. Executar CI e Windows Sandbox; comprovar instalação, falha, reboot, upgrade, cache offline, políticas DNS/WFP, CA, desinstalação e rollback.
4. Validar licenças de lista UT1, identidade RSM, dependências e dados; produzir SBOM, hashes e assinatura do binário/MSI.
5. Publicar tag imutável com artefatos, hashes, proveniência, matriz de suporte e instruções de rollback.
6. Fazer implantação piloto e acompanhar ACK, `last_error`, acesso do servidor e incidentes; ampliar progressivamente.

Os artefatos de validação antigos usam builds e commits específicos. **Não distribuir o MSI de um Sandbox anterior como se representasse a versão atual de `main`**. Não há evidência nesta revisão de release corporativo assinado.

Consulte [atualizações](../deployment/upgrades.md), [gate de produção](../deployment/production-checklist.md).
