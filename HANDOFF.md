# Handoff — roadmap v2

## Retomada — 22/11/2026

O checkout operacional está em `C:/Users/kenzo.fujimoto/Desktop/codigo/projetos/openems-server`, branch `feature/catalog-vm-acceptance`. O diretório aberto no aplicativo pode ser outro worktree; use esse caminho ao retomar os roteiros locais.

A solução está em homologação Windows. O piloto físico foi preparado e ainda não foi executado. A [matriz de aceite](ACCEPTANCE.md) registra os resultados por pacote.

## Resultados e publicação

- A main está em `605da3e`, com README ilustrado, índice de documentação e guia de contribuição no PR #20. O PR #21 integrou as correções já validadas de dependências e imagem. Ambos passaram 20/20 checks.
- O [PR Windows #13](https://github.com/kenzofujimoto/openems-server/pull/13) permanece em rascunho. CI, Security e CodeQL passaram para `8f20223`. Consulte os checks do PR para o resultado da revisão publicada nesta retomada.
- A revisão `10951c0` teve falha de dependências pelo alerta novo RUSTSEC-2026-0592. O commit `3d013b8` atualizou o lock para url 2.5.9 e form_urlencoded 1.2.3, com OSV local sem achados nos 644 pacotes. Os MSIs ec50572 permanecem originais, com url 2.5.8; não representam o build corrigido. Consulte os checks do PR e a [revisão de segurança](validation/url-rustsec-2026-0592-review-2026-11-22.json).
- Aplicativos: **10/10**, remoção MSI **0**. Catálogo, USB, sessão/upgrade/reboot e locais: **8/8** em cada aceite.
- Chrome e Firefox: **6/6**, TLS normal e comparação final exata das raízes. O preparo TLS anterior ao agente materializou GlobalSign R1 e IdenTrust: 22 raízes no baseline, 23 com a raiz própria e exatamente 22 após sua remoção. [Recibo final](validation/browser-trust-ec50572-final-2026-11-21.json)
- Ações web: **11/11** cenários e **6/6** navegações reais, com eventos conferidos no PostgreSQL, remoção MSI **0** e guest encerrado. Recuperação **5/5** aprovada, com nova remoção MSI **0** e limpeza confirmada. [Recibo web](validation/windows-web-actions-ec50572-review-2026-11-21.json)
- Painel: 154 testes, lint, typecheck e build aprovados; cobertura de linhas de 95,21%. Os oito testes inertes de isolamento e 11 contratos Node passaram.

O diagnóstico anterior identificou o CryptSvc e o PowerShell da sonda gravando raízes. O CAPI2 não confirmou o gatilho original; as rodadas reprovadas permanecem preservadas. [Diagnóstico](validation/browser-root-attribution-2026-11-21.json)

## Laboratório encerrado e restaurado

O lane privado é `.venv/web-actions-ec50572-20261121/`, projeto `openems-web-ec50572-a7f56353`. A matriz terminou em `matrix-20261121-193740`; a recuperação terminou em `resilience-20261121-195825`. Usa API e React reais, PostgreSQL/Redis próprios, MSI congelado e guests sequenciais de 2560 MiB. O supervisor é `run-with-checkpoint.ps1`.

Os dois summaries terminaram com `passed=true`, remoção MSI 0, limpeza própria verificada e guest parado. `host-containers-restoration.json` confirmou `restored=true`, sem diferenças nem erros; o checkpoint tem `restore_required=false`. A conferência de 22/11 encontrou os mesmos 29 IDs e estados originais, os dois contêineres próprios parados, zero Sandbox/VMware e zero listener da API de teste. O serviço antigo do host continua em execução com o mesmo hash. Preserve o volume privado e os resultados; não reinicie o laboratório por uma atualização documental.

## Piloto físico e aceites restantes

O pacote está em `~/Documents/OpenEMS-Lab/Pilot-ec50572-20261121/`, com MSIs, hashes, recibo e guia. Esta máquina já possui o agente 0.1.0, instalado em 22/10/2026, em execução, hash `ee5e56a9fe71ad121f62316c9cb8303f805abce1161b8d1718f046eff0b8eb34`. A conferência foi somente leitura; o processo atual está sem elevação e a configuração protegida recusou leitura. Preserve essa configuração em sessão elevada antes do ensaio de atualização. [Guia do piloto](docs/local-windows-pilot.md)

O pacote de laboratório está sem assinatura de distribuição. Não foi contratado serviço de assinatura. Ações web não comprovam automaticamente regras ordenadas, SafeSearch ou antiburla no candidato: esses aceites permanecem separados. Os roteiros [SafeSearch](deploy/test-safesearch-sandbox.ps1) e [antiburla](deploy/test-antibypass-sandbox.ps1) exigem verificações visuais no Edge. Os inputs antigos de outubro usam outros MSIs e não servem como prova de ec50572. Linux aguarda aceite operacional em VM; macOS segue parcial.

## Histórico

Os [checkpoints até 17/11/2026](docs/history/handoff-through-2026-11-17.md) foram preservados integralmente, com links relativos ajustados e conferidos.
