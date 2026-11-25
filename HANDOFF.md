# Handoff — roadmap v2

## Retomada — 25/11/2026: candidato preservado; aceites operacionais pendentes

Continua vigente a autorização para concluir a v1.0, executar o piloto nesta máquina e integrar/publicar após os critérios reais do [plano](windows-v1-release.md). O checkout operacional é `C:/Users/kenzo.fujimoto/Desktop/codigo/projetos/openems-server`; não usar por engano o worktree aberto no aplicativo.

O candidato continua em `f0092687e415f573b580d992fc905866a05bfcea`, com MSI e imagem intactos conforme o [recibo original](validation/windows-v1-candidate-2026-11-23.json). Dos 193 inputs registrados, 192 permanecem iguais; o lock recebeu apenas versão/checksum de cookie 0.18.2 para 0.18.3 após o CI detectar RUSTSEC-2026-0594. Cookie/cookie_store não participam das features padrão: os grafos completos Windows/Linux permaneceram idênticos ao arquivo congelado, normalizando somente o caminho da raiz. O scan de dependências passou sem supressões. A [revisão de alcance](validation/cookie-rustsec-2026-0594-review-2026-11-25.json) justifica conservar os artefatos existentes, sem atribuí-los a outra revisão. O [checkpoint de 25/11](validation/windows-v1-progress-2026-11-25.json) distingue testes concluídos dos aceites pendentes. Não há release publicada nem aceite operacional do RC1.

Concluídos: Rust **256/256**; painel **154/154**, lint/tipos/build e cobertura de linhas **95,21%**; contratos Node **50/50**. O scan do arquivo exato da imagem passou na política existente: zero HIGH/CRITICAL com correção disponível; 222 achados sem correção permanecem reportados. O gate de promoção agora exige também identidade imutável da imagem, scan, API/painel reais e revisão independente (**75 testes**, `62c19fe`); uma chamada que forneça apenas os aceites MSI é recusada. O catálogo aceita o candidato externamente fixado sem atribuí-lo ao HEAD novo (**17 testes**, `9df98fe`).

O host reiniciou. A suíte anterior parou em 52%, sem veredito; preserve `rc1/host-suite.log`. A primeira execução completa (`host-suite-20261125.log`) teve 1.920 passes, uma falha e cinco erros de ambiente: runtime headless do Playwright ausente e diretório de teste sem o auxiliar platform. Os nove testes desses módulos passaram após corrigir o ambiente, sem alterar fontes. Uma nova suíte completa está em `host-suite-final-20261125.log`, ainda em execução. Usa o diretório release cujos agent/session são byte a byte iguais ao candidato, cache Playwright privado com GC desativado, testes de serviço desativados e as quatro parametrizações destrutivas documentadas deselecionadas. A cobertura local com integrações desativadas não substitui a cobertura combinada do CI.

Pré-voo elevado **concluído** na tentativa `delegated-20261125-7675c042`: `backup_complete=true`, dez tópicos completos e oito arquivos copiados. O modo delegado mantém CU do usuário original fixado por hash/sessão/prazo, com LM conferido ao vivo. A autoridade canônica foi copiada por `SeBackupPrivilege` somente leitura, restaurando o token. A coleta do registro foi restringida à união auditada de nove caminhos usados pelo agente, em ambas as visões/hives: 36 posições, inclusive ausências, sem atravessar políticas IPSec alheias. Falhas dentro desse escopo continuam fatais (**79 testes**, `1ad60d7`). Resultados e destino protegido estão nos settings privados indicados por `rc1/current-delegated-attempt.txt`; nunca imprimir seu conteúdo, SID, configuração ou chaves.

**Recuperação ainda não comprovada.** O MSI 0.1.0 em cache corresponde ao produto registrado, mas seu payload é menor que o executável atualmente instalado; nenhum dos 42 MSIs únicos auditados contém esse executável. O plano privado `rc1/pilot-recovery-readiness.md` exige ensaio isolado de reinstalação do MSI antigo mais reposição do EXE preservado e dos dados/ACLs. A preparação desse ensaio está em `rc1/recovery-guest/`, sem transferir credenciais nem autoridade reais do host ao guest. O agente antigo continua Running/Auto, hash `ee5e56a9fe71ad121f62316c9cb8303f805abce1161b8d1718f046eff0b8eb34`; não foi atualizado. Não avançar o piloto físico apenas porque o backup terminou.

O laboratório `rc1/web/` tem TLS normal antes do MSI e seis checkpoints estritos de raízes no mesmo SID/sessão. A revisão corrigiu recuperação de contêiner criado antes da gravação do ID e exigência de exit zero além do JSON positivo de setup/navegadores/comandos: 24 testes privados e dois do supervisor passaram. `run-web-with-checkpoint.ps1` preserva os 31 contêineres originais e exige também prova de que os próprios ficaram parados, com IDs/imagens/labels corretos. A revisão estática está concluída; aguardar a suíte e executar sem apagar volumes ou falhas.

SafeSearch/antiburla: `rc1/search-bypass/attempt-20261125` foi preparado e verificado, sem execução; dez guardas inertes passaram. Os harnesses originais mantêm 5/9 cenários, confirmação visual real no Edge e prazo de 600 segundos. Catálogo: input congelado em `rc1/catalog-input`, run `351b6627c92c4666aad7ff33c086265b`. A preparação de mídias VMware de catálogo/aplicativos/USB está em `rc1/vm-regressions/`. Confirmar os recibos finais dessas mídias antes de usá-las. VM criptografada, login e reconexão de USB podem exigir o operador; não solicitar nem registrar senhas.

Sequência restante: concluir a suíte e publicar o patch do lock/revisão de alcance e a correção de registro no PR13; executar os guests sequencialmente, incluindo o aquecimento e a hora real do catálogo e o USB físico; conferir limpeza/restauração do host; comprovar recuperação antes do piloto físico; depois aguardar os checks finais, revisar, integrar e publicar somente os bytes aceitos com checksums e declaração de ausência de assinatura. Não reutilizar os aceites ec50572 para promover o RC1.

## Histórico — 24/11/2026

O operador autorizou concluir o candidato, os aceites, o piloto físico nesta máquina, a integração do PR13 e a publicação da v1.0. O plano vigente é [windows-v1-release.md](windows-v1-release.md). A proibição de merge/release do plano antigo foi substituída por essa autorização; as etapas só avançam após seus critérios reais.

O checkout operacional continua sendo o caminho canônico abaixo. Versão do servidor, painel, agente e builder alinhada em **1.0.0**. O candidato foi compilado da revisão `f0092687e415f573b580d992fc905866a05bfcea`, com os inputs de produção conferidos; sua identidade está em [windows-v1-candidate-2026-11-23.json](validation/windows-v1-candidate-2026-11-23.json). **Os novos bytes ainda não têm aceite operacional.** Os relatórios ec50572 permanecem históricos.

Artefatos privados em `.venv/windows-v1-20261123/rc1/`: MSI produção SHA b23752ae1d344f38d07bc91aa9b109b97643a81ece0cfba91f286191e1712d3a; fixture interna1.0.1 SHA6bf1a65b442f34b35eeab3c555e421d75fd64445339ff00126589dbcc20ab032; manifestoSHAe1e712ffad6a39a8426df39bb9a3fd0bddd40e5f671a6cc8f0f1d2a194f8a6e5. Nenhuma assinatura ou release pública. A imagem `openems-server:v1.0.0-rc1-f009268`, ID08abc4194dcfe5382bfc1179578462c81f3ac929370300d02e74a4a2b51497f2, tem API1.0/painel/migração008 presentes; o arquivo congelado tem SHA1147511decf57eba951093eed73e58a397e2be0918d3973034c902bc97a838a7. Os testes devem usar esses bytes sem rebuild.

Preparação: guardas de artefatos/staging27testes, planos de domínios ordenados75testescomcontratos existentes, versão19testes e inspetorMSI6testes+integração opcional. O painel passou154testes, lint/tipos/build, cobertura de linhas95,21%. A suíte completa e o CI dessa entrega ainda precisam concluir. O Trivy está verificando o arquivo exato da imagem, com relatórios em `rc1/security/`; durante a retomada seu download de base estava em execução, sem veredito. Preserve e verifique os processos/contêineres reais antes de qualquer nova inicialização.

O primeiro pré-voo físico elevado recusou `identity_mismatch` antes de copiar dados: `snapshot_created=false`, zero arquivos. O operador confirmou ter usado outra conta administradora. O helper está recebendo suporte delegado com contexto do usuário original preso por SHA, sessão e prazo, Documentos resolvido pelo perfil original e raízes CU identificadas como captura original. A revisão de segurança foi feita; confirme o commit GREEN final antes de executá-lo. Nunca use CU do administrador como baseline do usuário. O agente0.1.0 existente não foi alterado nem substituído, e o rollback ainda não está comprovado.

O novo lane `rc1/web/` está sendo preparado, sem iniciar Docker/guest, para matriz11, recuperação5 e regras ordenadas8 sobre a imagem congelada e stores próprios. Falta integrar a preparação TLS e a coleta estrita de raízes antes de executar. SafeSearch/antiburla e os regressivos em VM continuam pendentes, assim como piloto, merge e publicação. Não reutilizar a aprovação ec50572 para aceitar v1.0.

## Histórico da retomada — 22/11/2026

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
