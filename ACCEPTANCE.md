# Aceite final do roadmap desktop

## Estado vigente — 05/11/2026. Rodada 13 falhou na espera pelo marcador

O VMware restaurou o snapshot 1 às 12:46:46Z e conectou a ISO b6d4be5 às 12:50:05Z. A rodada v2 a6c27d86 encerrou às 13:04:00Z com “The fixture did not reach its sentinel.” As referências HTTPS iniciais e o check de app ausente passaram. Depois do ACK positivo v3 de rede e antes da publicação v4, uma das duas sondas criou um processo sem observar seu encerramento ou marcador na janela de 10 s. A fixture grava o marcador antes de HTTPS. O relatório não distingue qual sonda falhou. Um LocalError v2 antecedeu o ACK v3 positivo; a relação causal continua desconhecida. [Relatório original](validation/vm-catalog-b6d4be5-result-2026-11-05.json) e [revisão](validation/catalog-vm-b6d4be5-startup-failure-review-2026-11-05.json).

O host reavaliou o recibo, app ausente e limpeza. MSI 0, ausência de serviço/watchdog/NRPT/firewall/CI próprios e registros de fixture, mesmas 482 regras externas sem diferenças e mesmos 14 IDs CI externos. A coleta de limpeza v2 funcionou nesta falha. Rede, processo, WDAC e rechecagem de uma hora não concluíram; a rodada permanece reprovada.

Preservar a VM. Coletor 14 solicitado em OpenEMSResults com o atalho 14 - Collect catalog startup diagnostics as administrator.lnk. Ele lê hashes/tempos dos arquivos e marcadores próprios, categorias sanitizadas do agente e eventos delimitados de inicialização. Parser PS5.1, quatro verificações sintéticas de filtros e atalho elevado conferidos. Aguardar catalog-startup-diagnostics-a6c27d86.json. Código e pacote congelados enquanto o diagnóstico está pendente. Os checkpoints anteriores abaixo são históricos.

## Estado vigente — 05/11/2026. Evidências v2 prontas para aceite na VM

O vermelho do commit 3b42cb5 teve 63 falhas esperadas e 1.460 sucessos. A implementação b6d4be5 passou na mesma suíte completa permitida com 1.523 sucessos, 57 skips e quatro casos integrais legados desmarcados. Ruff, pip check e parser PS5.1 passaram. O roteiro grava o baseline antes do MSI, registra diferenças e resultados independentes de limpeza em caso de falha, retém categorias seguras dos ACKs e finaliza o relatório após a coleta. O verificador do host recalcula a preservação. O exportador copia cada versão do checkpoint uma vez.

A ISO OpenEMS-Catalog-b6d4be5-a6c27d86.iso, os dez arquivos ópticos, os MSIs 0.4.0/0.4.1 e o atalho 13 foram conferidos. O agente nativo mantém o SHA-256 f33dfd05…; a nova mídia corresponde à fonte b6d4be52550c59ad7c5e8083bca193229212aa28 e ao run a6c27d86de834dbb85cafe8388c82d70. A rodada real está pendente. [Recibo de preparação](validation/catalog-vm-preparation-b6d4be5-2026-11-05.json).

Próxima ação no VMware. Desbloquear a VM no próprio VMware, usar Go To no snapshot clean-preflight-before-controls, montar a ISO nova e marcar Connected. No guest, abrir OpenEMSResults e executar 13 - Catalog acceptance as administrator.lnk com UAC. Aguardar o aceite integral com 90 s por ACK, uma hora real e limpeza normal. A CLI pede a senha de criptografia para operações de snapshot; não enviar senha pelo chat. A VM estava fora da lista de VMs em execução.

A rodada anterior permanece reprovada, com limpeza confirmada e causas específicas de firewall/OSError/LocalError desconhecidas. A melhoria é de evidências. Integrações vivas, USB físico e cobertura global continuam pendentes. As etapas de aprovação, diagnóstico e suíte em execução abaixo são históricas.

## Estado vigente — 04/11/2026: coleta 12 válida; plano de evidências aguarda aprovação

[Coleta corrigida original](validation/vm-catalog-5e71292-agent-log-diagnostics-2026-11-04.json) e [revisão](validation/catalog-vm-5e71292-acceptance-review-2026-11-04.json): concluída sem erros de coleta; mesmo log de 654 bytes/hash da coleta 11. Foram identificados OSError às 18:38:00Z e 19:14:07Z, LocalError às 19:35:09Z e 19:35:18Z, todos entre 2,8 e 9,0 segundos antes dos quatro ACKs negativos correspondentes. As categorias confirmam falhas locais, mas não identificam a operação ou subsistema que falhou. O estado da tarefa ainda era Running no instante da exportação; esse campo não comprova um exit code final. O relatório completo de diagnóstico foi recebido.

Todas as coletas solicitadas foram preservadas e revisadas. Limpeza independente, remoção MSI0 e os 14 IDs CI externos permanecem confirmados pela coleta 10. A rodada 09 permanece reprovada; causa da diferença do firewall e das falhas locais ainda desconhecida. Nenhuma nova coleta manual solicitada. Manter a VM no estado atual; não iniciar outra rodada.

[Plano concreto proposto](docs/catalog-cleanup-evidence-plan.md), ainda sem implementação: três arquivos (teste, roteiro, builder), TDD vermelho commitado antes do ajuste, persistência de baseline/diferenças/limpeza mesmo em falha, retenção restrita de categorias de ACK e verificação independente no host. Mantém a guarda e todos os prazos/critérios; não altera produto nativo nem atribui causa sem evidência. Aguarda aprovação explícita conforme a regra do AGENTS.md para duas ou mais alterações de arquivos. Dados/documentação já atualizados; gates locais anteriores não foram repetidos sem mudança de código. As pendências anteriores da coleta 12 abaixo são históricas.

## Atualização vigente — 04/11/2026: filtro do coletor 11 inválido; repetição 12 preparada

[Coleta 11 original preservada](validation/vm-catalog-5e71292-agent-log-diagnostics-invalid-filter-2026-11-04.json) e [revisão](validation/catalog-vm-5e71292-acceptance-review-2026-11-04.json): execução concluída em 22 segundos, mas a lista vazia de falhas é inválida. O filtro gerado perdeu escapes e rejeita uma linha sintética válida do logger nativo; não concluir ausência de erros pelos dados dessa coleta. O log preservado tem 654 bytes.

Coletor 12 preparado e solicitado: 12 - Collect catalog agent log diagnostics retry as administrator.lnk, saída catalog-agent-log-diagnostics-eb8486c4-retry1.json. Mesmo escopo restrito e somente leitura do 11; filtro corrigido sem depender de escapes, parser e 12 casos sintéticos verificados em Windows PowerShell 5.1, atalho elevado conferido. Preservar guest e aguardar a saída. Limpeza independente da coleta 10 continua confirmada; causa do firewall e quatro erros locais permanecem desconhecidos, e o aceite continua reprovado.

[Plano proposto para evidências completas](docs/catalog-cleanup-evidence-plan.md): persistir baseline/diff/limpeza e categoria restrita de ACK, com TDD em teste/roteiro/builder. Nenhuma implementação iniciada; aguardar diagnóstico 12 e aprovação explícita antes de alterar os três arquivos. Nenhum novo MSI/ISO, controle no host, restauração ou repetição de suítes. As pendências anteriores do 11 abaixo são históricas.

## Atualização vigente — 04/11/2026: coleta 10 confirmou remoção; falha de firewall ainda sem causa

[Coleta 10 original](validation/vm-catalog-5e71292-cleanup-diagnostics-2026-11-04.json) e [revisão](validation/catalog-vm-5e71292-acceptance-review-2026-11-04.json): concluída em 53 segundos, sem erros. Log MSI com retornos 0/0; serviço, watchdog e diário de aplicações ausentes; NRPT, firewall próprio e política CI própria zerados; registros das fixtures ausentes. Os mesmos 14 IDs CI externos foram preservados e o ACK de liberação v7 foi conferido. **Limpeza atual confirmada, mas a rodada continua reprovada pela guarda de preservação do firewall.**

As 483 regras atuais têm nomes únicos; nenhum evento dos IDs 2004/2005/2006/2033 foi encontrado no intervalo. Isso não identifica qual regra mudou nem comprova preservação retroativa, pois o baseline não foi persistido. A coleta também revelou quatro ACKs negativos da v6: 18:38:03Z, 19:14:12Z, 19:35:11Z e 19:35:26Z. O runtime envia success=false quando um ciclo local de enforcement retorna erro; o backend da fixture descartou a categoria desse erro. Houve recuperações positivas após os dois primeiros, e liberação v7 positiva após os últimos. Não atribuir esses erros à geração WDAC ou à hora opcional sem evidência; não confundir os sete efeitos observados com uma execução sem falhas locais.

**Preservar guest até ler os logs remanescentes.** Coletor 11 preparado/solicitado em OpenEMSResults: `11 - Collect catalog agent log diagnostics as administrator.lnk`, saída `catalog-agent-log-diagnostics-eb8486c4.json`. Só exporta metadados/hash e horários/categorias permitidas das linhas de falha de enforcement no intervalo da rodada, lendo quatro nomes fixos de logs com tamanho limitado. Não exporta configuração, estado, stderr bruto ou segredos e não aplica controles. Parser PS5.1 e atalho elevado conferidos. Nenhuma nova alteração de produto/roteiro, teste, mídia ou restauração; próximos passos dependem dessa coleta. As pendências anteriores do coletor 10 abaixo são históricas.

## Estado vigente — 04/11/2026: sete critérios passaram; aceite completo falhou na preservação do firewall

[Relatório original](validation/vm-catalog-5e71292-result-2026-11-04.json) e [revisão](validation/catalog-vm-5e71292-acceptance-review-2026-11-04.json), fonte `5e71292bfe7542fdbe9d5f0bdb7fc4555e5d03ff`, run `eb8486c4e5d940238c9ff17c3336f6d8`: **failed**, encerrado às19:39:28Z. Os sete checks presentes foram reavaliados no host contra o manifesto: app ausente, rede/referência/liberação, processo, WDAC original/renomeado, remoção quando ausentes, hora real e liberação final passaram. Rechecagem3602,795s monotônicos/3602,943s UTC; diário avançou3610s e63 observações mantiveram a mesma atribuição v6/digest. Executável B renomeado iniciou antes e foi recusado depois (erro nativo4551, sem criação de processo). Liberação v7 reconhecida, original/renomeado exit0, sem política própria ou regras de firewall próprias nessa etapa.

**Falha final: `An unrelated firewall rule changed.`** A guarda compara cada regra anterior por Name/Enabled/Direction/Action e também rejeita zero ou múltiplos matches. Não exporta qual regra divergiu e mantém o baseline somente em memória. Lançou antes de construir o check cleanup, portanto estado final do serviço/watchdog/NRPT/CI não foi registrado. Remoção MSI0 é inferida pelo fluxo (não houve erro nessa chamada), ainda sem confirmação independente. Não atribuir a causa ao produto, Windows Update ou duplicidade sem evidência. Nenhum aceite completo; falhas anteriores preservadas.

**Preservar guest; não restaurar nem repetir a rodada.** Coletor10 preparado e solicitado em `\\vmware-host\Shared Folders\OpenEMSResults`: `10 - Collect catalog cleanup diagnostics as administrator.lnk`. Coleta somente leitura de ACKs, resultado MSI, estado dos controles, regras atuais e eventos de firewall no intervalo da rodada; não executa fixtures, reinstala agente, aplica política ou altera permissões. Parser Windows PowerShell5.1 e atalho elevado conferidos. Aguardar `catalog-cleanup-diagnostics-eb8486c4.json`; tentar identificar a alteração e conferir limpeza/14IDs CI externos. Se não houver baseline recuperável, preparar plano TDD para persistir baseline/diff e estado de limpeza antes de nova rodada. Produto/roteiro/prazos congelados, gates locais1454Python/251Rust/154painel já concluídos, sem necessidade de repetir suítes sem mudanças. Integrações vivas, USB físico e gates globais por módulo permanecem pendentes. As seções abaixo são históricas.

## Estado vigente — 04/11/2026: roteiro corrigido e pacote5e71292 pronto

[Recibo de pacote e gates](validation/catalog-vm-preparation-5e71292-2026-11-04.json): **1454 Python,251 Rust e154 painel passaram**, além dos gates estáticos/build. Python teve57skips e quatro casos integrais de controles desmarcados. TDD vermelho baee7c0 com1falha esperada/1453sucessos; correção5e71292 isola ambos os probes HTTPS sob allow já reconhecido, antes do bloqueio de processo absent. Produto/builder/regras e limites originais preservados; agente mantém SHA f33dfd05. Cobertura app/agente88,88%; gates completos por módulo e integrações vivas pendentes.

MSIs0.4.0/0.4.1 sem fault injection/ISO `OpenEMS-Catalog-5e71292-eb8486c4.iso` e atalho09 conferidos. Nova rodada source5e71292/runeb8486c4e5d940238c9ff17c3336f6d8 **não iniciada e sem aceite Windows**. Dados da rodada948608e e coleta08 preservados; liberação e limpeza independente confirmadas,14IDs CI externos mantidos. Pode restaurar snapshot limpo e executar09 somente com a nova ISO conectada. Manter todos os oito critérios, ACK90s,3600s reais e remoção normal. As falhas anteriores permanecem reprovadas; validações locais não substituem enforcement real.

## Diagnóstico — 04/11/2026: referência de rede interfere com bloqueio de processo

[Coleta08 e revisão](validation/catalog-network-order-diagnostic-review-2026-11-04.json) confirmaram liberação/limpeza independente,14IDs CI preservados e HTTPS200 com ambos os EXEs exit0 após remover o agente. A política `absent` v2 ainda bloqueia o nome do processo original quando o roteiro inicia sua referência de rede; o log mostra esse encerramento no intervalo. Regressão isolada reproduziu a falha com as políticas da API real e fronteiras mockadas, sem controles/EXEs no host. [Continuação TDD](docs/catalog-network-baseline-order-plan.md) vai isolar as referências sob a política `allow` já reconhecida. Nenhuma aceitação reclassificada; rede/processo/WDAC/hora real continuam pendentes, e os prazos/critérios não mudam.

## Resultado vigente — 04/11/2026: 948608e reprovado antes do bloqueio de rede

[Rodada original](validation/vm-catalog-948608e-result-2026-11-04.json), run0e93a06a: app ausente passou, mas um ou ambos os executáveis próprios falharam no HTTPS de referência antes de publicar a política de rede. **Rede/processo/WDAC/hora real sem aceite.** [Análise](validation/catalog-vm-948608e-network-baseline-failure-2026-11-04.json) preserva o resultado; limpeza reportou MSI0 e nenhum erro/controle próprio, mantendo14IDs CI externos. Coletor08 solicitado para conferir estado atual, ACK de liberação e distinguir DNS/conexão/HTTPS/execução individual como SYSTEM. Host obteve HTTP200 no mesmo destino. Não restaurar o guest antes dos diagnósticos. Nenhum código, limite ou critério alterado para converter a falha em sucesso.

## Atualização — 04/11/2026: diagnóstico concluído; novo aceite pendente

[Revisão do coletor 06](validation/catalog-vm-d87d059-diagnostic-review-2026-11-04.json) confirmou ACK bruto de liberação v7 e limpeza independente, com preservação dos 14 IDs CI externos. Os seis XMLs próprios exportados conferem por tamanho/hash e reproduzem o contêiner kernel vazio já corrigido na fonte 948608e. A rodada d87d059 continua reprovada; o guest pode agora ser restaurado ao snapshot limpo, pois os dados necessários foram preservados e revisados. Nova rodada 948608e/0e93a06a pelo atalho 07 ainda não iniciada; exigir todos os critérios e 3600 segundos reais. Testes locais e preparação não substituem o aceite Windows.

## Estado vigente — 03/11/2026: 948608e validado localmente; VM pendente

[Validação e pacote](validation/catalog-vm-preparation-948608e-2026-11-03.json): **1452 Python, 251 Rust e 154 painel passaram**, além dos gates estáticos/build/release. Python teve 57 skips e quatro casos integrais de controles desmarcados no host. A tentativa Rust inicial teve uma falha no marcador do filho inerte antes do timeout de cinco segundos; a suíte completa serial passou sem alterar limites/asserts. Cobertura app/agente 88,88%; gates completos por módulo e PostgreSQL/Redis continuam pendentes.

Correção de três linhas omite somente o contêiner kernel vazio que violava o XSD Microsoft; preserva cenário 131, `ProductSigners`, hashes de usuário e validador original. TDD vermelho `5c6e966` com quatro falhas esperadas; implementação `948608e`. MSIs sem fault injection e ISO `OpenEMS-Catalog-948608e-0e93a06a.iso` conferidos. Run novo `0e93a06a306e493b9d1fe4975ce2aaf8`, atalho 07: **não iniciado e sem aceite de enforcement**.

Rodada d87d059/385b1eb0 permanece reprovada e preservada. Coletor 05 deu timeout; coletor 06 com checkpoints solicitado ao operador, ainda sem resultado recebido. Não restaurar o snapshot nem iniciar o 07 antes de conferir liberação/limpeza atuais e diagnósticos. Após revisão, repetir em snapshot limpo todos os oito critérios, ACK 90 s e hora real 3600 s. Escopo continua API real em processo com fixtures sintéticas e serviço Windows por backend local; servidor em rede/painel/PostgreSQL/Redis/frota/USB físico são validações separadas. Nenhum controle ou MSI executado no host.

## Resultado vigente — 03/11/2026: catálogo d87d059 reprovado

[Rodada original](validation/vm-catalog-d87d059-result-2026-11-03.json), run `385b1eb0f9304a6ebb308e0620215c6f`: app ausente e bloqueio/liberação de rede passaram; app presente não obteve ACK de sucesso em 90 s. **Sem aceite de processo, WDAC ou hora real.** [Análise e recibos](validation/catalog-vm-d87d059-failure-analysis-2026-11-03.json) preservam a falha; o validador independente recusou o relatório.

Limpeza reportou MSI 0, nenhum erro ou controle próprio restante e preservação dos 14 IDs CI externos. Coleta 05 pendente para conferir o ACK bruto de liberação, estado atual e causa da rejeição. Não restaurar o snapshot antes de revisar os diagnósticos. Nenhuma alteração de produto, prazo ou critério realizada nesta investigação. As seções seguintes registram estados anteriores.

## Estado vigente — 03/11/2026: correção local verde; aceite Windows pendente

[Pacote novo e evidências](validation/catalog-vm-preparation-d87d059-2026-11-03.json), fonte `d87d059`, run `385b1eb0f9304a6ebb308e0620215c6f`: **1451 Python, 251 Rust e 154 painel passaram**, além de fmt/Clippy/Ruff/lint/tipos/build/release. Python teve 57 skips e quatro casos integrais de controles desmarcados no host. Cobertura app/agente 88,88%; gates completos por módulo e integrações PostgreSQL/Redis continuam pendentes.

Normalização estrita dos dois cenários e transporte privado implementados após testes vermelhos commitados. Validador original preservado. MSIs 0.4.0/0.4.1 sem fault injection; dez arquivos da ISO e vinte arquivos legados conferidos por hash. ISO `OpenEMS-Catalog-d87d059-385b1eb0.iso`; atalho 04 preparado para guest descartável. Nenhum controle ou instalador executado no host.

**Nova rodada não iniciada e sem aceite de enforcement.** Snapshot limpo restaurado e guest no desktop; conectar a ISO nova e executar o atalho 04 manualmente. Manter ACK de 90 s, hora real de 3600 s, processo/rede/WDAC original e renomeado, remoção quando ausente, liberação e remoção normal do MSI com limpeza. Escopo: expansão pela API real em processo com fixtures sintéticas e serviço Windows na VM por backend local. Servidor em rede, painel, PostgreSQL/Redis, republicação por inventário de frota e USB físico são validações separadas. Falha `f15761c` preservada e reprovada; sua liberação e limpeza foram conferidas independentemente. As seções seguintes são históricas.

## TDD iniciado — 03/11/2026: adendo de transporte aguarda aprovação

O plano de normalização foi aprovado. Testes vermelhos commitados em `15d5fe0`: 95 casos no módulo, 29 novos; suíte Python permitida com **3 falhas esperadas, 1446 sucessos, 57 skips e quatro casos integrais de controles desmarcados**, sem falhas adicionais ([registro](validation/wdac-dual-scenario-red-2026-11-03.json)). Nenhum código de produto foi alterado.

A revisão detectou o limite do transporte nativo: o script atual vai por `-Command`, com apenas 1109 unidades UTF-16 livres na linha serializada. Uma sonda inerte acima do limite reproduziu `WinError 206` ([medição](validation/windows-control-transport-boundary-2026-11-03.json)). O teste mockado por `-File` não cobriria esse problema. O [plano recebeu adendo](docs/wdac-dual-scenario-hash-plan.md) para incluir somente `agent-rs/src/windows_control.rs` e seus testes internos: arquivo compilado temporário privado, JSON apenas por stdin, argumentos curtos, criação/handles/limpeza protegidos. Escopo ampliado aguarda aprovação antes de implementar. A falha original e a limpeza confirmada permanecem preservadas.

## Causa reproduzida — 03/11/2026: aprovação da correção pendente

[XML original](validation/vm-catalog-f15761c-owned-hash-policy-2026-11-03.xml), 4148 bytes/SHA-256 `24457a4c42a42d444809fb64820b126b1d639be6d93e5f3a314a2d9488fca36b`, e [reprodução isolada](validation/catalog-xml-rejection-reproduction-2026-11-03.json). O XML contém quatro hashes de usuário e quatro hashes kernel equivalentes, com IDs separados e todas as referências válidas. O validador original rejeita esse formato com `OPENEMS_INVALID_HASH_POLICY`; a reprodução usou somente a função extraída por AST, com zero mutações no host.

[Plano concreto aguardando aprovação](docs/wdac-dual-scenario-hash-plan.md): TDD primeiro; normalização somente do formato duplicado conhecido, preservando o escopo de usuário e a validação estrita; casos negativos; suítes completas permitidas; novo MSI/ISO e rodada limpa de uma hora. Altera quatro arquivos de produto/teste, fora do escopo anterior de três arquivos de aceite, e depende de aprovação explícita conforme o AGENTS.md. Nenhum código de produto nem teste novo foi alterado nesta investigação. Liberação v7 e limpeza atual já confirmadas; a rodada original permanece reprovada.

## Diagnóstico confirmado — 03/11/2026, coleta 02

[Coleta original](validation/vm-catalog-f15761c-diagnostics-2026-11-03.json) e [análise](validation/catalog-vm-diagnostic-analysis-2026-11-03.json): seis ACKs negativos da v5, sem erros do backend; liberação v7 com ACK positivo conferido. Estado atual confirma ausência de serviço/watchdog/NRPT/firewall próprio/diário/política própria e preservação dos 14 IDs CI externos. A rodada permanece reprovada.

Sete cópias privadas correspondem à fixture A. Os sete XMLs intermediários têm oito regras Deny e quatro referências UMCI; essa contagem viola a validação atual de hash. Ainda falta o XML exato para identificar a primeira rejeição e planejar a normalização sem aceitar regras ou referências extras. A documentação Microsoft admite oito hashes por cenários distintos, mas isso não comprova a estrutura deste XML local. Atalho `03 - Export owned hash XML as administrator.lnk` preparado: exporta só um arquivo de 4148 bytes com SHA-256 fixado. Preservar o guest até essa coleta. Código de produto e critérios intactos; correção aguarda diagnóstico completo e plano aprovado.

## Catálogo `if_present` — falha real de 03/11/2026

[Relatório original](validation/vm-catalog-f15761c-result-2026-11-03.json), fonte `f15761c`, MSI `7b514947…`: app ausente e bloqueio/liberação de rede passaram; a atribuição app presente v5 não obteve ACK de sucesso em 90 segundos. **Aceite completo reprovado nesta rodada:** processo, WDAC original/renomeado e hora real não foram concluídos. A causa ainda depende dos logs protegidos; não atribuir a timeout interno, ConfigCI ou produto sem evidência.

O relatório de limpeza registra MSI 0 e ausência de serviço/watchdog/NRPT/firewall/política própria/registro das fixtures, sem erros, preservando os 14 IDs CI externos. Coleta complementar preparada para conferir ACK bruto de liberação e estado atual. Preservar o guest até concluir o diagnóstico; nenhum código, prazo de ACK ou política foi alterado para converter o resultado em sucesso.

## Catálogo `if_present` — preparação de 02/11/2026, aceite pendente

[Pacote e validação local](validation/catalog-vm-preparation-f15761c-2026-11-02.json), fonte `f15761c`. MSIs 0.4.0/0.4.1 de produção preparados; dez arquivos da ISO conferidos por hash e atalho elevado validado. Python: 1420 passaram, 57 skips e quatro casos integrais de controles excluídos do host; Rust 237 e painel 154 passaram. Cobertura agregada app/agente 88,88%; gates completos por módulo e PostgreSQL/Redis permanecem pendentes.

**Nenhum aceite novo na VM foi iniciado.** Restaurar `clean-preflight-before-controls` UID 1, montar `OpenEMS-Catalog-f15761c-e667c411.iso` e executar o atalho `01 - Catalog acceptance as administrator.lnk` no guest. Exigir app ausente/presente, encerramento de processo, firewall por executável, recusa WDAC nativa do original/renomeado, remoção quando todas as regras faltam, rechecagem após 3600 segundos reais com atribuição estável, liberação e remoção normal do MSI sem sobras. O relatório ainda não existe; preparação e testes locais não aprovam o enforcement Windows.

A API real expande políticas em processo no host a partir de catálogo/inventário sintéticos de fixtures próprias. O serviço instalado na VM recebe essas políticas por backend local de homologação. Integração de rede com servidor real, painel, PostgreSQL/Redis e republicação por inventário de frota são rodadas separadas. Os resultados antigos abaixo continuam vinculados aos seus próprios bytes.

## Pendência imediata — 29/10/2026

**Rodada 40 avançou ao bloqueio, mas o roteiro falhou no código Windows:** [registro](validation/windows-controls-vm-959e9de-2026-10-29.json). V4 recebeu ACK; tentativa original native_error 4551/started=false/exit=-1. O SDK define 4551 como violação de política de integridade; Assert-ExecutionDenied só reconhece 577/1260. A falha do classificador é independente do agente. Não reclassificar aceite: rename/editor não chegaram a ser testados e a associação CI específica ainda não foi exportada. Release v5 e remoção normais passaram, serviço/watchdog/processos/NRPT/diários ausentes. [Plano TDD do roteiro](docs/windows-wdac-refusal-code-plan.md) apresentado e pendente de aprovação; nenhum código alterado ainda. Mesmos MSIs 959e9de serão reutilizados, com revisão do roteiro separada e coleta CI automática na próxima rodada completa.

**Novo pacote 959e9de preparado para aceite, sem liberação de produção.** Integração aprovada do catálogo privado somente para uma regra hash, com validações normais de assinatura/hash/XML e fallback preservados. TDD b26708b: 1 falha/58 sucessos; depois 59/59 verdes. [Validação](validation/windows-wdac-catalog-fix-2026-10-29.json): Python completo 1.159 passaram/1 timeout de inventário em 90 s/58 skips/quatro casos desmarcados; repetição isolada passou em 77,14 s. Não chamar a suíte completa de verde. Rust 225 e painel 102/fmt/Clippy/lint/typecheck/release passaram; Ruff global S603 preexistente e gates de cobertura por módulo pendentes (88,58% agregado).

[MSI/ISO congelados](validation/windows-wdac-catalog-package-2026-10-29.json), fonte 959e9de55ec365899086290b404c29ce1f791bb4, arquivos/versões 0.4.0–0.4.1 conferidos e sem fault injection. Agente dbf4d6d5…, principal 478531dc…, ISO openems-controls-fixed-959e9de.iso (a07dbf27…). Atalho ACCEPT-WDAC-40 requer snapshot limpo UID 2 e essa mídia exata. Operador já recebeu instruções. Resultado esperado fixed-959e9de/applications, ainda pendente. Só aceitar com ACK em 90 s e bloqueio real antes da execução/rename/publisher/liberação/remoção. Roteiro/limites intactos; nenhum controle instalado no host.

O pacote anterior 2100dd7 [falhou no ACK hash](validation/windows-controls-vm-2100dd7-2026-10-29.json), com carga CI tardia e cinco checks iniciais aprovados. Release/remoção normais e ausência de controles ativos confirmadas em SYSTEM. A [comparação 39](validation/vm-applications-fixed-2100dd7-catalog-comparison-2026-10-29.json) manteve oito critérios e 14 IDs CI, geração 2.663 ms/pipeline 8.225 ms, sem carregar política. Não confundir essa prova privada com o aceite novo. USB 918aba2 completo continua falho; limpeza 31 passou com ACK v7/MSI 0/PENMACK restaurado. Pendência não conta como aceite. Sem push/PR/merge/CI ou mudanças em TLS/AV.

### Histórico preservado da investigação

**WDAC comparativo ainda pendente:** [32 terminou em 81,4 s](validation/vm-applications-fixed-918aba2-userpes-comparison-2026-10-29.json) na geração/filtragem das regras, com coleção .NET encapsulada. [Prova sintética PS 5.1](validation/windows-powershell-collection-filter-probe-2026-10-29.json) mostra que o wrapper da sonda pode ocultar regras verdadeiras do filtro; a seleção atual de produção difere. Não atribuir esse resultado automaticamente ao produto nem marcar ausência real de regras UMCI sem enumerar seus elementos. Atalho 33 preparado para a mesma comparação com expansão explícita, sem mudar propriedades ou carregar política. A enumeração CI posterior não ocorreu no 32; igualdade dos IDs não foi verificada nessa rodada.

**Atualização: remoção verificada.** [Atalho 31](validation/vm-usb-fixed-918aba2-normal-removal-retry1-2026-10-29.json) confirmou liberação v7/ACK e MSI 0, sem forçar proteção. Serviço/watchdog/processos/NRPT gerenciado/diários ausentes; canário PENMACK passou leitura/escrita/exclusão. USB continua falho nos cenários restantes da rodada original; limpeza bem-sucedida não substitui aceite. A comparação WDAC já aprovada será retomada no snapshot de diagnóstico UID 3, sem instalar agente nem carregar política.

**Pausa solicitada pelo operador:** [atalho 30 falhou antes do MSI](validation/vm-usb-fixed-918aba2-normal-removal-2026-10-29.json). Não houve ACK de liberação; a proteção foi respeitada e não se tentou remover à força. Cache v4 ainda tem default USB block e uma regra; serviço permanece instalado apenas na VM. Remoção/USB/WDAC continuam sem aceite. Retomar quando o operador voltar; não restaurar o snapshot enquanto os dados necessários não estiverem preservados.

**USB 918aba2, repetição 1: falhou; remoção ainda pendente.** [Resultado original](validation/vm-usb-fixed-918aba2-retry1-2026-10-29.json) e [suplemento](validation/vm-usb-fixed-918aba2-retry1-supplement-2026-10-29.json). Passaram instalação/hash, bloqueio de armazenamento com HID saudável e reinício offline. Sem ACK da política seguinte v4 (allow selecionado por VID/PID/serial conforme a sequência do roteiro), nem da liberação v5 no finally. Serviço/watchdog/processos continuam na VM; não marcar limpeza ou aceite. Atalho 30 preparado para remoção pelo MSI normal após confirmação de liberação recebida, sem contornar proteção; aguardar seu relatório. Instância, somente leitura e restauração final continuam sem aceite desta fonte. WDAC continua pendente; snapshot de diagnóstico UID 3 preservado.

## Correção dos controles Windows — 28/10/2026

**Continuação em 29/10 — erro auxiliar identificado:** as sondas 24–26 não provaram travamento de WMI. O escritor JSON falhou em File.Replace no PS 5.1 e deixou os resultados finais no temporário ([recuperação](validation/vm-usb-fixed-918aba2-diagnostic-recovery-2026-10-28.json), [reprodução isolada](validation/windows-diagnostic-ipc-nullstring-2026-10-29.json)). Após corrigir apenas o coletor com NullString.Value, backend iniciou em 8.238 ms e respondeu HTTP 204. USB completo está em execução pelo atalho 29, mesmos MSI/harness/prazos, saída separada usb-retry1; três checks iniciais passaram. Resultado final e remoção ainda precisam ser confirmados. Não considerar a sonda ou checks parciais como aceite.

**USB 918aba2 ainda sem aceite:** [rodada falhou no backend local antes da instalação](validation/vm-usb-fixed-918aba2-backend-startup-failure-2026-10-28.json), zero checks. PENMACK correto em E:, todos os hashes conferidos, serviço/watchdog/NRPT/diários ausentes e canário USB posterior passou ([suplemento](validation/vm-usb-fixed-918aba2-supplement-2026-10-28.json)). As sondas auxiliares 24/25 pararam em consulta WMI antes de medir o backend. Sonda 26 separa essa consulta da medição de Start-Job/HTTP; sem alteração do harness, instalação ou política. Snapshot WDAC adicional UID 3 preserva a investigação anterior. Nenhuma dessas sondas substitui os cenários USB completos.

**Comparação UserPEs ainda pendente:** o [atalho 23](validation/vm-applications-fixed-918aba2-userpes-probe-timeout-2026-10-28.json) atingiu 120 s em `identify_fixture`, antes de ConfigCI, sem carregar política. A estratégia proposta não foi validada. O operador voltou a ter o PENMACK autorizado; a rodada USB com fonte `918aba2` pode seguir após preservar o estado WDAC em snapshot adicional e restaurar o snapshot limpo UID 2. Disponibilidade do hardware não conta como aceite.

**Diagnóstico da falha por hash:** [worker recuperado](validation/vm-applications-fixed-918aba2-generation-recovered-2026-10-28.json) parou em New-CIPolicyRule com OPENEMS_NO_USER_MODE_RULE após ~124 s. Importação e assinatura foram rápidas; nenhuma política foi carregada pelo diagnóstico e os 14 IDs CI permaneceram iguais. O controlador auxiliar falhou antes de impor seu limite; o resultado não conta como aceite. Nova estratégia de geração por amostra explícita ainda depende de aprovação, validação comparativa e TDD; prazos e critérios serão mantidos.

**Repetição mais recente, atalho 18:** [falhou no WDAC por hash](validation/vm-applications-fixed-918aba2-retry1-2026-10-28.json). HTTPS de referência e bloqueio/liberação de rede passaram. Política v4 recebeu ACK negativo; release v5 recebeu ACK de sucesso. Remoção do agente e ausência de serviço/watchdog/NRPT/diários confirmadas no [suplemento](validation/vm-applications-fixed-918aba2-retry1-supplement-2026-10-28.json). Diagnóstico somente de leitura do erro/CodeIntegrity pendente no atalho 19. Não atribuir causa específica nem aceitar hash/editor antes dessa investigação e de execução completa bem-sucedida.

**Última execução:** [Applications 918aba2 falhou antes do WDAC](validation/windows-controls-vm-918aba2-2026-10-28.json), por timeout da sonda HTTPS de referência. Instalação/inventário passaram e remoção foi verificada. Bloqueio WDAC ainda não foi exercitado nesta rodada. [Diagnóstico posterior como SYSTEM](validation/vm-applications-fixed-918aba2-network-diagnostic-2026-10-28.json) passou em todas as sondas com validação normal; o timeout não se reproduziu após remoção. Repetição em snapshot limpo preparada no atalho 18, mesmos bytes e critérios, saída separada applications-retry1. USB com esse pacote continua pendente do PENMACK autorizado. A falha original permanece registrada.

**Resultado atual:** [USB f1fb891 falhou](validation/vm-usb-fixed-f1fb891-2026-10-28.json) por falta de ACK v5; allow físico por serial passou e remoção/restauração do PENMACK foram verificadas. WDAC e aceite USB completo continuam pendentes. A incompatibilidade do digest do roteiro em PS 5.1 foi reproduzida; sua correção com TDD foi aprovada, mantendo validação e critérios. [Auditoria de invocação indevida do roteiro no host](validation/windows-controls-host-invocation-audit-2026-10-28.json): Plan/recusa ocorreram via pytest; sem aplicação de controles. Futuras execuções no host devem desmarcar esses quatro casos.

Quatro defeitos corrigidos em `fix/windows-control-adapters`: TDD em `787caab` (11 falhas/6 sucessos antes do produto), WDAC em `e31e2fe`, USB em `548584b`. Regressões 17/17, Rust 225/225 sem ignorados, Ruff, fmt e Clippy passaram. Painel 102/102, cobertura de linhas 95,17%. Suíte Python 3.14 com release: 1111 aprovados, 58 skips, 0 falhas, cobertura 88,58%; gate completo permanece pendente. Timeout anterior de inventário e tentativas de ambiente estão preservados no [registro](validation/windows-controls-fix-2026-10-28.json).

Par MSI novo 0.4.0/0.4.1 gerado da revisão `548584b2496fdd6872e8f7a2af7afe13304bad5c` e verificado por manifesto, hashes e ausência de fault injection ([recibo](validation/windows-controls-fixed-package-2026-10-28.json)). Pacotes v2 originais intactos. Isso não equivale a aceite na VM: nenhum novo MSI instalado, controle aplicado no host ou snapshot restaurado nesta etapa.

A correção adicional do serial foi aprovada e concluída com TDD: testes `3adaeea`, produto `f1fb891`, 27/27 regressões; Rust 225/225. WMI malformado mantém a identidade PnP válida. Suíte completa final: 1121 aprovados, 0 falhas, 58 skips, cobertura 88.58%; pendências de cobertura/integração preservadas.

Pacote final separado da revisão `f1fb89192c003cec457230cc507873f9837435ad`: [recibo de MSI, executáveis e ISO](validation/windows-controls-serial-fixed-package-2026-10-28.json). O pacote anterior de quatro correções e o v2 não foram substituídos. **USB físico e Applications/WDAC permanecem pendentes**, exigindo snapshot limpo UID 2 antes de cada fase. A ISO e os atalhos novos estão preparados. O operador confirmou a restauração do snapshot UID 2; a execução USB ainda aguarda mídia/PENMACK. Nenhum controle foi executado no host. [Estado da nova rodada](validation/windows-controls-vm-reacceptance-2026-10-28.json).

## Tabela de domínios — validação local de 29/10/2026

[Relatório](validation/domain-rules-table-2026-10-29.json): tabela ordenada, Simples/Wildcard, Permitir/Bloquear/Monitorar, importação CSV com prévia, exportação, busca e paginação implementados na branch separada `feature/domain-rules-table`. Primeira regra correspondente precede categorias e horários; migração conserva as permissões antigas antes dos bloqueios. Passaram 139 testes do painel, cinco cenários em Chromium com API real e 228 testes Rust; fmt/Clippy/lint/TypeScript/build passaram. A suíte Python completa e Ruff global têm pendências descritas no relatório. Isso não é aceite DNS físico de um novo agente: nenhum MSI da feature foi gerado/instalado e os pacotes Windows de aceite permanecem intactos. [Contrato, CSV e limites](docs/ordered-domain-rules.md).

## Segunda máquina física — rodada de 27–28/10/2026

[Evidência sanitizada](validation/second-machine-browsers-2026-10-28.json), main fixada em `5ba6be67c10237c9015ff1098258494039093f8b`, MSI v2 da origem `18cd811`. Integridade do ZIP e 21 arquivos do recibo aprovada; servidor Docker, migrações 001–008, listas de homologação e política WebActions v1 preparados. Baseline elevado coletado sem agente existente. Parte A aprovada; aceite global parcial por pendência da Parte B.

**Parte A aprovada na instalação válida:** hash esperado, convite consumido/removido e ACK v1 confirmados. Sondas DNS, eventos esperados sem evento IETF, Chrome 156.0.8078.48/Firefox 158.0.1 físicos em perfis novos e painel/teclado/foco/tema passaram; observações dos navegadores e legibilidade/foco confirmadas pelo operador. YouTube passou nos dois: página aberta sem reprodução com CDN bloqueado (ACK v2 e eventos reais googlevideo.com), reprodução por pelo menos 10 s com CDN liberado (ACK v3). Duas tentativas anteriores inválidas e suas remoções pelo MSI permanecem registradas; não foram convertidas em sucesso.

Remoção autorizada por liberação assinada recebida às 00:37:25; MSI terminou com código 0 às 00:38:00. Ausência de serviço, watchdog, processos e NRPT; DNS público voltou, configurações DNS e políticas dos navegadores iguais ao baseline. O hosts perdeu apenas um bloco OpenEMS antigo já presente no baseline, preservando byte a byte as entradas externas; hash total não é igual ao inicial e o backup original está preservado. Servidor de homologação encerrado sem remover volumes nem afetar outros projetos. Nenhuma alteração no código, CI, certificados ou proteção antivírus; sem push/merge.

**Parte B não aprovada:** VM descartável, snapshot limpo UID 2 e passthrough PENMACK verificados. USB físico executado exclusivamente no guest em 28/10, 12:18:33–12:21:26: **falhou** por ausência de ACK de sucesso da política após instalação/inventário aprovados ([JSON original](validation/vm-usb-2026-10-28.json)). Sem erros de limpeza no harness. Diagnóstico independente confirmou ACK de liberação v3 e ausência de serviço/watchdog/processos/NRPT/diário USB. Após reconexão normal do Alcor Micro pelo VMware, PENMACK voltou em E: (PnP OK, não somente leitura/offline) e o canário de leitura/escrita/remoção passou, com limpeza verificada ([antes](validation/vm-usb-diagnostics-before-reconnect-2026-10-28.json), [depois](validation/vm-usb-diagnostics-after-reconnect-2026-10-28.json)). Causa da falha da política v2 (seis ACKs `LocalError`) não determinada. Applications/WDAC executado no guest após restaurar o snapshot UID 2, em 28/10, 13:21–13:26: **falhou** ([JSON](validation/vm-applications-2026-10-28.json)). Instalação, inventário e bloqueio/liberação de rede por aplicativo passaram; a política WDAC por hash não recebeu ACK de sucesso. O ACK e o `agent.log` registram só `LocalError`, porque o adaptador PowerShell descarta a mensagem; causa em investigação. Nenhum controle executado no host, nenhuma alteração no código/MSI/roteiro. Falha e pendência não contam como aceite.

Continuação de 28/10 pela manhã: usuário autorizou criar a VM e baixar a ISO. [Provisionamento](validation/vm-provisioning-2026-10-28.json): ISO oficial baixada e SHA-256 conferido contra a Microsoft; configuração VMware corrigida e criptografia/TPM conferidos. Windows instalado com conta local e VMware Tools instalado/atual confirmado após reinício. Watermark do guest indica build 26100, apesar do rótulo 26H2 no nome da ISO; versão efetiva e capacidades serão verificadas no guest. Snapshot `clean-win11-tools-before-controls` existe no VMSD/arquivo de estado, mas o operador esclareceu que foi capturado com Windows Setup aberto: não comprova baseline limpo. Setup fechado sem concluir instalação, conforme operador. Aguarda reinício/preflight do guest, nova montagem da mídia de dados e novo snapshot verificado antes de controles; USB/WDAC não iniciados. Isso não altera o resultado da Parte A.

Preflight do guest em 28/10 às 12:08:37 ([relatório](validation/vm-preflight-2026-10-28.json)): versão efetiva 10.0.26300/build 26300 por CIM, CiTool/ConfigCI disponíveis, sem agente, Setup aberto ou reinício pendente nas chaves consultadas. Substitui a observação visual anterior de build 26100. Novo snapshot `clean-preflight-before-controls` criado após montar a mídia de testes, confirmado pelo operador e verificado no VMSD/arquivo de estado (UID 2). PENMACK E: identificado como Generic Flash Disk USB de ~4 GB no host; aguarda passthrough e identificação dentro do guest. Nenhum controle USB/WDAC executado ainda.

## Ações web — entrega de 27/10/2026

Permitir/Bloquear/Monitorar usa [matriz de aceite própria](docs/web-filter-actions-acceptance.md). O build desta entrega é preparado separadamente em `.venv/web-actions-acceptance/`, preservando os pacotes e resultados anteriores. Os quatro roteiros abaixo continuam como regressões de sessão/locais/controles; não substituem o aceite das ações web nem dos navegadores.

```powershell
.venv\Scripts\python.exe tools\build_final_acceptance.py --output .venv/web-actions-acceptance
```

Use o manifesto dessa pasta para identificar a revisão e os hashes. Compilar e gerar os MSIs não equivale a executar a nova rodada de aceites; resultados de 26/10 só valem para seus próprios bytes.

**Resultado de 27/10/2026** ([evidência](validation/web-actions-guest-2026-10-27.json)): três Sandboxes novos com o MSI `20e9d24e…` e o agente `5290604d…`, servidor/painel da `main` e migração 008 aplicada. A matriz prioritária passou: Permitir, Bloquear, Monitorar, monitoramento geral, exceções, precedência, horários, categoria ausente e digest inválido. Também passaram a sonda DNS e Chrome/Firefox com perfis novos. Netflix passou só em DNS. Na continuação do mesmo dia ([evidência](validation/web-actions-followup-2026-10-27.json)) passaram: reinício offline com cache completo e incompleto, token expirado/reenrollment, retry do mesmo lote, fila saturada, seletor por teclado e modo escuro. O YouTube, sem conta, substituiu a Netflix e passou no Chrome e no Firefox: o vídeo trava com o CDN bloqueado e toca com ele liberado. O aviso de listas desatualizadas também passou. Fica **pendente** só o aceite no Windows físico e em VM com USB/WDAC ([roteiro da segunda máquina](docs/second-machine-acceptance.md)). Depois da revisão de segurança, o agente passou a remover o convite usado do `agent.json`. O **MSI v2** (`762c931a…`, revisão `18cd811`) passou na regressão em Sandbox novo ([evidência](validation/msi-v2-regression-2026-10-27.json)) e é o que a segunda máquina deve validar. As falhas de harness das rodadas 1 e 2 estão registradas. No Sandbox, o DNS upstream é o resolvedor do host: não use domínios que o agente do host bloqueia (`example.com`) e trate respostas loopback como não atribuíveis.

## Rodada anterior

Estado inicial: **pendente**. Testes locais, compilação, inspeção de MSI e geração de pacote não equivalem a um aceite no sistema operacional. A F9 continua fora do escopo. O estado de implementação de cada fase está em `HANDOFF.md`.

Rodada real concluída em **26/10/2026**, com os pacotes/manifestos `779b483`: sessão passou nas duas fases, com reboot real; locais passou 8/8. USB passou nos quatro checks automatizados e aplicativos nos seis checks de inventário/rede/limpeza. Permanecem pendentes o USB físico e o bloqueio antes da execução por WDAC em VM compatível. Ambos retornam `manual_required`, com `automation_passed: true`, sem erros de limpeza. O consolidado e os relatórios finais estão em `validation/`; os pacotes atuais já foram preparados.

## Preparar uma única versão para todos os testes

No repositório, depois de concluir e commitar o código nativo:

```powershell
.venv\Scripts\python.exe tools\build_final_acceptance.py
```

O comando compila o release, gera os MSIs de produção atual e de upgrade e copia **os mesmos bytes** para os quatro pacotes pendentes. Não inicia Sandbox nem instala nada. Recusa fontes nativas ainda não commitadas. Os manifestos guardam o commit e o SHA-256 dos pacotes e roteiros; os launchers recusam arquivos modificados. Refaça a preparação se alterar código ou roteiro. Não misture MSIs de rodadas diferentes.

Os perfis ficam em `.venv/sandbox-acceptance/`; entradas são mapeadas só para leitura em `C:\openems-input`, e os relatórios voltam para `.venv/sandbox-acceptance/results`. Feche um Sandbox antes de abrir o seguinte. Use sempre um **Sandbox novo** para cada linha abaixo.

| Ordem | Perfil | Comando em Win+R dentro do Sandbox | O que precisa passar | Relatório |
|---|---|---|---|---|
| 1 | `session.wsb` | `C:\openems-input\RUN-SESSION-TEST.cmd` | Ícone por sessão, reabertura se encerrado, aviso de app fechado, upgrade sem reboot. Reinicie **o Sandbox por dentro** quando solicitado e rode o mesmo comando novamente: watchdog recupera serviço desativado no registro, componente retorna e desinstalação o fecha. | `session-phase1.json`, `session-result.json` |
| 2 | `locations.wsb` | `C:\openems-input\RUN-LOCATIONS-TEST.cmd` | Política interna por CIDR + MAC reais; mesma faixa com outro gateway volta à externa; ACK e avisos corretos; reinício offline dentro e fora; remoção restaura DNS/hosts. | `locations-result.json` |
| 3 | `usb.wsb` | `C:\openems-input\RUN-USB-TEST.cmd` | Instalação, inventário, regra de armazenamento sem afetar HID, cache no reinício offline, remoção. **Não aceita USB físico**: sem dispositivo adequado retorna `automation_passed: true`, `physical_acceptance_pending: true`, `passed: false`. | `usb-result.json` |
| 4 | `applications.wsb` | `C:\openems-input\RUN-APPLICATIONS-TEST.cmd` | Inventário de processo real com hash; app bloqueado na rede ainda inicia, mas não conecta, enquanto cópia de controle conecta; WDAC recusa original e cópia renomeada por hash e por um editor de teste exclusivo; liberação e remoção preservam políticas/regras anteriores. | `applications-result.json` |

A fase de aplicativos precisa de Internet para `https://example.org/`; a conectividade das duas cópias é verificada antes do bloqueio. O teste de rede usa destino externo porque bloquear loopback não prova uma regra de Firewall por aplicativo. A sonda escreve um arquivo antes de conectar, permitindo separar "processo impedido de abrir" de "processo abriu, conexão recusada".

O editor usado no teste WDAC é um certificado de assinatura exclusivo, criado e confiado **somente dentro do guest**, e removido ao terminar. Nunca se nega o editor da Microsoft ou outro editor compartilhado pelo sistema. O teste por hash exige recusa do Windows antes que o executável escreva seu primeiro arquivo; encerrar um processo depois de aberto não conta.

CiTool e ConfigCI precisam existir no guest. CiTool vem com Windows 11 22H2 e Windows Server 2025; a remoção de política unsigned sem reboot exige Windows 11 24H2 ou posterior. Ausência de recurso, ACK recusado ou reboot pendente **não são aprovação**. Nesse caso, repita em uma VM descartável com versão suportada, preservando o relatório e o `agent.log`, e só aceite depois de confirmar aplicação, execução bloqueada e remoção após o reboot necessário. Fontes: [CiTool](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/operations/citool-commands), [remoção de políticas](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/deployment/disable-wdac-policies).

Os roteiros gravam evidência parcial a cada etapa. `status: failed`, `cleanup_errors` preenchido, tempo esgotado ou serviço instalado ao final impedem o aceite. Não repita uma rodada no mesmo Sandbox: preserve os JSONs e descarte esse guest.

Para repetir aplicativos em uma VM Windows descartável com CiTool funcionando, copie `applications-input` para `C:\openems-input` dentro da VM. Em PowerShell elevado, crie a mesma atestação de VM usada pelo roteiro USB e execute diretamente o roteiro de controles (o launcher de Sandbox não se aplica à VM):

```powershell
Set-Content -LiteralPath C:\openems-disposable-vm.txt -Value 'OPENEMS DISPOSABLE USB ACCEPTANCE' -Encoding ASCII
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\openems-input\test-controls-sandbox.ps1 -Kind Applications -DisposableVm -OutputDirectory C:\openems-results
```

A atestação é compartilhada pelos dois roteiros; aplicativos não exige pendrive. O teste ainda verifica modelo virtual e hipervisor. Preserve `applications-result.json` e confirme limpeza antes de descartar o guest.

Sessão e locais agora exportam os logs MSI e `agent.log` automaticamente para subpastas `results/session-diagnostics-*` e `results/locations-diagnostics-*`, inclusive em falha. Depois de terminar o CMD, confirme que a pasta apareceu no projeto antes de descartar o guest. Se aparecer aviso de falha ao exportar, mantenha o Sandbox aberto para recuperar os logs. A primeira rodada retornou MSI 1603; a reprodução com logs identificou DLL de runtime ausente (`vcruntime140.dll`, `0xC0000135`). O build foi corrigido para carregar a configuração de runtime estático também quando iniciado na raiz. Use somente os pacotes reconstruídos após essa correção.

USB não exige enumeração de Code Integrity. No roteiro de aplicativos, enumeração WDAC indisponível deixa execução pendente e permite continuar o teste de rede; não constitui aceite de WDAC nem dispensa a VM suportada.

## USB físico: VM Windows com passthrough

Uma pasta compartilhada não é um pendrive. A [configuração documentada do Sandbox](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file) não oferece um parâmetro de passthrough de armazenamento USB. Use uma VM Windows descartável com snapshot limpo e o pendrive de teste redirecionado para ela. Conecte somente dispositivos de teste; os dados físicos do pendrive não são revertidos pelo snapshot da VM.

1. Copie a pasta `usb-input` final para `C:\openems-input` **dentro da VM** e conecte um pendrive dispensável com VID, PID e serial reportáveis. Verifique sua letra, por exemplo `E:`. Não use disco de boot/sistema.
2. Confirme que o modelo da máquina é virtual e crie, dentro desse guest, a atestação explícita:

   ```powershell
   Set-Content -LiteralPath C:\openems-disposable-vm.txt -Value 'OPENEMS DISPOSABLE USB ACCEPTANCE' -Encoding ASCII
   ```

3. Em PowerShell elevado **na VM**, execute, substituindo somente a letra correta:

   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\openems-input\test-controls-sandbox.ps1 -Kind USB -DisposableVm -PhysicalDrive E: -OutputDirectory C:\openems-results
   ```

4. O roteiro valida hipervisor/modelo virtual + atestação, sobe sua tarefa SYSTEM e recusa disco que não seja USB ou que seja de boot/sistema. Cria e remove somente seu próprio arquivo canário. Deve comprovar: exceção por VID/PID/serial, bloqueio por instância, leitura permitida e gravação recusada em somente leitura, evento no servidor, liberação e remoção. Reinsira o pendrive quando necessário para a liberação; acompanhe o andamento do JSON.
5. Preserve `C:\openems-results\usb-result.json`. Só esta rodada física pode retirar `physical_acceptance_pending`; a automação do Sandbox continua sendo apenas uma parte do aceite. Usando o pacote final intacto, o próprio roteiro confere o manifesto e inclui o recibo da versão no relatório. Após revisar o resultado físico, copie esse JSON intacto para a pasta de resultados, preservando também o relatório anterior do Sandbox com outro nome. Se a limpeza falhar, libere a política no guest e confirme acesso/gravação antes de reconectar o pendrive ao host. Não trate o descarte da VM como prova de restauração do dispositivo físico.

O controle atual decide por ciclos de inventário/aplicação em modo usuário. O teste não demonstra proteção de kernel antes da primeira montagem; esse limite precisa constar da decisão de implantação.

## Painel e servidor real

Além dos roteiros Windows, use um ambiente de homologação com PostgreSQL/Redis e pelo menos um agente dessa versão. Os testes MSW não substituem este fluxo:

- Entrar como administrador e como leitor; leitor consulta, mas não publica políticas nem muda cadastros. Sessão expirada mostra login/erro adequado; ações usam CSRF.
- Publicar perfis de web, aplicativos e USB; conferir digest/versão e ACK real. Atualizar só uma seção deve preservar as outras. Categorias, listas permitidas, curingas, horários e SafeSearch devem chegar ao agente com suas advertências de capacidade.
- Exercitar grupos/regras, convites, auditoria, administração e configuração/instalador conforme as funções implementadas. Conferir inventários e eventos reais nas fichas, sem credenciais em tela/log de auditoria.
- Navegar por teclado, inclusive formulários e diálogos; alternar modo escuro e recarregar. Conferir que as funções migradas não dependem do console antigo.
- Repetir HTTP/HTTPS, SafeSearch, categorias e antiburla com a versão final. Os aceites históricos de F2 pertencem aos binários anteriores. Chrome/Firefox em uma segunda máquina física e a assinatura de código continuam sendo aceites externos quando ainda não houver evidência.

## Linux: VM descartável própria

Windows Sandbox não valida systemd, systemd-resolved, USBGuard ou fapolicyd. Compile agente e helper como ELF Linux compatíveis e gere DEB/RPM conforme `deploy/linux/SUPPORT.md`; RPM exige `rpmbuild`. Use uma VM com snapshot e instale somente o pacote apropriado à arquitetura/distribuição. Um build em contêiner sem privilégios valida compilação/empacotamento, não enforcement real.

Os artefatos locais desta rodada ficam em `.venv/linux-build/packages/`, com manifestos SHA-256. Foram compilados em Debian 13 amd64; comece o aceite DEB nessa distribuição. Para outra distribuição, confira a compatibilidade de glibc ou recompile no ambiente correspondente. A geração do RPM não demonstra compatibilidade com todas as versões de Fedora/RHEL.

Exemplo DEB dentro da VM, com perfil de homologação previamente publicado:

```bash
sudo dpkg -i ./openems-agent_0.5.0_amd64.deb
read -r -s -p 'Convite de homologação: ' OPENEMS_INVITATION
export OPENEMS_INVITATION
sudo --preserve-env=OPENEMS_INVITATION /usr/bin/openems-agent configure \
  --server https://SEU-SERVIDOR --devid linux-acceptance \
  --config-path /etc/openems/agent.json --dns-filter
unset OPENEMS_INVITATION
sudo systemctl enable --now openems-agent.service
sudo systemctl status openems-agent.service
```

Conferir cadastro/ACK, DNS bloqueado/permitido pelo sistema, cache e restart após reboot, transição de local offline e restauração de DNS ao parar/falhar o serviço. Com USB passthrough, testar allow/block e HID. Com fapolicyd configurado conforme `SUPPORT.md`, negar executável dispensável por hash, renomear, confirmar recusa e liberar. Remover o pacote e comprovar que só os trechos gerenciados desapareceram, políticas externas ficaram e estado privado foi preservado. Um trecho gerenciado alterado fora do agente deve impedir limpeza destrutiva e manter o journal de recuperação.

Aceitar explicitamente os limites atuais: NetworkManager sem systemd-resolved, USB somente leitura/instância Windows e políticas de app por editor/nome/rede não devem receber ACK de sucesso como se fossem implementadas. Não habilitar opções Windows de CA HTTPS/WFP/browser como se fossem recursos Linux.

## macOS: compatibilidade e itens externos

`deploy/macos/SUPPORT.md` descreve o pacote de compatibilidade e os pré-requisitos de assinatura. O pacote exige um binário Mach-O assinado, Developer ID Installer, notarização e aceite em Mac. Testar launchd, cadastro/ACK, cache após reboot, bloqueio explícito por hosts, fallback por nome de processo, liberação e limpeza.

**Network Extension para DNS e Endpoint Security para USB/apps ainda precisam de implementação nativa, entitlements e validação em Mac.** Não marcar a F8 completa nem inferir esses recursos a partir de launchd/pacote/compilação. O modo de compatibilidade não satisfaz o aceite completo dessas extensões.

## Consolidar evidências

Depois dos Sandboxes, execute no repositório:

```powershell
.venv\Scripts\python.exe tools\build_final_acceptance.py --summarize .venv\sandbox-acceptance\results
```

O resumo só aceita relatórios da versão atual com `passed: true`, sem hardware pendente. Ausência, JSON parcial, recibo de outra compilação, falha ou limpeza incompleta permanecem pendentes/falhos. O resultado físico da VM deve ser preservado e revisado; substitua o relatório USB consolidado apenas pelo JSON real da rodada física, mantendo a evidência anterior, nunca por um arquivo editado para mudar `passed`. Mantenha também os registros de homologação do painel, da VM Linux e do Mac. O CI fica para a rodada final combinada com o usuário; este roteiro não o dispara.
