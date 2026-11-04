# Persistência das evidências de limpeza do aceite do catálogo

Estado: plano proposto, sem implementação. Aguardar aprovação explícita antes de alterar os três arquivos de código/teste. Coleta 12 ainda pendente; preservar a VM e não iniciar outra rodada.

## Problema observado

A rodada fonte 5e71292/run eb8486c4 concluiu sete checks, inclusive uma hora real e liberação, mas terminou reprovada com “An unrelated firewall rule changed.” A guarda mantém o baseline apenas em memória e lança antes de construir o check de limpeza. O relatório não identifica a regra divergente nem registra o estado final dos demais controles.

A coleta 10 confirmou posteriormente remoção MSI com retorno zero, ausência dos controles próprios e preservação dos 14 IDs CI externos. Não encontrou eventos de alteração do firewall; 483 regras atuais têm nomes únicos. A mudança original continua sem causa identificada e a rodada permanece reprovada.

Quatro ACKs negativos da v6 mostram falhas locais de enforcement. O backend da fixture descartou a categoria do erro. A coleta 11 não serve para concluir ausência de falhas: seu filtro estava incorreto. O filtro corrigido do coletor 12 foi verificado com 12 casos sintéticos em Windows PowerShell 5.1; seu resultado ainda precisa ser analisado.

## Escopo

Somente os três arquivos do roteiro original:

- tests/test_catalog_sandbox.py: regressões com dados inertes e fronteiras mockadas.
- deploy/test-catalog-sandbox.ps1: persistência de snapshots/diferenças, coleta completa da limpeza e retenção restrita da categoria de erro recebida no ACK.
- tools/build_catalog_acceptance.py: versão do contrato de evidência e validação independente dos novos dados.

Produto nativo e adaptadores de controle ficam fora deste plano. Se os logs indicarem correção no produto, elaborar plano específico com TDD antes de alterar seu código. Este plano não explica nem corrige por suposição a mudança de firewall.

## Sequência

1. Rever a coleta 12 e preservar seus bytes; distinguir falha do coletor, categoria local conhecida e causa demonstrada. Atualizar este plano se os dados exigirem outro escopo.
2. Escrever regressões vermelhas para baseline/snapshot final persistidos; regra removida, modificada ou com nome duplicado provoca reprovação com diferença identificável; estado sem alterações passa; falha da guarda não impede registrar os demais resultados de limpeza; evidência ausente ou adulterada é rejeitada pelo host.
3. Acrescentar regressão para retenção de “enforcement failed: categoria permitida” em ACK negativo, sem exportar mensagem arbitrária ou segredos. Erros não podem desaparecer nem se transformar em sucesso.
4. Rodar a suíte Python completa permitida e commitar os testes no vermelho antes da implementação. Nenhum serviço, MSI, PE de fixture ou controle será executado no host.
5. Implementar o mínimo: persistir baseline antes da instalação; capturar estado final antes da guarda; registrar diferenças e resultados independentes da limpeza mesmo com reprovação. Falhas de consulta continuam explícitas e não significam ausência de controles.
6. Versionar o contrato de evidência da nova mídia. O host recalcula a preservação a partir dos snapshots e rejeita dados ausentes/inconsistentes; flags de sucesso do guest não bastam. Relatórios antigos permanecem na versão original, sem reclassificação.
7. Rodar a suíte completa e gates aplicáveis, revisar o diff e commitar a implementação. Repetir verificações somente se novas alterações/falhas justificarem.
8. Preparar nova mídia e recibos apenas após revisar os diagnósticos atuais e justificar nova rodada. Repetir o aceite integral em snapshot limpo; sucesso parcial anterior não substitui critérios da nova execução.

## Restrições e riscos

- Preservar a guarda atual: cada regra anterior deve ter exatamente um correspondente com o mesmo Name/Enabled/Direction/Action. Registrar adições sem mudar silenciosamente a semântica original.
- Não ignorar regras do Windows, desligar atualizações, aumentar prazos ou relaxar comparações para obter sucesso.
- Manter ACK de 90 segundos, espera real de 3600 segundos e timeout total de 5400 segundos.
- Snapshots não são transações do firewall. Registrar horário e falhas de leitura; inconsistência precisa continuar visível.
- Serializar escalares estáveis; testar enums CIM, tipos JSON, ordenação e formatos inválidos.
- Persistir somente metadados necessários das regras e categorias permitidas de erro; nenhuma configuração, credencial ou stderr bruto.
- Limpeza independente aprovada não prova retroativamente preservação do firewall externo.
- Backend/painel/PostgreSQL/Redis vivos, USB físico e gates globais de cobertura continuam fora deste aceite.

## Critério de conclusão

O roteiro preserva baseline, snapshot final, diferenças e estado de limpeza em sucesso e falha; o host verifica esses dados independentemente. Nova rodada só passa com todos os oito critérios originais e evidências completas. A fonte 5e71292 permanece reprovada.
