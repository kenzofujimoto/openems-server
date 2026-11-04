# Correção do isolamento da referência de rede no aceite do catálogo

## Escopo e autorização

Continuação do roteiro de catálogo já aprovado com TDD: somente `tests/test_catalog_sandbox.py` e `deploy/test-catalog-sandbox.ps1`, ambos no escopo original de três arquivos. Não altera o produto, o builder, regras expandidas, prazos ou critérios. Evidências e handoff serão atualizados. As aprovações anteriores permanecem válidas; esta manutenção corrige a execução do roteiro existente.

## Evidência

Rodada 948608e/run0e93a06a falhou na referência HTTPS antes de publicar a política de rede. A política `absent` v2 contém `app_control.blocked = ['openems-catalog-a.exe']`. O roteiro executa o original e a cópia renomeada nessa política; o runtime encerra processos por nome independentemente de descobrir uma amostra WDAC opcional. O log registra `terminated openems-catalog-a.exe` às14:26:29Z, dentro desse intervalo.

Coleta08 posterior confirmou DNS/TCP/HTTPS200 e ambos os EXEs com exit0 após remoção, além de ACK bruto de liberação, limpeza e preservação de14IDs CI externos. Os códigos individuais da falha original não foram retidos; a interferência do roteiro está comprovada, mas não se atribui exclusivamente a ela todo o erro HTTPS sem essa observação.

## Sequência TDD

1. Adicionar regressão que use políticas expandidas pela API real em processo e execute somente os statements de orquestração selecionados por AST. MSI/backend/ACKs/probes serão fronteiras mockadas; nenhum top-level do roteiro, serviço, fixture PE ou controle roda no host. A simulação de enforcement por nome deve reprovar o fluxo atual, e um controle negativo deve continuar rejeitando uma política inicial adulterada.
2. Rodar a suíte Python completa permitida, mantendo serviço/MSI desabilitados e quatro casos integrais legados de controles desmarcados. Commitar o vermelho antes da implementação.
3. Mover somente as duas verificações HTTPS de referência e sua inicialização para depois do ACK de `allow` v1, antes de publicar `absent` v2. Preservar o check de app ausente, a política de rede v3 sem bloqueio de processo, sua liberação v4, processo/WDAC v5 e rechecagem real v6; a ordem dos oito checks permanece igual.
4. Rodar novamente a suíte completa e gates pertinentes, commitar a correção e preparar pacote/ISO separados com recibos corretos. Não atribuir sucesso à rodada antiga nem substituir seus bytes.
5. Somente com limpeza revisada, restaurar snapshot limpo e repetir todos os critérios na VM. Manter ACK90s, rechecagem3600s reais, timeout5400s, HTTPS com validação normal, encerramento de processo, bloqueio por executável, recusa WDAC original/renomeado, liberação e remoção normais.

## Riscos e verificações

- A referência deve ocorrer depois do ACK de uma política sem processo, execução ou rede bloqueados; não basta executar rapidamente para evitar o próximo tick.
- O teste por AST deve aceitar somente comandos mockados conhecidos e rejeitar chamadas nativas/métodos inesperados antes de executar os statements. Nunca executar o top-level/finally de aceite no host.
- A referência precisa observar os dois caminhos. O controle negativo impede passar se a política inicial for substituída por uma política restritiva.
- Não aumentar prazos, aceitar exit de processo encerrado como falha de rede legítima, remover testes de firewall, modificar TLS ou relaxar validação. Cobertura/integrações globais pendentes permanecem explícitas.
