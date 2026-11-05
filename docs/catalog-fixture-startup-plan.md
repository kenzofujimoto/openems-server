# Evidências de inicialização das sondas do catálogo

Estado proposto para aprovação. A coleta 14 e a rodada 13 foram preservadas. A rodada continua reprovada.

## Evidência e limite do diagnóstico

A rodada a6c27d86 em b6d4be5 recebeu ACK positivo da política de rede v3. O roteiro expirou enquanto esperava o encerramento ou o marcador de uma das duas sondas, antes de publicar v4. O relatório v2 confirmou limpeza normal e preservação das 482 regras externas de firewall.

A coleta 14 encontrou dois marcadores das sondas de referência e um às 12:58:02 UTC sob v3. Os quatro executáveis conferem com o manifesto. Os registros consultados não associam o terceiro marcador a um PID ou papel da sonda. Ele pode ter vindo da primeira sonda antes da segunda falhar ou ter sido gravado após a última leitura. O intervalo de aproximadamente 208 s desde o ACK inclui a enumeração do firewall e não mede o início da sonda. Na rodada anterior aprovada em rede, o intervalo entre ACK v3 e v4 foi de aproximadamente 236 s.

O laço atual consulta o predicado somente enquanto o cronômetro está abaixo do prazo. Um ensaio inerte com prazo de 1 s, marcador lógico pronto aos 300 ms e pausa de 1.150 ms perdeu a amostra e expirou. Outro ensaio observou que um predicado lento pode retornar sucesso após ultrapassar o prazo. Isso demonstra a limitação da observação, sem atribuir a ela a falha real ou o LocalError anterior sob v2.

## Escopo

- deploy/test-catalog-sandbox.ps1 recebe evidência por sonda e um controle de prazo específico para a leitura do marcador.
- tests/test_catalog_sandbox.py recebe regressões por AST e fronteiras mockadas. Serviços, MSI, executáveis reais e controles de endpoint ficam restritos à VM.

As evidências novas são dados diagnósticos no relatório v2. Os oito critérios, a sequência das políticas, o verificador existente, o prazo de ACK de 90 s, a hora real e o timeout de 5.400 s continuam aplicáveis.

## Sequência

1. Escrever regressões vermelhas para distinguir alvo e controle, vincular o identificador do marcador ao PID e preservar diagnóstico em falha nativa, timeout ou consulta indisponível. Cobrir início no prazo, pausa que perde a amostra e predicado que só termina após o prazo.
2. Rodar a suíte completa permitida e commitar as falhas esperadas antes de implementar.
3. Registrar, para as chamadas de Invoke-Fixture, fase, papel, marcador, início da criação, PID quando disponível, retorno nativo e relógios UTC e monotônico. Medir separadamente o tempo de Process.Start, a espera pelo marcador, o encerramento e a enumeração dos filtros de rede.
4. Manter a janela de 10 s após o retorno do handle. Registrar o último estado no prazo e o resultado de uma leitura diagnóstica terminal, se disponível. Um marcador encontrado depois do prazo permanece evidência diagnóstica. O critério de início exige uma observação concluída dentro da janela.
5. Preservar as observações no relatório final e manter a liberação/limpeza mesmo se uma leitura diagnóstica falhar. Qualquer persistência de progresso deve ficar fora da janela medida e reaproveitar o exportador atual.
6. Rodar a suíte completa e o parser PS5.1, conferir o diff e commitar. Preparar mídia e recibo novos depois do verde.
7. Restaurar snapshot limpo e rodar o aceite integral. A execução pode seguir para a hora real quando concluir rede, processo e WDAC. Em nova falha, examinar a sonda e a etapa registradas antes de propor outra alteração.

## Riscos e critérios

- Dados UTC ajudam a correlacionar eventos. O cronômetro monotônico decide o prazo.
- Marcadores tardios e ausência de logs podem ter várias causas. Registrar falhas de leitura e evitar inferir causa pela categoria do ACK ou pela diferença entre horários de etapas.
- Preservar o resultado observado do lançamento nativo, os limites de 10 s e 15 s das sondas e os efeitos exigidos. Um marcador tardio, saída antes do início ou falha de coleta não pode virar uma observação de início válida.
- Exportar apenas identificadores do teste, metadados de processo e categorias seguras. A coleta não precisa de stdout, comandos de processos alheios, configuração ou credenciais.
