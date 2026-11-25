# Diagnóstico de falhas locais durante a rechecagem

Plano proposto para aprovação. O aceite do catálogo na VM e a integração com painel, dois workers HTTP, PostgreSQL e Redis passaram. As causas específicas dos cinco ACKs negativos da rodada 15 continuam abertas.

## Evidência

Os três OSError da v6 foram seguidos de ACK positivo para a mesma atribuição. Os dois LocalError ocorreram perto da rechecagem horária, com liberação v7 positiva posteriormente. A evidência nativa mostra recusa WDAC 4551 do executável renomeado, seguida de liberação e remoção normais. Esses dados confirmam os efeitos observados e não identificam a operação que falhou em cada ciclo.

O runtime agrega validação, aplicação dos controles, outras operações locais e gravação do estado. A falha enviada no ACK retém a categoria retornada por AgentError.kind. Uma falha de I/O no script temporário, no processo, na saída do filho, no diário de eventos ou na persistência pode produzir OSError. O transporte também reduz várias falhas internas ao mesmo LocalError. O adaptador de aplicativos retorna control_failed para a maioria das exceções, sem a etapa. Os arquivos preservados registram as categorias já conhecidas.

## Escopo

- agent-rs/src/error.rs define o contexto de diagnóstico com identificadores fechados de etapa e código de sistema opcional.
- agent-rs/src/runtime.rs registra o contexto seguro no log local do agente e conserva a categoria que o servidor já recebe.
- agent-rs/src/controls.rs distingue reconciliação USB, reconciliação de aplicativos e persistência de eventos.
- agent-rs/src/windows_control.rs distingue staging, criação/espera do filho, I/O, validação da resposta e limpeza do script privado. Preserva códigos numéricos disponíveis na origem.
- deploy/agent-applications.ps1 registra uma etapa fechada da execução local, como diário, descoberta de amostra, geração/aplicação/verificação da política ou reconciliação de firewall.
- tests/test_windows_control_adapters.py cobre a saída sanitizada do adaptador com fronteiras simuladas. As regressões Rust ficam nos módulos acima.

## Sequência TDD

1. Escrever e commitar o vermelho depois da suíte completa permitida. Cobrir erros de I/O iguais em etapas diferentes, código numérico preservado, falha de processo/timeout, falha conjunta com limpeza, etapa desconhecida do adaptador e ausência de texto sensível no log. Verificar que a categoria, o ACK e a decisão de aplicação esperados continuam iguais.
2. Propagar o contexto com enumerações e números, mantendo a precedência atual das falhas. Quando uma falha de limpeza ou de persistência de eventos obscurecer outra falha, guardar somente os marcadores seguros das duas operações. Preservar os diários, a validação estrita e a limpeza do transporte.
3. Emitir uma linha adicional correlacionável por horário e versão da atribuição. Manter a linha de categoria já existente. Dados admitidos são a categoria, as etapas fechadas e um código numérico de sistema quando observado. A resposta interna do adaptador pode acrescentar etapa e código seguros; respostas desconhecidas caem em diagnóstico genérico.
4. Rodar suítes completas permitidas, parser PS5.1, Ruff, fmt e Clippy. Exercitar scripts inertes e mocks no host. Conferir que conteúdo bruto da exceção, stderr, payload, caminhos, credenciais e configuração não saem pelo novo registro.
5. Preparar MSI/ISO e executar o catálogo em snapshot limpo. Preservar ACK 90 s, início de sonda 10 s, uma hora real, 5.400 s totais e remoção normal. Usar o log protegido para correlacionar eventuais falhas com a operação observada. Se o problema não repetir, registrar o limite da evidência.

## Riscos e conclusão

A instrumentação abrange o caminho compartilhado de controle no Windows. Nenhuma decisão de política, autorização, timeout, ACL ou contrato HTTP deve depender da telemetria. A validação deve preservar erros de reinício e falta de suporte, o comportamento de Linux e o reconhecimento das categorias legadas. O resultado esperado é identificar o ponto da falha quando ela ocorrer novamente. Qualquer correção do comportamento depende desse diagnóstico.
