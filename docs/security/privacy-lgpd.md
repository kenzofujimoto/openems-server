# Privacidade, telemetria e LGPD

Documento técnico, **não é parecer jurídico**. Antes de uso em dispositivo de colaborador, controlador e encarregado devem validar finalidade, base legal, necessidade, transparência e proporcionalidade.

## Dados

| Categoria | Exemplo | Risco |
| --- | --- | --- |
| Identificação do endpoint | `devid`, hostname, IP, SO, hora de contato | Correlação a colaborador |
| Navegação indireta | Domínio DNS, categoria, motivo, contagem/hora | Inferências sobre comportamento; não prova acesso |
| Integridade | Tentativa de remoção/alteração, erro | Interpretação disciplinar sem contexto |
| Auditoria | Admin, operação, alvo, timestamp | Identidade e ações sensíveis |
| Captura opcional | JSONL de laboratório via `OPENEMS_RECORD` | Possível presença de payloads/tokens em corpo |

## Medidas implementadas

O agente agrega bloqueios DNS por hora e limita lotes; evento não contém nome do usuário Windows. Ainda assim, máquina pode ser relacionada a empregado pelo inventário. Retenção em `OPENEMS_EVENT_RETENTION_DAYS` tem padrão 30 dias e admite 1–365; acesso requer autorização, e leituras de eventos são auditadas no processo. Não assumir que expurgo no banco remove arquivos de captura, backups, exportações e logs secundários.

## Pendências de governança

- Documento de finalidade, base legal, transparência e política interna; avaliação de eventual RIPD.
- Perfil de acesso por necessidade, trilha de investigação e retenção/descarte por meio de armazenamento.
- Protocolo para incidentes, acesso de titulares e exportação de dados.
- Avaliação humana de falso positivo; evento de DNS não é URL acessada nem prova de intenção.
- Revisão do conteúdo do painel e do contrato com operadores/processadores antes de escala.

A coleta de dados deve ser minimizada e **não ativada em produção sem esta análise**. Ver [eventos](../reference/telemetry-events.md).
