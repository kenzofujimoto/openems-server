# Aceite das ações web

Use um agente compilado desta entrega em guest descartável ou máquina de homologação. Não reutilize como evidência os MSIs e relatórios anteriores à implementação de `category_actions`. O painel, servidor e agente devem ser da mesma entrega; aplicar a migração `008_web_event_actions.sql` pelo mecanismo normal de migrações antes do uso persistente.

## Preparação

1. Publicar listas e conferir saúde, data e contagens no painel. Confirmar que o endpoint baixou as categorias usadas, inclusive as permitidas explicitamente.
2. Usar modo DNS e conferir capacidades do agente. Um agente antigo deve recusar a política nova; um ACK de sucesso ignorando ações novas é falha.
3. Escolher domínios de teste controlados, incluídos em listas de homologação conhecidas. Não usar sites perigosos reais. Isolar esta política de outros bloqueios de rede, aplicativos ou antiburla para que o resultado seja atribuível.
4. Registrar a revisão e os hashes dos pacotes usados, política aplicada, ACK e horários. Nos testes de monitoramento, confirmar também a chegada do lote ao servidor; ausência imediata no painel não prova ausência de coleta local.

## Matriz mínima

| Configuração | Resultado esperado |
|---|---|
| Categoria Permitir; monitoramento geral desligado | DNS permitido, sem evento de navegação para a decisão |
| Categoria Bloquear | Resposta de bloqueio e evento `blocked` |
| Categoria Monitorar | Resposta encaminhada normalmente e evento `monitored` |
| Monitoramento geral ligado; domínio fora das categorias | Permitido e monitorado com motivo de política |
| Monitoramento geral ligado; categoria explicitamente Permitir | Permitido e sem evento de navegação |
| Domínio permitido explicitamente, também numa categoria bloqueada/monitorada | Exceção prevalece e não gera evento de navegação |
| Domínio em duas categorias com ações diferentes | Bloquear > Monitorar > Permitir |
| Janela de horário ativa/inativa | Somar as regras ativas; observar limites de horário e fuso |
| Categoria necessária ausente ou digest inválido | Política nova não ativada/confirmada com sucesso; manter proteção anterior válida |
| Reinício offline com cache completo/incompleto | Usar somente política com bases válidas; não iniciar monitoramento sem reconhecer exclusões |
| Token expirado e novo enrollment | Reenviar capacidades antes de buscar política; não entrar em repetição de incompatibilidade |
| Retry do mesmo lote após perda da resposta | Contagem não aumenta duas vezes |
| Fila saturada | Descartes contabilizados separadamente; não inflar bloqueios nem monitoramentos |

No painel, verificar o seletor por teclado, os três ícones com rótulos, o aviso de listas desatualizadas e os registros separados de bloqueio/monitoramento. Repetir uma navegação em Chrome e Firefox com perfis novos e testar resolução DNS diretamente. Cache e conexões já abertas podem impedir nova consulta; a navegação no navegador não substitui o teste DNS.

## Limites do aceite

O DNS observa consultas, inclusive de aplicativos e pré-carregamento. Não comprova todas as páginas visitadas, reprodução de streaming, URLs completas ou autoria por pessoa. Para Netflix, testar login e reprodução separadamente, liberando apenas dependências verificadas.

A extensão em `browser-extension/` possui testes e pacotes próprios, mas depende de um broker nativo ainda pendente. Sem esse componente, o resultado esperado é inatividade e nenhuma observação enviada. Seus testes com APIs simuladas não são aceite da integração com Chrome/Firefox ou do armazenamento no servidor.

Atualização, remoção, controles USB/WDAC e aceites já existentes devem manter seus roteiros e recibos. Um teste antigo aprovado não valida bytes novos. F9 permanece fora desta rodada.
