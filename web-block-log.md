# F2 — registro de bloqueios e painel (recorte 4b)

> Documento histórico: as rotas e o editor descritos abaixo já foram implementados. Os eventos atuais representam bloqueios DNS observados, não histórico completo de navegação. Consulte o [manual atual](docs/web-filter-compatibility.md), o [plano de monitoramento](docs/web-filter-actions-plan.md) e o [HANDOFF](HANDOFF.md).

Plano para aprovação, parte 4b de `web-categories.md` (aprovado em 2026-10-23, com retenção de 30 dias, agregação por hora e sem usuário do Windows). Nada será implementado antes do aceite.

## O que já existe

- O painel já chama `/api/v1/stats/overview` e `/api/v1/events` (`web/src/lib/queries.ts`). Hoje as duas respondem 404 e os cartões ficam vazios. Os formatos estão em `web/src/lib/schemas.ts`.
- O servidor tem papéis `viewer` (leitura) e `admin`, auditoria (`app/audit.py`) e stores em memória ou PostgreSQL.
- O agente decide cada consulta em `agent-rs/src/dns.rs` (`decide`), mas não guarda o motivo do bloqueio.
- O manifesto das categorias já traz nome e grupo (`"label": "Jogos"`) e a atribuição da UT1.

## Decisões que precisam de aprovação

| # | Decisão | Recomendação | Alternativa |
|---|---|---|---|
| 1 | O que conta como bloqueio | Respostas DNS bloqueadas por regra, categoria ou DoH. Um mesmo domínio com o mesmo motivo conta **no máximo uma vez por minuto** por máquina, porque o navegador repete a consulta (A, AAAA, novas tentativas). SafeSearch **não** entra: é reescrita, não bloqueio, e encheria o ranking com `google.com` | Contar toda consulta: números inflados e sem relação com tentativas de acesso |
| 2 | Agentes sem DNS local | Só agentes com `web-filter:dns` geram registro. O modo hosts não enxerga as consultas. O painel mostra isso no aviso de capacidades (item 6) | Contar acessos à página de bloqueio: só pega HTTP/HTTPS no navegador e conta em dobro com o DNS |
| 3 | Fila local | **Só em memória**: até 5.000 linhas agregadas (hora, domínio, motivo, categoria, contagem). Ao estourar, soma em `dropped` e manda isso ao servidor. Um reinício perde o que ainda não foi enviado (no máximo um ciclo) | Gravar em disco: sobrevive a reinício, mas deixa histórico de navegação no endpoint |
| 4 | Envio | Rota própria `POST /fct/api/public/v1/events/`, chamada a cada ciclo de sincronização quando há linhas. Se falhar, as linhas voltam para a fila | Pegar carona no `config/ack`: mistura assuntos e só acontece quando a política muda |
| 5 | Auditoria das visualizações | Registrar `events.read` **uma vez por administrador e por rota a cada hora**. O painel atualiza a cada poucos segundos, e registrar cada consulta inundaria a auditoria | Registrar toda leitura |
| 6 | Aviso de capacidades | `endpoint_view` ganha `missing_capabilities` (por exemplo `["web-filter:categories"]` quando a política efetiva usa categorias e a máquina não tem a tag). `POST /api/v1/profiles/{vdom}` devolve `warnings` com as máquinas afetadas. A ficha da máquina no painel mostra o aviso | Bloquear a publicação: impediria migrar aos poucos |
| 7 | Escolha de categorias no editor | O editor de políticas é a F7 e ainda não existe. Na 4b, a página "Filtro web" passa a listar as categorias publicadas, com grupo, contagem e a **atribuição CC BY-SA**, a partir de uma nova rota `GET /api/v1/categories`. A seleção fica para o editor da F7 | Criar agora um editor só de categorias, que seria refeito na F7 |
| 8 | Tarefa diária | `tools/update_categories.py --url` baixa o pacote da UT1, extrai com proteção contra caminho fora da pasta e publica com a troca atômica que já existe. No `docker-compose.yml`, um serviço `categories` (mesma imagem, sem portas, só leitura) roda a cada 24 h e grava num volume que o `server` lê. A URL vem de `OPENEMS_UT1_URL`, **sem valor padrão** até a licença e o endereço oficial serem confirmados | Cron no host: fora do compose e mais fácil de esquecer |

## Agente (Rust)

- `WebFilter::block_reason(name, when, lookup) -> Option<BlockReason>`: `Rule`, `Category(id)` ou `Doh`, com a mesma precedência de `blocks_at_with` (`allowed` vence). Os vetores compartilhados ganham o motivo esperado, conferido também pelo `agent/policy.py`.
- `events.rs`: o agregador (hora UTC, domínio, motivo, categoria, contagem), a janela de 1 minuto, o limite de 5.000 linhas e o `dropped`. `dns.rs` registra o bloqueio no agregador; `runtime.rs` envia a cada ciclo.
- Página de bloqueio: quando o motivo é categoria, mostra "Categoria: Jogos". O nome vem do `manifest.json`, guardado no cache de categorias. O texto é escapado como o domínio já é.

## Servidor

- Tabela `block_events` (devid, hour, domain, reason, category, count), com chave única e soma no conflito. Migração `002_block_events.sql` e store em memória para os testes.
- `POST /fct/api/public/v1/events/` (token do dispositivo): até 5.000 linhas, domínio normalizado e válido, motivo da lista fechada, categoria da taxonomia, hora entre agora − retenção e agora + 1 h (relógio do endpoint errado não planta dado no futuro), contagem de 1 a 100.000.
- `GET /api/v1/events?limit=` e `GET /api/v1/stats/overview` (leitura). Em `overview`, `blocks_by_day` e `top_domains` cobrem os últimos 7 dias, e `apps`/`usb` ficam em 0 até a F3 e a F4. `previous_period` só tem dado real para `blocks`, porque o servidor não guarda histórico de máquinas online, então os outros campos passam a ser opcionais.
- Retenção: `OPENEMS_EVENT_RETENTION_DAYS` (30 por padrão, de 1 a 365). Apaga o vencido a cada envio e filtra também na leitura.
- `GET /api/v1/categories`: o manifesto sem os digests (id, nome, grupo, contagem, versão, atribuição).

## Painel

- `eventSchema` aceita `category`, `reason` e `count` opcionais. A lista de eventos mostra "steamcommunity.com · Jogos · 12×".
- `previousPeriodSchema` aceita campos opcionais. Sem dado anterior, o cartão não mostra variação.
- A página "Filtro web" lista as categorias com a atribuição.
- A ficha da máquina mostra o aviso de capacidades.
- Um aviso fixo junto dos eventos informa que o registro de bloqueios é dado pessoal do colaborador e quanto tempo fica guardado.

## Testes (falham primeiro)

1. Rust: `block_reason` com regra, categoria, `allowed` e DoH; o agregador (janela de 1 minuto, troca de hora, limite e `dropped`); a página com o nome da categoria escapado.
2. Vetores: motivo nos vetores Python e Rust.
3. Servidor: validação do envio (domínio, motivo, categoria, hora, limite, token de outro dispositivo); soma de contagens; retenção; `overview` e `events` no formato do painel; `viewer` lê e não escreve; auditoria uma vez por hora; `missing_capabilities` e `warnings`; PostgreSQL com a migração (onde já há testes com banco).
4. `tools/update_categories.py --url` com um `.tar.gz` local, incluindo um arquivo com `../` recusado.
5. Contrato nativo: o agente real bloqueia `api.steampowered.com` e o servidor de teste recebe a linha `category=games`.
6. Painel: Vitest para os esquemas, a lista de eventos, o aviso de capacidades e a página de categorias.
7. **Sandbox:** estender `deploy/test-categories-sandbox.ps1` com duas verificações: o servidor simulado recebe a linha de bloqueio da categoria `games`, e o Edge mostra "Categoria: Jogos" na página de bloqueio (confirmação do operador, junto com a que já existe).

## Ordem dos commits

1. `test(policy)` + `feat(policy)`: motivo do bloqueio e vetores.
2. `test(agent)` + `feat(agent)`: agregador, envio e página com categoria.
3. `test(api)` + `feat(api)`: rota de envio, tabela, retenção.
4. `test(api)` + `feat(api)`: `events`, `overview`, `categories`, capacidades e auditoria.
5. `test(web)` + `feat(web)`: painel.
6. `test(tools)` + `feat(deploy)`: download da UT1 e serviço diário.
7. Aceite em Sandbox, evidência e HANDOFF.

## Riscos

- **LGPD:** domínio + máquina é dado pessoal. Mitigações: sem usuário do Windows, agregação por hora, 30 dias, leitura só com permissão, auditoria e aviso. A base legal e a comunicação aos colaboradores continuam com a RSM, e a produção depende dessa validação.
- **Números aproximados:** a contagem é de tentativas de resolução, não de páginas abertas. O cache de DNS do Windows esconde parte das repetições.
- **Endpoint mal-intencionado** pode enviar dados falsos sobre a própria máquina, mas não sobre outra (token por dispositivo). O tamanho do pedido e o número de linhas são limitados.
- **Download da UT1** depende de endereço e licença ainda não confirmados. Por isso a URL não tem valor padrão.
- O recorte é grande. Se preferir, posso entregar até o passo 4 (agente e servidor) e deixar o painel e a tarefa diária para um aceite separado.

Commits locais com `[skip ci]`, sem PR e sem CI, conforme o handoff.
