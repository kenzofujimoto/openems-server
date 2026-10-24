# F5 — proteção contra adulteração

Proposta para aprovação. Nada será implementado antes do aceite deste documento. Critérios da fase em `roadmap-v2.md`: um usuário comum não consegue parar nem remover o agente; desinstalar sem código falha; uma alteração no DNS do sistema é revertida e registrada.

## Hoje

- O serviço `openems-agent` (LocalSystem) inicia no boot e é reiniciado após falha (5 s, 15 s, 60 s). Isso já foi aceito em Sandbox.
- A DACL do serviço é a padrão do Windows. O usuário comum já não consegue parar o serviço, mas **um administrador local para, reconfigura e remove**. A desinstalação pelo MSI não pede nada além da elevação.
- A pasta de dados é protegida (SYSTEM e Administradores com controle total, usuários só com leitura). Os arquivos sensíveis, como `state.json`, só são acessíveis ao dono, ao SYSTEM e aos Administradores.
- A regra NRPT, os filtros WFP e as políticas de navegador são criados na partida. Ninguém confere depois se continuam no lugar. Só o bloco do `hosts` é regravado a cada ciclo.
- Não há eventos de adulteração. O painel já tem o tipo `tamper` na lista de eventos (`web/src/lib/schemas.ts`).

## Limite honesto

Um administrador local determinado sempre consegue desligar um agente em modo usuário: ele pode tomar posse da DACL, editar o registro ou encerrar o processo com SeDebugPrivilege. O que esta fase entrega é:
- impedir que o **usuário comum** pare, altere ou remova o agente;
- impedir que um administrador faça isso **por engano ou pelos caminhos comuns** (Serviços, `sc`, Painel de Controle, `msiexec /x`);
- **desfazer e registrar** o que for alterado.

Proteção forte exige um driver de kernel assinado pela Microsoft, fora deste escopo. A recomendação continua sendo retirar o direito de administrador local dos usuários.

## Decisões que precisam de aprovação

| # | Decisão | Recomendação | Alternativa |
|---|---|---|---|
| 1 | Entrega | Duas partes com aceite próprio. **5a:** permissões, watchdog e eventos de adulteração. **5b:** código de desinstalação, que envolve servidor, painel e MSI. O componente de sessão no logon (avisos ao usuário) vira uma **5c** posterior, porque não faz parte dos critérios de aceite | Tudo de uma vez |
| 2 | DACL do serviço | SYSTEM com controle total. Administradores podem consultar, **iniciar** e ler a configuração, mas não podem parar, pausar, alterar a configuração, mudar a DACL nem remover. Usuários autenticados só consultam o estado. O MSI continua funcionando porque o Windows Installer executa como SYSTEM | Deixar os Administradores com controle total e proteger só contra o usuário comum, o que o Windows já faz hoje |
| 3 | Watchdog | Duas camadas. (a) **No serviço**, a cada ciclo (15 s): confere e refaz a regra NRPT, os filtros WFP, as políticas de navegador, o bloco do `hosts`, o tipo de início, a recuperação, a DACL do serviço e a tarefa agendada. (b) **Uma tarefa agendada como SYSTEM** (`openems-agent watchdog`), no boot e a cada 5 min: se o serviço estiver desativado ou parado sem que a remoção esteja em andamento, restaura o tipo de início e inicia o serviço. Uma camada recoloca a outra | Só a verificação no serviço: um administrador que desative o serviço no registro e encerre o processo o deixa parado até alguém intervir |
| 4 | Eventos de adulteração | Nova rota `POST /fct/api/public/v1/tamper/`, com tabela própria, a mesma retenção do registro de bloqueios e o tipo `tamper` na lista de eventos do painel. Tipos: `dns_rule_restored`, `wfp_restored`, `browser_policy_restored`, `hosts_restored`, `service_config_restored`, `watchdog_restored`, `service_started_by_watchdog`, `unexpected_exit` (o serviço anterior terminou sem parada normal) e, na 5b, `uninstall_code_rejected`. O mesmo tipo é enviado no máximo uma vez a cada 10 min. A fila fica em memória, com limite | Gravar só no log local do agente: ninguém vê |
| 5 | Código de desinstalação (5b) | O segredo de cada máquina é **derivado de uma chave-mestra da organização**: HMAC-SHA256(chave-mestra, client_id). O servidor recebe a chave em `OPENEMS_UNINSTALL_MASTER_KEY` e entrega ao agente só o segredo derivado, uma vez, pela sincronização autenticada. O agente o guarda num arquivo só do SYSTEM. O painel gera códigos HOTP (RFC 4226) de 10 caracteres em base32 (cerca de 50 bits), na ficha da máquina, só para `admin`, com auditoria e o código mostrado uma única vez. O MSI recebe `UNINSTALLCODE=...`, que fica oculto no log. A ação de remoção confere o código **localmente, sem rede e sem servidor**, aceita só contadores acima do último usado (janela de 20) e bloqueia por 1 hora depois de 5 erros. Upgrades não pedem código | Segredo aleatório por máquina, guardado só no banco: se o servidor for perdido, nenhuma máquina sai sem remoção forçada |
| 7 | Servidor desligado ou perdido | Dois caminhos. (a) **Desligamento planejado:** um botão no painel ("Liberar desinstalação") publica para um grupo ou para toda a frota uma marca assinada. Os agentes a guardam, e a partir daí a remoção não pede código. Recomendado antes de encerrar o servidor ou trocar de produto. (b) **Servidor perdido:** `tools/uninstall_code.py` gera o código de qualquer máquina **sem servidor**, a partir da chave-mestra e do client_id ou do nome da máquina. O nome aparece em `agent.json`, legível por administradores na própria máquina. A RSM guarda a chave-mestra num cofre de senhas, fora do servidor | Só o painel gera códigos: é o cenário do FortiClient EMS sem licença, que acabou na remoção forçada |
| 6 | Máquinas que ainda não receberam o segredo | A remoção sem código continua permitida, mas gera um evento `uninstall_without_secret` antes de prosseguir. Assim, instalações antigas ou que nunca sincronizaram não ficam presas | Recusar sempre: um agente que nunca falou com o servidor só sairia com intervenção manual |

## Parte 5a

**Agente (Rust)**
- `service.rs`: aplica a DACL da decisão 2 na instalação, na `configure-recovery` e, se ela mudar, no watchdog.
- Novo `watchdog.rs`: uma lista de verificações, cada uma com `check() -> Estado` e `repair()`, testáveis com sistemas simulados, como já é feito em `browser_policy.rs`. Roda dentro do laço de aplicação e não altera nada em `dry_run`.
- Comando `openems-agent watchdog`, chamado pela tarefa agendada. A tarefa é criada e removida pelas ações do MSI e verificada pelo próprio serviço.
- Marcador de execução: `running.marker`, criado na partida e removido na parada normal. Se o marcador existir na partida seguinte, o agente gera `unexpected_exit`.
- Fila de eventos de adulteração enviada a cada sincronização, com o mesmo padrão de limite e restauração do registro de bloqueios.

**Servidor e painel**
- `app/events.py` ganha `TamperEvent`, o store e a migração `003_tamper_events.sql`.
- A rota de envio valida o tipo contra uma lista fechada, o horário e o tamanho do detalhe (até 200 caracteres, sem dado do usuário).
- `/api/v1/events` passa a misturar `web_block` e `tamper`, em ordem de horário. O painel já tem ícone e rótulo para `tamper`.

**Aceite em Sandbox** (`deploy/test-tamper-sandbox.ps1`, MSI de produção):
1. Um usuário comum criado no próprio Sandbox, com senha gerada na execução que nunca sai dele, recebe "acesso negado" em: `sc stop`, `sc config`, `sc delete`, gravação em `agent.json` e remoção do executável.
2. Um administrador recebe "acesso negado" em `sc stop`, `sc config` e `sc delete`.
3. A regra NRPT apagada pelo administrador volta em até 30 s, e o servidor simulado recebe `dns_rule_restored`.
4. Uma política de navegador alterada volta e é registrada.
5. Com o serviço marcado como desativado no registro e o processo encerrado, ele volta a rodar em até 6 min pela tarefa agendada, e o servidor simulado recebe `service_started_by_watchdog` e `unexpected_exit`.
6. O upgrade do MSI 0.3.0 para o novo funciona com a DACL restrita.
7. A desinstalação remove a tarefa agendada e devolve a regra NRPT, a confiança e o `hosts`.

## Parte 5b

- Servidor: segredo derivado da chave-mestra (decisão 5), entregue em `POST /fct/api/public/v1/uninstall_secret/` só quando o agente ainda não tem um. O contador de cada máquina fica numa coluna nova, com migração. A rota `POST /api/v1/endpoints/uninstall_code` (admin) gera o próximo código e registra a auditoria `endpoint.uninstall_code` sem o código. A rota `POST /api/v1/uninstall_release` (admin, por grupo ou para toda a frota) publica a liberação da decisão 7a, também auditada.
- Ferramenta offline: `tools/uninstall_code.py --master-key-file ... --client-id ...` (ou `--devid`), sem banco e sem rede. A chave-mestra pode ser lida de arquivo ou da entrada padrão, nunca da linha de comando.
- Liberação de remoção: a marca é assinada com HMAC do segredo da própria máquina, para um agente não aceitar uma marca forjada no `state.json`.
- Agente: guarda o segredo em `uninstall.json` (DACL só do SYSTEM). `installer-prepare --remove` passa a exigir `--uninstall-code` e o comando `openems-agent uninstall` também. O contador usado e as tentativas erradas ficam no mesmo arquivo.
- MSI: propriedade `UNINSTALLCODE` em `MsiHiddenProperties`, repassada só à ação de remoção.
- Painel: botão "Gerar código de desinstalação" na ficha da máquina, só para `admin`, com o código exibido uma vez e copiável.
- Aceite em Sandbox: `msiexec /x` sem código e com código errado falha e mantém o produto. Com o código gerado pelo servidor simulado, remove. O mesmo código não serve uma segunda vez numa reinstalação com o mesmo segredo. O upgrade não pede código. **Com o servidor simulado desligado e a rede do Sandbox cortada**, um código gerado por `tools/uninstall_code.py` (fora do Sandbox) remove o agente, e o mesmo vale depois de uma liberação de remoção recebida enquanto o servidor estava no ar.

## Testes (falham primeiro)

- Rust: SDDL da decisão 2; cada verificação do watchdog com sistemas simulados (ausente, alterado, já certo); marcador de saída inesperada; fila de adulteração com limite; HOTP com os vetores do RFC 4226; janela, contador e bloqueio de tentativas.
- Python: validação e retenção da rota `tamper`; `/api/v1/events` misturado; segredo entregue uma única vez; geração de código só para `admin`, com auditoria sem o código; a mesma função HOTP no Python, conferida pelos vetores compartilhados.
- Vitest: evento `tamper` com detalhe; geração de código na ficha (só `admin`, exibido uma vez).
- Os contratos dos dois roteiros de Sandbox ficam vermelhos antes da implementação.

## Riscos

- **DACL errada pode travar o upgrade ou a remoção.** Mitigações: o upgrade e a remoção entram no aceite, e a DACL não é aplicada antes de o MSI terminar a instalação.
- **Administradores perdem o `sc stop`.** Para manutenção, o caminho passa a ser o código de desinstalação, ou uma política sem regras se a ideia for só desligar o filtro.
- **O watchdog pode brigar com outra ferramenta** que mexa em NRPT ou nas políticas de navegador, como GPO ou outra VPN. Mitigação: o watchdog só toca no que o agente criou e marcou (o comentário da regra NRPT e os valores salvos), e cada restauração vira evento visível no painel.
- **A chave-mestra gera o código de qualquer máquina.** Ela fica só na variável de ambiente do servidor e no cofre da RSM: nunca no banco, no log ou no painel. Trocar a chave invalida os segredos já entregues, então a troca é uma operação planejada que reenvia o segredo a cada agente na sincronização seguinte. Quem tem acesso ao servidor já controla a frota.
- **Remoção forçada** (a ferramenta da Microsoft que apaga o registro do MSI) não executa as ações do agente: deixa o serviço, a regra NRPT e a CA para trás. Por isso os caminhos da decisão 7 existem, e a 5b entrega também um `openems-agent cleanup`, que exige o código e desfaz tudo o que o agente criou, para máquinas em que o MSI já foi removido à força.

Commits locais com `[skip ci]`, sem PR e sem CI, conforme o handoff.
