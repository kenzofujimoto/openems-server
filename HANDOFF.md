# Handoff — roadmap v2

## Estado da continuação final — 2026-10-26

### Resultado final da correção dos Sandboxes — 26/10/2026

Pacote testado: código nativo `2733810`, roteiros/manifestos `779b483`. Os mesmos dois MSIs foram usados nas quatro fases. A rodada foi executada em guests novos; sessão incluiu reboot real dentro do mesmo guest. Todos os guests criados pela tarefa foram encerrados após preservar as evidências.

| Fase | Resultado da rodada final | Pendência |
|---|---|---|
| Sessão | 5 checks na fase 1 e 3 após reboot; watchdog, componente, upgrade e remoção aprovados | Nenhuma nesta rodada |
| Locais | 8/8: dentro/fora, ACK, avisos, reinícios offline e remoção | Nenhuma nesta rodada |
| USB | `automation_passed=true`, 4 checks, sem erros de limpeza | Pendrive físico em VM com passthrough; `passed=false`/`manual_required` é esperado até esse teste |
| Aplicativos | `automation_passed=true`, 6 checks: inventário, bloqueio/liberação de rede e remoção | Execução por hash/editor exige VM com Code Integrity funcional; este Sandbox retornou `0x80073BC3` |

O consolidado em `validation/sandbox-final-summary-2026-10-26.json` contém três relatórios aceitos, duas pendências e **nenhuma falha**. Os JSONs finais individuais estão em `validation/`; a pasta de resultados normal contém os mesmos relatórios com recibos do pacote atual. Nada foi editado para transformar pendência em aceite.

Correções reproduzidas com TDD:

- MSI 1603: `ConfigureRecovery` retornava `0xC0000135`; os três executáveis importavam `vcruntime140.dll`. Cargo iniciado na raiz ignorava a configuração dentro de `agent-rs/.cargo`. Configuração de CRT estático movida para `.cargo/config.toml` na raiz (`1074510`), com contrato de imports PE.
- Inventário USB: disco virtual do Sandbox não existe como `MSFT_Disk`; selecionar somente USB antes de `Get-Disk` (`2733810`), mantendo erros de USB real e proteção de boot/HID.
- Roteiro USB não depende de WDAC; aplicativos registra capacidade indisponível como pendência e continua os testes independentes de inventário/rede (`c6fb741`).
- Publicação de progresso: VSMB recusava substituir JSON existente com Move-Item. Snapshots compartilhados usam Copy-Item, arquivos locais continuam com troca atômica; recibos e três harnesses cobertos (`779b483`). Probe real de duas gravações passou.
- Sessão e locais exportam logs MSI/agent automaticamente, inclusive em falha. Relatórios originais falhos permanecem em `validation/sandbox-failures-2026-10-26/`.

Validação final: **854 Python aprovados, 54 ignorados, cinco deselecionados; 205 Rust Windows; fmt, clippy e Ruff aprovados**. PostgreSQL/Redis opcionais não estavam ativos nesta repetição; a rodada anterior com infraestrutura está registrada abaixo. O teste Rust de SafeSearch teve uma falha de prazo sob carga e a suíte inteira passou na repetição sem mudar código, prazos ou asserções.

Próxima ação do usuário: USB físico oferecido para amanhã em VM descartável e teste WDAC nessa VM compatível, conforme `ACCEPTANCE.md` (inclui os comandos diretos para VM). Não aplicar esses controles no host. Os quatro perfis normais continuam manuais; perfis `*-auto.wsb` são somente os diagnósticos usados pela tarefa. Não recompilar só por alterações de documentação: isso preserva os recibos dos MSIs já testados. CI, push e PR continuam adiados.

Branch local: `feature/desktop-roadmap`, empilhada sobre a F6. Escopo autorizado até F8; F9 excluída. Nenhum push, PR ou execução de CI nesta continuação. Os registros anteriores abaixo são históricos; o roteiro atual é `ACCEPTANCE.md`.

| Fase | Implementação atual | Aceite restante |
|---|---|---|
| F4 USB | Contrato Python/Rust; inventário de armazenamento Windows; regras ordenadas com seletores combinados, exceções e allow/block/read_only; proteção de HID e disco de sistema; journal de alterações próprias e reversão. | Automação Sandbox aprovada; falta VM Windows com pendrive físico redirecionado para allow/block/read_only. |
| F3 aplicativos | Inventário de apps/processos; encerramento legado; WDAC por amostra local verificada/hash/editor/caminho/nome original e firewall por executável; journal e limpeza próprios. Falha de capacidade/reboot pendente não recebe ACK de sucesso. | Inventário/rede/liberação/limpeza aprovados no Sandbox; falta VM compatível para recusa antes da execução, cópia renomeada e editor exclusivo. |
| F7 painel/servidor | React substitui o console antigo; políticas completas, inventários, grupos/regras, auditoria/eventos, convites, administradores e instaladores/configuração. CSRF, perfis por função, If-Match e preservação de seções. Persistência PostgreSQL, migrações 006/007 e revogação durável de convite bootstrap. | Homologação com agentes reais e revisão visual/teclado. O console antigo redireciona para `/panel/`. |
| F8 Linux | Agente/helper compilados como ELF Linux; integração systemd/resolved com restauração, USBGuard allow/block e fapolicyd por caminho/hash. DEB gerado; recursos não suportados são recusados explicitamente. | VM Linux com systemd, USB passthrough e fapolicyd; instalação, reboot, offline, bloqueio e remoção. Build em contêiner não comprova enforcement. |
| F8 macOS | Fontes de compatibilidade launchd e empacotamento assinado; pré-requisitos em `deploy/macos/SUPPORT.md`. | **Incompleta:** Network Extension e Endpoint Security precisam de implementação nativa, entitlements, assinatura/notarização e Mac para validação. Não marcar F8 integralmente concluída. |

O runtime aplica controles antes de confirmar a política, preserva eventos offline em fila limitada, envia inventário autenticado e distingue instalação de política de tentativa de bloqueio real. Restrições Windows de CA/antiburla não são anunciadas como implementadas nas outras plataformas.

Validação do painel final: **97 testes**, cobertura statements 91,27%, branches 83,47%, functions 88,31%, lines 95,09%; lint, tipos e build aprovados. **Cinco testes de navegador contra o bundle de produção e API real aprovados**, incluindo login cookie/CSRF, políticas, regras, XSS, leitor, mobile/teclado e tema. Build mantém aviso de bundle maior que 500 kB.

Rodada anterior do servidor/agente com infraestrutura: **891 Python aprovados, cinco deselecionados** (`-m 'not windows_only'`, PostgreSQL/Redis descartáveis e agente release obrigatório), **202 Rust Windows** e **189 Rust Linux** aprovados. Ruff, fmt, clippy Windows com `-D warnings` e builds release passaram. O build Linux mantém dois avisos de código específico Windows não usado. A imagem Docker de produção foi compilada e iniciou com PostgreSQL/Redis descartáveis; painel, redirecionamento do console, login com cookie seguro e API autenticada funcionaram. Não houve execução de MSI/WDAC/USB/firewall/DNS de produção no host.

As falhas encontradas e corrigidas na rodada completa foram: `$pid` colidindo com `$PID` no inventário USB, chave de registro Uninstall vazia retornando `$null`, expectativa antiga de cópia parcial do pacote Python no Dockerfile e asserção ambígua de conexão TCP após fechar o DNS no Linux. Os contratos novos reproduziram os erros antes da correção. A falha transitória de sessão foi repetida isoladamente e na suíte completa final, ambas aprovadas.

Artefatos locais finais: `.venv/sandbox-acceptance/` contém os quatro perfis e manifestos de `779b483`; MSI atual SHA-256 `fc69cfb8ede407afb5d66970c5fcd06e71fcfbcd53cbc36de1119e8c61739d06`, upgrade `ac028a71daf227a36fe9de1ed63909dc47c646c9fddec4b785cf722efbee713a`. Os roteiros foram executados no Sandbox; sessão e locais estão aprovados, USB físico e WDAC permanecem pendentes. `.venv/linux-build/packages/` mantém DEB/RPM amd64 e manifestos da fase Linux anterior, ainda pendentes de VM própria.

Pacotes finais são preparados por `tools/build_final_acceptance.py`: um mesmo par de MSIs para sessão, locais, USB e aplicativos, com commit e SHA-256 verificados pelos launchers. Não executar roteiros de controle no host. Evidência ausente, falha de limpeza, reboot necessário ou hardware pendente continuam pendentes no consolidado.

Pendências externas adicionais: assinatura de produção, Chrome/Firefox na segunda máquina, confirmação acessível da licença UT1 na fonte oficial e revisão operacional/LGPD. Nenhum desses itens foi convertido artificialmente em aceite por teste unitário.

## Roteiros de Sandbox e pendências

Decisão do usuário em 2026-10-25: as rodadas de Sandbox ficam para o fim, todas juntas. Nenhuma fase desta lista está aceita até o JSON de resultado dizer `passed: true`. Use os pacotes conjuntos de `tools/build_final_acceptance.py` e siga `ACCEPTANCE.md`, inclusive para USB e aplicativos; comandos e hashes individuais registrados nas seções históricas abaixo foram substituídos pela preparação final.

| Fase | Roteiro | Pacote e perfil | Como rodar | Resultado |
|---|---|---|---|---|
| F5 5c — componente de sessão e reboot | `deploy/test-session-sandbox.ps1` | `.venv/sandbox-acceptance/session-input` (`python tools/build_session_sandbox.py`), `session.wsb` | Win+R → `C:\openems-input\RUN-SESSION-TEST.cmd`; ao fim da fase 1, reiniciar o Sandbox por dentro e rodar de novo | `results/session-phase1.json`, `results/session-result.json` |
| F6 — locais de rede | `deploy/test-locations-sandbox.ps1` | `.venv/sandbox-acceptance/locations-input` (`python tools/build_locations_sandbox.py`), `locations.wsb` | Sandbox novo, Win+R → `C:\openems-input\RUN-LOCATIONS-TEST.cmd` | `results/locations-result.json` |

## Continuação Codex — F2 HTTPS local

Branch local: `feature/https-blockpage`. Contrato aprovado em `https-blockpage.md`.

## Estado atual do teste no host — autorizado posteriormente pelo usuário

- Em 2026-10-22, o usuário autorizou explicitamente testar na própria máquina fora do Sandbox. Essa autorização específica substitui a proibição anterior para este teste controlado, não para a suíte destrutiva de MSI/serviço.
- **Novo agente instalado e CA local confiável ativa no host.** Serviço atualizado preservando cadastro/configuração; `127.0.0.1:443` pertence ao PID do serviço. Listeners Docker/WSL em IPv6 foram preservados; bind IPv4 foi verificado disponível antes da troca.
- Checkpoint protegido de executável/configuração/estado/hosts e ACLs: `C:\ProgramData\openems-checkpoint-b258bb1772a4426f86f5196deb969fbc`. Procedimento operacional temporário em `.venv/host-https-test/host-update.ps1`, com modo `-Rollback -Checkpoint <pasta>`. Rollback remove só a CA criada nesta tentativa antes de restaurar a configuração e o executável; erros da limpeza não impedem a tentativa de restauração. Não registrar conteúdo da configuração/tokens.
- **Chrome do host aprovado por aba manual e captura do usuário**, URL `https://example.com/` conferida pela lista de abas. A aba criada/controlada pela automação sofreu `STATUS_ACCESS_VIOLATION`, com timeouts CDP; causa não determinada. Não continuar controlando a aba manual para evitar interferir no aceite.
- Evidência em `validation/host-chrome-https-2026-10-22.json`. O estado instalado foi mantido para o teste solicitado; não confundir com as validações anteriores sem alteração no host.
- Próximo recorte proposto: `PLAN-installer-blockpage.md` (F1/F2: opções no MSI, preservação de upgrade, transação de CA e pacote para a segunda máquina). Ainda precisa de aprovação específica do plano antes de alterar implementação em vários arquivos. Firefox permanece pendente; cada máquina deve gerar e proteger sua própria CA.

### Continuação — F2 categorias, parte 4a (branch `feature/web-categories`, `web-categories.md` aprovado em 2026-10-23)

- Feito com TDD:
  - Taxonomia no estilo FortiGuard em `agent/policy.py` (`CATEGORIES`, 21 ids), montada sobre as listas UT1. Nomes conferidos no espelho `olbat/ut1-blacklists`, ativo em 2026-10-12. **A licença CC BY-SA 4.0 precisa ser confirmada na fonte oficial**: o site da universidade mudou de endereço.
  - Arquivo de categoria: `OEMSCAT1` + contagem u32 + hashes u64 ordenados (8 primeiros bytes do SHA-256). Um domínio pertence à categoria se ele ou um domínio-pai estiver na lista. `blocked_categories` vale no topo e dentro das janelas de horário; `allowed` vence. Vetores compartilhados com o Rust (`categories.rs`).
  - Servidor: `tools/update_categories.py` (UT1 → arquivos + manifesto com atribuição, troca atômica) e rotas do agente `/fct/api/public/v1/categories/` e `.../categories/file/` (token do dispositivo, digest publicado). Configurado por `OPENEMS_CATEGORIES_DIR`.
  - Agente: depois de cada sincronização, baixa só as categorias referenciadas, com timeout próprio de 300 s, tamanho e SHA-256 conferidos e digest validado antes de virar nome de arquivo. Guarda em `categories/` ao lado do `state.json`, carrega do cache ao iniciar (funciona offline) e informa a tag `web-filter:categories`.
  - O contrato nativo (`tests/test_native_categories.py`) roda o agente real contra o servidor de teste, numa porta DNS efêmera.
- Corrigidas duas instabilidades de teste: o `free_port` caía em blocos de portas reservadas (agora sorteia abaixo da faixa dinâmica), e o contrato encerrava o agente antes de a política chegar ao `state.json`. O agente agora informa no log se carregou cada categoria do cache.
- O agente aplica e grava uma política nova assim que ela chega, sem esperar o próximo ciclo (antes, um reinício nos 15 s seguintes perdia a política). Contrato nativo com intervalo de 30 s.
- Suíte: **580 Python aprovados, 41 ignorados, 5 deselecionados; 110 Rust**.
- Aceite `deploy/test-categories-sandbox.ps1` (contratos em `tests/test_categories_sandbox.py`), com a categoria `games` gerada pela ferramenta real.
  - Verifica: bloqueio de `api.steampowered.com` e `steamcommunity.com`, `allowed` para `store.steampowered.com`, arquivo em cache com o digest, reinício do serviço offline ainda bloqueando, Edge em `steamcommunity.com` confirmado pelo operador, e desinstalação.
- Pacote: `.venv/sandbox-acceptance/categories-input/` (MSI e `categories/`) e `categories.wsb`, com rede. Win+R → `C:\openems-input\RUN-CATEGORIES-TEST.cmd`; relatório em `results/categories-result.json`. O pré-teste espera até 60 s pela rede do Sandbox.
- **Aceite em Sandbox aprovado em 2026-10-24 (6/6)**, Edge confirmado pelo operador: `validation/sandbox-categories-2026-10-24.json`.
### Continuação — roadmap restante (pedido do usuário em 2026-10-25: "faça tudo menos a 9")

- Ordem: F5 5c (componente de sessão e reboot) → F6 → F4 → F3 → pendências de código da F7 e da F2 → F8 (Linux aqui; macOS depende de Mac e Apple Developer ID). Cada fase: desenho em `.md`, TDD, roteiro de Sandbox. O usuário autorizou seguir sem parar para aprovar cada plano; decisões que mudariam o rumo são sinalizadas.
- `main` = `19ef954` (tudo até a 5b, push feito). Cada fase em branch nova a partir da anterior.

### Continuação Codex — F6 (branch `feature/network-locations`, desenho em `network-locations.md`)

- Retomada da sessão do Claude: testes de casamento já estavam commitados em `4b2ef63`; `locations.rs` ainda estava incompleto. A autorização anterior para seguir o roadmap e adiar todos os Sandboxes foi recuperada no registro da sessão.
- Agente: decide a cada aplicação da política, inclusive offline, por IP público ou dois tipos de sinais locais. Coleta endereços, sufixos DNS e MACs dos gateways no Windows sem alterar adaptadores. Confere o certificado DER e a assinatura do handshake TLS da sonda interna. Uma faixa doméstica igual, sozinha, não identifica a empresa.
- Cache: `state.json.profile` mantém a política externa completa e as alternativas internas verificadas por digest. O IP público vale por menos de três intervalos após a resposta do servidor e fica desconhecido após reiniciar. As categorias de todos os perfis possíveis são mantidas em cache. A liberação de desinstalação continua vindo da configuração externa.
- ACK: confirma perfil e local realmente aplicados; as tags continuam informando o grupo externo para não fazer as regras de atribuição oscilarem. Mudanças de local geram avisos em `session.json`.
- Servidor: CRUD administrativo auditado de locais, mapeamento grupo/local/perfil interno, `client_ip` do transporte, validação do ACK e localização na ficha. Persistência em memória e PostgreSQL; migração `005_network_locations.sql`. No overlay TLS a porta direta do servidor deixa de ser publicada; o nginx sobrescreve `X-Forwarded-For` com o endereço do cliente.
- Painel: "Locais de rede" com cadastro, edição, exclusão e mapeamentos; leitor só consulta. A ficha mostra o último local confirmado. Página e formulário conferidos no navegador em modo mock.
- Sandbox preparado, **ainda não executado**: `deploy/test-locations-sandbox.ps1` com oito verificações (DNS dentro/fora, mesma faixa e gateway diferente, ACK, avisos, reinício offline dentro e fora e remoção). A tabela no topo contém pacote, comando e resultado esperado. Recompilar os MSIs do código final de todas as fases antes da rodada conjunta.
- Pacotes locais recompilados do código `e9758d9`: MSI 0.4.0 `4f43265b…`, próximo 0.4.1 `9f8ff5e3…`. Os mesmos dois arquivos estão em `locations-input` e `session-input`; os geradores dos dois pacotes foram executados novamente. Nenhuma instalação ou execução de Sandbox foi feita.
- Correção encontrada pelo contrato nativo: `localhost` resolve IPv6 antes de IPv4 nesta máquina, e uma conexão IPv6 sem resposta consumia todo o prazo da sonda. Agora cada endereço recebe uma parte do prazo restante, reservando tempo para as próximas tentativas e o handshake. Regressão Rust verificada vermelha antes da correção; os dois contratos nativos com o servidor Python passaram no release corrigido.
- Limites: coleta de sinais locais fora do Windows fica para a F8. As sondas TLS compartilham dois segundos e quatro trabalhadores; com mais de quatro sondas silenciosas saturando o prazo, a prioridade de coleta gira entre ciclos e um local dependente de sonda pode levar mais de um ciclo para ser reconhecido. Na dúvida permanece a política externa.
- Validação local final (2026-10-25): **766 Python aprovados, 44 ignorados, cinco deselecionados** (`-m "not windows_only"`, agente nativo obrigatório, release final); **171 Rust**, `fmt --check`, `clippy --all-targets -- -D warnings` e `cargo build --release` aprovados; **54 testes do painel**, lint, tipos e build aprovados. Coverage do painel: 87,5% de linhas no total, 94,87% nas telas de locais, 98,62% em `lib/`; todos os gates passaram. PostgreSQL descartável verificou separadamente 109 contratos (um ignorado), e `app/network_locations.py` atingiu 100% de cobertura; o contêiner foi removido ao terminar. O Ruff geral encontra 15 problemas anteriores em arquivos sem mudanças nesta fase; arquivos da F6 passam. O build web mantém o aviso anterior de bundle maior que 500 kB. Nenhum push, PR ou CI foi disparado.

### Continuação — F5 parte 5c (branch `feature/session-component`, a partir da `main`; desenho em `session-component.md`)

- **Feito com TDD:**
  - `agent-rs/src/session.rs`: quadro `session.json` ao lado do `state.json` (SYSTEM grava; Administradores e Usuários leem, `D:P(A;;FA;;;SY)(A;;FR;;;BA)(A;;FR;;;BU)`), com `protected`, `last_contact` e até 20 avisos numerados em português. A numeração continua depois de reiniciar.
  - `runtime.rs`: aplicativo encerrado pela política vira aviso `app_closed`; aplicação ok → `protected`; sincronização ok → `last_contact`.
  - `src/bin/openems-session.rs`: segundo executável, sem console. Ícone (escudo do sistema) com a dica de estado e balão para avisos novos; mutex `Local\openems-session`; sai em `WM_CLOSE`/`WM_QUERYENDSESSION`/`WM_ENDSESSION`; refaz o ícone se o Explorer reiniciar. `--print --board PATH` mostra o mesmo em JSON, sem interface. Teste rápido no host: sobe, fica vivo e a segunda instância sai.
  - `src/session_launcher.rs` + `service.rs`: o serviço abre o componente em cada sessão ativa (`WTSEnumerateSessions`, `WTSQueryUserToken`, `CreateProcessAsUser`) a cada 15 s, e fecha todos antes de informar `Stopped` (upgrade e remoção não encontram o `.exe` em uso). `remove_protections` também fecha.
  - MSI: componente `SessionExecutable` com `openems-session.exe`; `tools/build-msi-fixtures.ps1` passa `-d SessionExe` (ao lado do `AgentExe`).
  - Testes: `agent-rs/tests/session.rs` (7), `tests/test_native_session.py` (3), contratos `tests/test_session_sandbox.py` (5). Rust 151, Python 733.
- **Aceite em Sandbox pendente (duas fases, com reboot):** `deploy/test-session-sandbox.ps1`. Pacote em `.venv/sandbox-acceptance/session-input` (MSIs recompilados após a F6: 0.4.0 `4f43265b…` e 0.4.1 `9f8ff5e3…`) e perfil `session.wsb`, gerados por `tools/build-msi-fixtures.ps1 -Production` (e `-Next`) e `python tools/build_session_sandbox.py`.
  - Para rodar: abrir `session.wsb` (Sandbox novo), Win+R → `C:\openems-input\RUN-SESSION-TEST.cmd`. Ao terminar a fase 1, **reiniciar o Sandbox por dentro** (Iniciar → Energia → Reiniciar) e rodar o mesmo comando de novo. Resultados: `results/session-phase1.json` e `results/session-result.json`.
  - Fase 1: componente na sessão do usuário; encerrado, volta; aplicativo bloqueado vira aviso; upgrade sem 3010; `Start=4` no registro e serviço parado. Fase 2: depois do boot, o watchdog restaura e inicia o serviço (`service_started_by_watchdog`), o componente volta, e a remoção fecha o componente e apaga o `.exe`.
  - A tarefa watchdog roda a cada 5 min: se a fase 2 demorar a começar, ela pode religar o serviço antes do reboot. O resultado continua valendo (o evento é o mesmo); só não separa o caminho do boot do periódico.

### Continuação — F5 parte 5b (branch `feature/uninstall-code`, criada a partir de `feature/tamper-protection`; decisões 5 a 7 do `tamper-protection.md`)

- **Feito (etapa 1 de 6, `dc58b02`):** primitivas do código de desinstalação, com paridade entre Python e Rust conferida por `contract/uninstall-vectors.json` (`tools/gen_uninstall_vectors.py`).
  - `agent/uninstall.py` (só biblioteca padrão, servidor e ferramenta offline) e `agent-rs/src/uninstall.rs` (HMAC-SHA256 implementado sobre o `sha2`, sem dependência nova).
  - Segredo = HMAC-SHA256(chave-mestra, `"openems-uninstall-v1\0" + client_id`). A chave tem no mínimo 32 bytes. Como o segredo vale por cadastro, reinstalar gera um segredo novo e invalida códigos antigos.
  - Código = HMAC-SHA256(segredo, contador u64 big-endian). Usa os 50 bits mais altos, escritos como 10 símbolos Crockford base32 no formato `XXXXX-XXXXX`. A normalização aceita minúsculas, espaços e traços, e lê O como 0 e I/L como 1.
  - A conferência aceita contadores em (último usado, último usado + 20]. A liberação de remoção é HMAC(segredo, `"openems-release-v1"`) em hex.
- **Feito (etapa 2 de 6, `a487a95` testes, `098f1a7` implementação):** `tools/uninstall_code.py --master-key-file PATH|- --client-id ID [--counter N] [--count 1..20]`.
  - A chave vem só de arquivo ou da entrada padrão. A ferramenta não repete argumentos desconhecidos (um `--master-key SEGREDO` não vaza no erro) e não mostra caminho nem conteúdo nos erros de leitura.
  - `master_key_from_text` em `agent/uninstall.py` fixa o formato da chave: texto UTF-8, sem BOM, aparado e com no mínimo 32 bytes. **A etapa 3 deve ler `OPENEMS_UNINSTALL_MASTER_KEY` por essa função**, para servidor e ferramenta não divergirem.
  - `--count 20` lista uma janela inteira (o último contador usado é desconhecido offline). Se todos forem recusados, continuar com `--counter 21`.
  - **Mudança no desenho:** o `--devid` foi retirado. O `client_id` é aleatório (`secrets.token_hex(16)`) e sua ligação com o `devid` só existe no banco. Na máquina, o `client_id` está em `C:\ProgramData\openems\state.json`. Na etapa 4, o agente deve mostrá-lo na mensagem que pede o código.
  - **Risco para as etapas 3 e 4:** `update_client_id` (`app/service.py`) troca o `client_id` e, com ele, o segredo derivado. O servidor precisa reenviar o segredo ao agente nesse caso. Senão, o código gerado com o `client_id` novo não bate com o segredo antigo guardado. (Resolvido no servidor na etapa 3; falta o agente na etapa 4.)
- **Feito (etapa 3 de 6, testes `947840b` e `b22b945`, implementação `f05421f`):** servidor. Módulo novo `app/uninstall_codes.py`.
  - **Mudança no desenho 1, entrega única com confirmação.** O `state.json` é legível por Administradores e guarda o `device_token`. Se o segredo fosse entregue sempre, um admin local o buscaria pela API e geraria os próprios códigos.
    - `POST /fct/api/public/v1/uninstall_secret/` com `{client_id}` → `{"secret": hex}`. Entrega o segredo enquanto o agente não confirma; depois disso, responde 409.
    - `POST /fct/api/public/v1/uninstall_secret/ack/` com `{client_id, proof}`, em que `proof = delivery_proof(secret)`: HMAC com o rótulo `openems-secret-delivered-v1`, já nos vetores. Prova errada → 403.
    - Admin: `POST /api/v1/endpoints/uninstall_secret/reset` com `{devid}` reabre a entrega para um agente que perdeu o `uninstall.json` (auditoria `endpoint.uninstall_secret.reset`).
  - **Mudança no desenho 2, contador numa tabela própria.** A tabela `uninstall_state` (chave `client_id`, migração `004_uninstall.sql`, também em `init_schema`) fica fora de `endpoints`, cujo `upsert` regrava a linha inteira e poderia desfazer um incremento. O incremento é atômico (`INSERT ... ON CONFLICT ... RETURNING`). Um `client_id` novo começa do zero: segredo novo, contador 0 e entrega pendente.
  - `POST /api/v1/endpoints/uninstall_code` com `{devid}` → `{devid, counter, code}`. Só admin. A auditoria `endpoint.uninstall_code` guarda o contador, nunca o código. Funciona também para máquina revogada.
  - `GET` e `POST /api/v1/uninstall_release` com `{scope, released}`: `scope` é um grupo ou `*` (frota inteira). Auditoria `uninstall.release` e `uninstall.release.revoke`. Vale pelo **grupo efetivo atual**. Para máquinas cobertas, `config/assigned` ganha `uninstall_release = release_token(secret)`, também quando `unassigned`.
  - `OPENEMS_UNINSTALL_MASTER_KEY` é opcional (vazio = desligado, e as rotas respondem 503) e é lida por `master_key_from_text`. O `docker-compose.yml` a repassa com `:-`. `deploy/new-env.ps1` gera 64 caracteres, avisa para guardar no cofre e **mantém a chave existente com `-Force`**. Nunca trocar a chave com agentes instalados.
  - `TAMPER_KINDS` (servidor e schema) inclui `uninstall_code_rejected` e `uninstall_without_secret`. Os rótulos no painel ficam para a etapa 5.
  - Corrigido também um defeito antigo: `test_concurrent_runners_apply_once` (só roda com `OPENEMS_TEST_DSN`) ainda esperava uma única migração (`1cd8a18`).
  - Postgres para os testes: contêiner descartável `docker run -d --rm --name openems-uninstall-pg -e POSTGRES_PASSWORD=pw -p 127.0.0.1:55432:5432 postgres:16` e `OPENEMS_TEST_DSN=postgresql://postgres:pw@127.0.0.1:55432/postgres`. O `openems-test-pg` antigo tem senha desconhecida.
  - Corrigido depois da etapa 3 (`5f4e205` teste, `ecc611a` correção): os testes de DNS do Rust falhavam de forma intermitente com WSAEACCES (10013). Causa: o Windows entrega portas UDP efêmeras por um cursor global que avança de 1 em 1, e Hyper-V/WSL/Docker reservam blocos TCP de até 300 portas seguidas. Com o cursor logo antes de um bloco, as 32 tentativas de `bind_pair` caíam todas nele. Agora só a primeira tentativa usa a porta do sistema; as seguintes sorteiam portas da faixa 49152–65535. Produção não era afetada, porque o agente abre a porta fixa 53. Reprodução: avançar o cursor UDP até 57253 e rodar `cargo test --test dns_resolver`.
- **Feito (etapa 4 de 6, de `3127e48` a `9cc4853`):** agente.
  - Paridade em Rust: `derive_secret`, `delivery_proof` e `master_key_from_text` em `agent-rs/src/uninstall.rs`, conferidos pelos vetores. `TamperKind` ganhou `uninstall_code_rejected` e `uninstall_without_secret`.
  - `agent-rs/src/removal.rs`: `uninstall.json` ao lado do `state.json` com `client_id`, segredo (hex), `acked`, `last_used`, `failures`, `locked_until` e `release`. Gravado só para SYSTEM (`D:P(A;;FA;;;SY)`) quando o processo é SYSTEM; fora dele (testes, `run` manual), com a permissão privada comum.
  - Decisão (`authorize`), nesta ordem:
    - liberação válida → remove;
    - bloqueado → recusa;
    - sem código → recusa, mostrando o `client_id`;
    - código válido → grava o contador e remove;
    - código errado → conta o erro; 5 erros = bloqueio de 1 h, com evento `uninstall_code_rejected`.
  - Sem segredo guardado, o agente pergunta ao servidor:
    - 200 → grava e passa a exigir o código;
    - 409 → recusa (o arquivo foi apagado depois da entrega);
    - sem resposta → remove e registra `uninstall_without_secret`.
  - Proteções contra atalhos:
    - acesso negado ou JSON danificado recusam a remoção, em vez de contarem como "sem segredo";
    - `state.json` danificado não dispensa o segredo guardado;
    - um `client_id` editado no `state.json`, sem resposta do servidor, mantém o segredo guardado (o `state.json` é gravável por Administradores).
  - Sincronização (`runtime.rs`, `sync_uninstall`): busca, grava, confirma; com `client_id` novo, troca o segredo. Resposta 404/405/409/503 → tenta de novo depois de 1 h. A liberação de `config/assigned` é espelhada, e some quando o campo some.
  - Comandos:
    - `installer-prepare --remove --uninstall-code X`: confere antes de qualquer mudança. `--uninstall-code` sem `--remove` é erro, validado no código, porque o `requires` do clap não funciona com o flag booleano.
    - `uninstall-service --uninstall-code X`.
    - Novo `cleanup --uninstall-code X` (Windows): remove serviço, tarefa, `hosts`, confiança, NRPT, WFP e políticas de navegador. A remoção de proteções foi extraída para `remove_protections`, usada também por `prepare_removal`.
    - Todos exigem SYSTEM na prática, porque o `uninstall.json` só é legível pelo SYSTEM; a mensagem de acesso negado orienta a usar o `msiexec /x` ou rodar como SYSTEM.
  - Eventos na remoção: enviados na hora (o serviço está parado) e, sem servidor, gravados em `tamper-pending.json`. Cada chamada ao servidor tem o limite de 10 s do `ApiClient`, então uma remoção sem rede pode levar até ~20 s.
  - `openems-agent uninstall-code --master-key-file PATH|- --client-id ID [--counter N] [--count 1..20]`: saída idêntica à de `tools/uninstall_code.py`, conferida em `tests/test_native_uninstall.py`. Erros de argumento desse subcomando são genéricos, para nunca repetir uma chave digitada.
  - Testes: `agent-rs/tests/removal.rs` (13) e `tests/test_native_uninstall.py` (7). **Os testes nativos usam `target/release` primeiro: rode `cargo build --release` antes.** A remoção real (SYSTEM) fica para o aceite da etapa 6.
  - O `uninstall.json` fica na máquina depois da remoção, como o `state.json`. Numa reinstalação com o mesmo cadastro, o contador continua e um código já usado não vale de novo.
- **Feito (etapa 5 de 6, de `54be26a` a `2ae8740`):** MSI e painel.
  - MSI: `UNINSTALLCODE` com `Secure` e `Hidden` (entra em `MsiHiddenProperties`), repassada só a `PrepareAgentRemoval` (`installer-prepare --remove --uninstall-code "[UNINSTALLCODE]"`, `HideTarget="yes"`). `tests/test_native_uninstall.py` compila o MSI com o WiX portátil e lê as tabelas pelo COM do Windows Installer.
  - **Decisão: a conferência continua depois de `StopServices`.** Antecipá-la exigiria uma marca de autorização entre duas ações, porque conferir grava o contador. Custo aceito: com código errado, o serviço fica parado alguns segundos (até ~20 s sem rede) até o rollback do MSI, e a tarefa watchdog também o reinicia.
  - "Programas e Recursos" não pede o código: com segredo ativo, a remoção falha ali com o erro 1603, e o motivo fica no log do MSI. Comando documentado no topo do `.wxs`: `msiexec /x openems-agent.msi /qn UNINSTALLCODE=XXXXX-XXXXX`.
  - Painel (só admin; leitores não veem nada):
    - ficha da máquina (`UninstallSection.tsx`): "Gerar código de desinstalação" mostra o código uma vez, com cópia, e ele não entra no cache; "Reabrir entrega do segredo" pede confirmação;
    - página Endpoints (`ReleaseDialog.tsx`): "Liberar desinstalação" por grupo efetivo ou "Toda a frota", com aviso, lista e revogação;
    - sem chave-mestra (503) ou em servidor antigo (404), o botão some e a ficha explica;
    - rótulos em português de `uninstall_code_rejected` e `uninstall_without_secret`.
  - Testes do painel em `web/src/features/endpoints/uninstall.test.tsx` (8). Conferido no navegador no modo mock (`panel-mock-repo`, porta 5174).
- **Etapa 6 de 6: aceite em Sandbox aprovado em 2026-10-25 (11/11)**, em `validation/sandbox-uninstall-2026-10-25.json` (roteiro: `6c95b5d` contratos, `4c17d6d` roteiro). Remoções levam ~2 s. As instalações levam ~122 s, como nos aceites anteriores (antiadulteração e MSI): é do ambiente do Sandbox, não desta parte. **A parte 5b está completa.** Commits ainda só locais na `feature/uninstall-code`.
  - Roteiro `deploy/test-uninstall-sandbox.ps1`, com contratos em `tests/test_uninstall_sandbox.py`:
    - `-Plan`;
    - `-SelfTest` reproduz `contract/uninstall-vectors.json` com o HMAC do .NET;
    - recusa rodar fora do Sandbox;
    - a fase de testes roda como SYSTEM, por tarefa agendada.
  - Servidor simulado em PowerShell em `127.0.0.1:18014`, com `client_id` fixo `sandbox-uninstall`. Ele entrega o segredo até a prova (depois responde 409) e publica `uninstall_release` quando existe o marcador `backend-release`. Com `backend-disabled`, responde 503 e simula o servidor sem chave-mestra.
  - Pacote em `.venv/sandbox-acceptance/uninstall-input`:
    - `openems-agent.msi` 0.4.0 (sha256 `4304928e…`) e `openems-agent-next.msi` 0.4.1 (`878871f4…`), ambos do código atual, gerados com `tools/build-msi-fixtures.ps1 -Production` (e `-Next`), WiX portátil e `DOTNET_ROOT=.venv/dotnet-sdk`;
    - `master.key`: a chave **só de teste** dos vetores;
    - `codes.json`: 20 códigos gerados no host por `tools/uninstall_code.py`;
    - o roteiro e `RUN-UNINSTALL-TEST.cmd`.
  - Perfil `.venv/sandbox-acceptance/uninstall.wsb`: entrada só leitura, resultados em `results/`, sem área de transferência e com a rede ligada, como o de antiadulteração.
  - **Para rodar:** abrir `uninstall.wsb` (Sandbox novo) e fazer Win+R → `C:\openems-input\RUN-UNINSTALL-TEST.cmd`. Leva uns 25 min. Resultado em `results/uninstall-result.json`; se `passed: true`, preservar em `validation/sandbox-uninstall-<data>.json`.
  - Cenários, nesta ordem; o bloqueio fica por último porque dura 1 h e o `uninstall.json` sobrevive às reinstalações:
    1. o segredo é entregue e confirmado;
    2. sem código: recusa e rollback;
    3. código errado: recusa, rollback e evento;
    4. upgrade sem código;
    5. código 1 remove, e o log do MSI não contém o código;
    6. reinstalação: código 1 recusado, código 2 remove;
    7. liberação recebida e servidor parado: remove sem código;
    8. servidor parado: código do `openems-agent uninstall-code` remove;
    9. remoção forçada (extração `/a` + `install-service`): `cleanup` sem código falha, com código remove;
    10. sem segredo: remove e reporta `uninstall_without_secret`;
    11. 5 erros: o código certo é recusado e nenhum código é consumido.
  - **Se mudar o agente ou o roteiro:** recompilar o release, gerar os dois MSIs de novo e recriar o resto com `python tools/build_uninstall_sandbox.py` (chave dos vetores, 20 códigos de `tools/uninstall_code.py`, roteiro, `.cmd` e `uninstall.wsb`).

### Continuação — F5 parte 5a (branch `feature/tamper-protection`, criada a partir de `feature/block-log`; `tamper-protection.md` aprovado em 2026-10-24 com 7 decisões)

- Feito com TDD:
  - `agent-rs/src/hardening.rs`: DACL do serviço (`SERVICE_SDDL`: SYSTEM com controle total; Administradores consultam e iniciam; usuários autenticados só consultam), decisões do watchdog agendado (não age com o Windows Installer em execução), executor de verificações (repara, registra e desliga a verificação cujo reparo não se mantém) e marcador `running.marker`.
  - `agent-rs/src/tamper.rs`: fila de eventos de adulteração (8 tipos, o mesmo tipo no máximo uma vez a cada 10 min, limite de 200) e o arquivo `tamper-pending.json`, que o watchdog agendado escreve e o serviço lê na partida.
  - Agente: saída inesperada e bloco do `hosts` reescrito sem mudança de política viram eventos enviados para `POST /fct/api/public/v1/tamper/`. Contratos nativos em `tests/test_native_tamper.py`.
  - Servidor: `TamperEvent`, migração `003_tamper_events.sql`, a mesma retenção do registro de bloqueios, e `/api/v1/events` mistura `web_block` e `tamper` por horário.
- Camada Windows (só compilada e testada em unidade neste host; **o aceite em Sandbox é a prova**):
  - `configure-recovery` (MSI) e `install-service` aplicam `SERVICE_SDDL`. Consequência: `uninstall-service` pela linha de comando só funciona como SYSTEM; o caminho oficial é o MSI.
  - O serviço roda um thread watchdog a cada 15 s: regra NRPT, lida no registro em `Dnscache\Parameters\DnsPolicyConfig` sem PowerShell; filtros WFP, pela contagem do provider; tipo de início, recuperação e DACL. A tarefa agendada é conferida a cada 4 ciclos. Política de navegador reaplicada gera evento.
  - `openems-agent watchdog` é a tarefa SYSTEM `openems-agent watchdog`, no boot e a cada 5 min. Não age enquanto o mutex `Global\_MSIExecute` existe e grava os eventos em `tamper-pending.json`. É criada pelo serviço e removida por `installer-prepare --remove` e por `uninstall-service`.
  - Painel: tipos de `tamper` em português.
  - MSI de produção agora é 0.4.0, e `-Production -Next` gera o 0.4.1 para o teste de upgrade.
- Suíte: **640 Python, 125 Rust, 35 Vitest**.
- Aceite: `deploy/test-tamper-sandbox.ps1` (contratos em `tests/test_tamper_sandbox.py`). Pacote em `.venv/sandbox-acceptance/tamper-input`: anterior 0.3.0 (`723f990d…`), atual 0.4.0 (`ee9abe9d…`) e próximo 0.4.1 (`c48130af…`). Abrir `tamper.wsb` e rodar Win+R → `C:\openems-input\RUN-TAMPER-TEST.cmd`; leva uns 20 min.
- **Aceite em Sandbox aprovado em 2026-10-25 (11/11)**: `validation/sandbox-tamper-2026-10-25.json`. Usuário comum e administrador recebem acesso negado ao parar, reconfigurar ou remover o serviço. NRPT, política de navegador, recuperação, DACL e tarefa são restaurados e reportados. O serviço morto volta pela recuperação, e o desativado e parado volta pela tarefa. O upgrade nos dois sentidos e a remoção funcionam. As tentativas anteriores falharam em defeitos do roteiro (Windows em português, redirecionamento do cmd, stderr nativo no PowerShell 5.1) e num defeito do agente: o evento do watchdog só era lido na partida, corrigido em `4c4271b`.
- Próximo: parte 5b (código de desinstalação, liberação e ferramenta offline), já aprovada no `tamper-protection.md`.

### Continuação — F2 parte 4b (branch `feature/block-log`, `web-block-log.md` aprovado em 2026-10-24)

- Feito com TDD:
  - Motivo do bloqueio (regra ou primeira categoria ativa) em `agent/policy.py` (`block_reason`) e no Rust (`block_reason_at`), com paridade nos vetores. Os nomes das categorias também estão nos vetores e no agente, para a página de bloqueio funcionar offline.
  - Agente (`agent-rs/src/events.rs`): as respostas DNS bloqueadas são agregadas por hora, domínio e motivo (regra, categoria ou DoH). Cada uma conta no máximo uma vez por minuto, com limite de 5.000 linhas e contador de descartes. Ficam só em memória e são enviadas a cada sincronização para `POST /fct/api/public/v1/events/`. Um servidor sem a rota (404/405) é registrado uma vez no log e as linhas são descartadas. SafeSearch e o canário do Firefox não entram.
  - Página de bloqueio (HTTP e HTTPS): "Categoria: Jogos" quando o bloqueio vem de uma categoria.
  - Servidor (`app/events.py`, migração `002_block_events.sql`): linhas inválidas são ignoradas e contadas. O servidor recusa hora fora da janela de retenção ou mais de 1 h no futuro, motivo ou categoria inconsistentes e domínio inválido. A retenção vem de `OPENEMS_EVENT_RETENTION_DAYS` (30 por padrão, de 1 a 365), e o vencido é apagado a cada envio.
  - Painel: `/api/v1/events`, `/api/v1/stats/overview` (7 dias por dia em UTC, os 5 domínios mais bloqueados, comparação só de bloqueios, retenção) e `/api/v1/categories` (sem digests, com atribuição). Cada leitura é auditada uma vez por administrador, rota e hora (`events.read`). `missing_capabilities` aparece em cada endpoint e `warnings` no `POST /api/v1/profiles/{vdom}` (`app/capabilities.py`).
  - React: os eventos mostram categoria e contagem, com o aviso de dado pessoal e os dias de retenção. A ficha da máquina avisa quando o agente não aplica parte da política. A página "Filtro web" lista as categorias publicadas por grupo, com a atribuição; a escolha por política fica para o editor da F7.
  - Deploy: `tools/update_categories.py --url ... --every-hours 24` baixa só por HTTPS (inclusive redirecionamentos), com limite de tamanho, e extrai apenas arquivos `<lista>/domains`. Recusa `..`, caminho absoluto, barra invertida e link no lugar de lista. O serviço `categories` do compose é opcional (`--profile categories`) e `OPENEMS_UT1_URL` não tem valor padrão até a licença ser confirmada. **Corrigido:** a imagem não copiava `agent/categories.py`, e sem ele o servidor não subia.
- Suíte: **619 Python aprovados, 42 ignorados, 5 deselecionados; 115 Rust; 34 Vitest**. Painel conferido no navegador com dados simulados. Build Docker, PostgreSQL e compose **não** validados localmente: os testes com banco são ignorados sem `OPENEMS_TEST_DSN`.
- Aceite: `deploy/test-categories-sandbox.ps1` ganhou duas verificações: o registro de bloqueios chega ao servidor simulado com `category=games` (nunca o nome liberado), e o Edge mostra "Categoria: Jogos". O pacote está em `categories-input` (MSI `723f990d…`) e o `categories.wsb` é o mesmo.
- **Aceite em Sandbox aprovado em 2026-10-24 (7/7)**, com o Edge confirmado pelo operador: `validation/sandbox-blocklog-2026-10-24.json`.
- Antes da produção: validação LGPD do registro de bloqueios pela RSM (jurídico/DPO), confirmação da licença e do endereço oficial da UT1, e validação da imagem Docker, do PostgreSQL e do compose num servidor real.

### Continuação — F2 antiburla (branch `feature/dns-anti-bypass`, `dns-anti-bypass.md` aprovado em 2026-10-23)

- Feito com TDD:
  - `contract/doh-endpoints.json`: lista de melhor esforço de hosts e IPs de DoH/DoT públicos, validada por `tests/test_doh_endpoints.py`. O resolvedor responde NXDOMAIN para esses nomes e os subdomínios.
  - Opção `anti_bypass`, que exige `dns_filter`: CLI `--anti-bypass`, MSI `ANTIBYPASS=1`, preservada em upgrade e gravada só quando ligada. Tag `web-filter:anti-bypass`.
  - Políticas de navegador em HKLM (`browser_policy.rs`): Chrome e Edge com `DnsOverHttpsMode=off`; Firefox com `DNSOverHTTPS` desligado e travado e `ImportEnterpriseRoots=1`.
    - O serviço grava antes de abrir qualquer listener e confere a cada 60 s.
    - Os valores originais são salvos uma vez, antes da primeira escrita, em `browser-policies.json` ao lado do `state.json`, e a desinstalação os restaura. Testado com registro simulado e uma leitura do registro real.
  - Filtros WFP (`wfp.rs`): provedor e subcamada próprios. A permissão de loopback (peso 15) e a do executável do agente nas portas 53/853 (peso 14) vencem os bloqueios dos IPs de DoH nas portas 443/853 (peso 12) e das portas 53/853 (peso 10).
    - Os filtros não são persistentes nem presos à sessão, então um travamento os mantém e um reinício os apaga.
    - Na parada normal, saem antes da regra NRPT; se a criação falhar, o agente devolve o DNS; a desinstalação remove sobras.
    - O plano e a arbitragem são testados como dados. As chamadas reais ao WFP só rodam no Sandbox.
- Suíte: **543 Python aprovados, 41 ignorados, 5 deselecionados; 108 Rust**. A compilação para Linux (CI) não foi verificada localmente: só o alvo Windows está instalado.
- Aceite `deploy/test-antibypass-sandbox.ps1` (contratos em `tests/test_antibypass_sandbox.py`). As sondagens partem de um processo que não é o agente: DNS cru para o primeiro DNS da placa que responde, TCP 443/853 para `1.1.1.1` e NXDOMAIN para nomes de DoH, cada uma comprovada antes da instalação.
  - Também verifica: HKLM; Edge (DNS seguro desligado e gerenciado, e página de bloqueio) confirmado pelo operador; processo morto e parada normal; desinstalação.
- Pacote: `.venv/sandbox-acceptance/antibypass-input/` (MSI sha256 `ffdec33d…`) e `antibypass.wsb`, com rede. Win+R → `C:\openems-input\RUN-ANTIBYPASS-TEST.cmd`; relatório em `results/antibypass-result.json`. - **Aceite real concluído em 2026-10-23, 16:47:** 9 de 9 cenários, `passed: true`, com os filtros WFP reais. Edge confirmado pelo operador: página de bloqueio, e DNS seguro desligado e gerenciado em `edge://settings/privacy`, aberto à mão porque o Edge ignora URLs `edge://` na linha de comando. Evidência em `validation/sandbox-antibypass-2026-10-23.json`.
- A primeira tentativa falhou antes de instalar por um defeito do roteiro: uma edição feita pelo bash expandiu `$servers` para vazio. Corrigido em `1c05b59`; o novo `tests/test_sandbox_scripts.py` verifica todos os roteiros.
- Fora do aceite: Firefox e Chrome em execução (só os valores em HKLM foram verificados), máquina física com FortiClient, DoH privado ou fora da lista, servidor real, painel, build Linux e assinatura.

### Continuação — F2 SafeSearch e horários (branch `feature/dns-safesearch-schedules`, `dns-safesearch-schedules.md` aprovado em 2026-10-23)

- Feito com TDD:
  - Referência Python: `safe_search` (google, bing, youtube, duckduckgo; YouTube `strict` ou `moderate`), `timezone` IANA obrigatório com `scheduled`, janelas `{blocked, days, from, to}` com fim exclusivo, `allowed` vencendo tudo. Domínios do Google tirados de https://www.google.com/supported_domains (187). `tzdata==2026.5` fixado.
  - Vetores compartilhados de validação, decisões em horários fixos, alvos de SafeSearch e lista do Google.
  - Rust (`WebFilter`): fuso pela base IANA embutida (`jiff`, `tzdb-bundle-always`), independente do fuso do Windows; o executável passou de 4,28 para 4,88 MB.
  - Resolvedor: A/AAAA de buscador ativado → CNAME para o host seguro mais os registros dele no upstream. O nome original do buscador nunca é encaminhado. Os outros tipos recebem NODATA, e qualquer falha no upstream vira SERVFAIL. Bloqueio vence; `allowed` mantém o SafeSearch.
  - Serviço: horários avaliados a cada consulta; o `hosts` é reescrito pelas janelas abertas em cada ciclo. No modo DNS, o cache do Windows é limpo quando a política ou as janelas abertas mudam. Isso corrigiu uma promessa do recorte 1: a limpeza só acontecia quando o `hosts` mudava, e um nome recém-bloqueado ficava no cache até o TTL. Nova tag `web-filter:v2`.
  - Referência Python: itens não textuais em `engines` e `days` passaram a ser erro de validação (antes, `TypeError` → 500).
- Suíte: **535 Python aprovados, 41 ignorados, 5 deselecionados; 92 Rust**.
- Aceite `deploy/test-safesearch-sandbox.ps1` (contratos em `tests/test_safesearch_sandbox.py`): monta as políticas pelo horário UTC atual (uma janela aberta, outra fechada) e calcula o digest em PowerShell, conferido com o Python em três horários.
  - Verifica bloqueio e liberação por horário, os CNAMEs dos quatro buscadores e o SafeSearch travado no Google pelo Edge, confirmado pelo operador.
  - Verifica que uma política nova limpa o cache, consultando sem limpar o cache, e a desinstalação.
  - Recusa rodar entre 23:40 e 00:00 UTC, e também se o host já filtrar os nomes ou já forçar SafeSearch.
- Pacote: `.venv/sandbox-acceptance/safesearch-input/` (MSI de produção sha256 `72af9b37…`) e `safesearch.wsb`, com rede. Iniciar com Win+R → `C:\openems-input\RUN-SAFESEARCH-TEST.cmd`; relatório em `results/safesearch-result.json`. - **Aceite real concluído em 2026-10-23, 15:38:** 5 de 5 cenários, `passed: true`, na primeira tentativa. SafeSearch do Google travado confirmado no Edge ("Filtro ativado" com cadeado e aviso de que o administrador controla a rede). Evidência em `validation/sandbox-safesearch-2026-10-23.json`.
- Fora do aceite: modos restritos de YouTube, Bing e DuckDuckGo no navegador (só os CNAMEs foram verificados), máquina física, Chrome/Firefox, DoH (recorte 3), servidor real, aviso no painel e assinatura.

### Continuação — F2 resolvedor DNS (branch `feature/dns-resolver`, `dns-resolver.md` aprovado em 2026-10-23)

- Feito, com TDD (testes vermelhos commitados antes de cada unidade):
  - Política: `*.dominio` cobre o domínio e todos os subdomínios. `web_filter.allowed` vence o bloqueio. Python (`agent/policy.py`) é a referência, com `normalize_domain_rule`, `domain_blocked` e `hosts_names`. Os vetores novos `domain_rules`, `matches` e `hosts_names` em `contract/policy-vectors.json` são lidos pelo Rust (`WebRules`).
  - No modo `hosts`, o curinga vira só o domínio e o `www.` (melhor esforço). A página HTTPS autoriza SNI e Host pela mesma regra. O agente Python também respeita `allowed`.
  - `agent-rs/src/dns.rs`: respostas locais para nomes bloqueados (127.0.0.1/::1 com a página, 0.0.0.0/:: sem ela, TTL 30 s, NODATA para os outros tipos), NXDOMAIN para `use-application-dns.net`, encaminhamento por UDP conectado com checagem de ID e pergunta, nova tentativa por TCP quando a resposta vem truncada, SERVFAIL ao estourar o orçamento, limites de concorrência.
  - Upstream: lido das placas ativas por `GetAdaptersAddresses`, com cache de 5 s. Testado no host só em leitura; encontrou o DNS da rede local.
  - Configuração `dns_filter`/`dns_port` e `--dns-filter`/`--dns-port`; `run-once` recusa o modo DNS. O serviço escuta em 127.0.0.1 e, se houver, em [::1], e no modo DNS remove o bloco gerenciado do `hosts`.
- Regra NRPT, decisão aprovada em 2026-10-23: o serviço é o dono (`agent-rs/src/nrpt.rs`).
  - Ele cria a regra para o namespace `.` apontando para o loopback só depois de escutar na porta 53 e a remove ao parar normalmente; um travamento deixa a regra.
  - Antes de criar, remove somente sobras com o mesmo comentário, namespace e servidores de loopback. Os scripts vão por `-EncodedCommand`, e um teste verifica a sintaxe no parser do PowerShell sem executar.
- MSI `DNSFILTER=1` e `installer-prepare --dns-filter`: opt-in, reservam a porta 53 (UDP e TCP) antes de qualquer mudança e preservam o cadastro, gravando a chave `dns_filter` só quando ela é ligada. Na desinstalação, o instalador remove uma sobra de NRPT.
- Tag `web-filter:dns` enviada quando o modo DNS está ativo.
- Suíte: **498 Python aprovados, 41 ignorados, 5 deselecionados; 80 Rust**. O WXS compila. **Nada foi executado no DNS desta máquina**: a regra NRPT real só será criada no Sandbox.
- Roteiro de aceite `deploy/test-dns-sandbox.ps1`, com contratos em `tests/test_dns_sandbox.py`. Usa o MSI de produção com `BLOCKPAGEHTTPS=1 DNSFILTER=1` e verifica sempre pelo caminho do sistema (sem `-Server`):
  - regra NRPT exata;
  - curinga bloqueando o domínio e os subdomínios, em A e AAAA;
  - nomes permitidos e não listados resolvendo pelo upstream;
  - `hosts` sem bloco gerenciado;
  - página HTTPS confiável para um subdomínio do curinga;
  - Edge confirmado pelo operador;
  - processo morto mantendo a regra e recuperação;
  - política nova sem reiniciar;
  - parada normal devolvendo o DNS e início recriando a regra;
  - desinstalação restaurando as regras NRPT, a confiança e o `hosts`.
- Pacote local em `.venv/sandbox-acceptance/dns-input/` e perfil `dns.wsb`, **com rede**, necessária para o upstream real. Iniciar com Win+R → `C:\openems-input\RUN-DNS-TEST.cmd`; relatório em `results/dns-result.json`.
- **Aceite real concluído em 2026-10-23, 14:52:** 8 de 8 cenários, `passed: true`, Edge confirmado pelo operador. Evidência em `validation/sandbox-dns-2026-10-23.json` (hash do MSI de produção).
  - Tentativas anteriores: na primeira, o proxy DNS do Sandbox resolve pelo host, e o agente openems do host bloqueia `example.com`. Corrigido trocando os nomes de teste para `iana.org` e conferindo antes de instalar (`d468da4`).
  - Na segunda, o serviço não informava `STOP_PENDING` enquanto removia a regra, e o `Stop-Service` falhava. Corrigido no serviço (`48bef1c`); um administrador num computador real teria o mesmo erro.
- Fora do aceite: máquina física com VPN e portal cativo, Chrome/Firefox, servidor real, DoH configurado no navegador (recorte 3) e assinatura. Depois, categorias da F2, recorte 4: taxonomia no estilo FortiGuard com listas abertas, sem a base da Fortinet.

### Continuação — resiliência do serviço (branch `feature/native-resilience`, plano A aprovado em 2026-10-23)

- Roteiro `deploy/test-resilience-sandbox.ps1` em duas fases, com contratos em `tests/test_resilience_sandbox.py`, verificados vermelhos antes da implementação. **Fase 1** (Sandbox novo): instala o **MSI de produção**, confirmando na tabela CustomAction que não há ações de injeção de falha, com `BLOCKPAGEHTTPS=1`. Depois verifica: TLS confiável servido pelo próprio serviço; processo morto reiniciado pela recuperação do serviço; backend fora do ar por 60 s sem perder bloqueio/página nem trocar de processo; nova sincronização (`config/assigned`) em até 360 s após o retorno. Termina com o backend parado e o marcador `C:\openems-resilience\phase1.json`. **Fase 2** (após reiniciar o Sandbox por dentro): exige boot posterior, backend ausente e serviço automático servindo TLS com a política em cache; depois desinstala e confere raízes e hosts originais.
- `tools/build-msi-fixtures.ps1 -Production` gera `openems-agent.msi` 0.3.0 sem defines. Pacote local em `.venv/sandbox-acceptance/resilience-input/` (MSI, roteiro, `RUN-RESILIENCE-TEST.cmd`, `diagnose.ps1`) e perfil `resilience.wsb` (sem rede, sem clipboard, sem LogonCommand). Relatórios: `results/resilience-phase1.json` e `results/resilience-result.json`.
- Suíte local: **471 aprovados, 41 ignorados, 5 deselecionados**.
- Primeira tentativa (10:47) falhou antes de instalar: `Join-Path` passava um caminho embrulhado em PSObject ao COM do Windows Installer (`DISP_E_TYPEMISMATCH`). Reproduzido no host somente leitura, teste de regressão antes da correção (`713125c`).
- **Aceite real concluído em 2026-10-23:** fase 1 (10:56) e fase 2 (11:05) com `passed: true`, sem erros de limpeza e sem raízes não relacionadas. O Windows Sandbox desta máquina **preserva o estado ao reiniciar por dentro**, então reboot pode ser testado nele. Evidência em `validation/sandbox-resilience-2026-10-23.json` (hash do MSI de produção 0.3.0). Fica fora: endpoint físico/soak longo, servidor real, assinatura, segunda máquina e componente de sessão/antiadulteração.

### Continuação — transação MSI (`PLAN-installer-blockpage.md`, passos 1–6)

- MSI com `BLOCKPAGE=1` / `BLOCKPAGEHTTPS=1` (opt-in; HTTPS implica HTTP; outro valor aborta). Upgrade sem `SERVER` preserva cadastro/configuração (`MajorUpgrade` em `afterInstallInitialize`).
- Ações `installer-prepare` / `installer-rollback` / `installer-commit` (`agent-rs/src/installer.rs`) executadas do executável embutido na tabela Binary. Journal SYSTEM-only em `ProgramData\openems\installer-transaction` com snapshots de config, state, hosts, backup do hosts e autoridade (bytes + ACL); rollback remove só a raiz criada pela transação e recusa restaurar se o arquivo mudou fora dela. Portas do bloqueio são reservadas antes de qualquer mudança. Journal não finalizado bloqueia a próxima instalação com diagnóstico (não é reparado automaticamente).
- Injeção de falha `FAIL_SETUP` / `FAIL_REMOVAL` existe apenas em builds com `-d FaultInjection=1` (`tools/build-msi-fixtures.ps1`); tabela InstallExecuteSequence do MSI de produção conferida sem essas ações.
- Fixtures 0.2.0/0.2.1/0.2.2 compiladas com WiX 5.0.2 portátil (`.venv/wix-tools`, `DOTNET_ROOT=.venv/dotnet-sdk`) em `.venv/sandbox-acceptance/msi-input/`, com roteiro e `RUN-MSI-TEST.cmd`. Perfil `.venv/sandbox-acceptance/msi-acceptance.wsb`: rede desabilitada (backend simulado é loopback), clipboard desabilitado, entrada somente leitura. Resultado esperado em `results/msi-result.json`.
- Verificação: Rust fmt/Clippy/testes e release OK; **460 Python aprovados, 41 ignorados, 5 deselecionados** com o binário release. Pendentes depois do aceite: passo 7 (pacote para segunda máquina, Firefox/Chrome) e assinatura.
- **Primeira tentativa real (2026-10-22, 17:12):** `passed: false`, "MSI operation timed out", zero checks. Diagnóstico (`msi-input/diagnose-msi.ps1`, somente leitura, grava `results/msi-diagnostics.txt`) mostrou que a instalação limpa 0.2.0 com `BLOCKPAGEHTTPS=1` **terminou com êxito em ~2 s** e o serviço escutava 127.0.0.1:443/80. Causa: `Start-Process -PassThru` no PowerShell 5.1 não detectou o fim do `msiexec`. Corrigido com `Diagnostics.Process` + `UseShellExecute=$false` (teste de regressão antes da correção, commit `ea65941`). Relatório antigo preservado como `results/msi-result-timeout-1712.json`; não vale como evidência. A confiança/TLS e os outros 4 cenários não foram verificados.
- **Segunda tentativa (2026-10-23, 09:09):** timeout de novo, zero checks. Log: `msiexec` ficou ~2 min em "SOFTWARE RESTRICTION POLICY: Verifying package" (fixtures não assinadas, Sandbox sem rede) e depois instalou em ~2 s. `Stop-Job` do backend ficou preso em `GetContext()` até a primeira requisição do agente, por isso o relatório coincidiu com o fim da instalação. Corrigido em `c4424e0`: 240 s por operação, 1500 s no total, `durations` no relatório e backend interrompível; perfil `msi-acceptance.wsb` agora com rede habilitada (backend continua em loopback). Relatório preservado como `results/msi-result-timeout-0911.json`. Rodar o teste só uma vez por Sandbox: uma execução manual simultânea falha com "soquete proibido" porque a primeira já ocupa a porta 18013.
- **Terceira tentativa (2026-10-23, 09:27, rede habilitada):** instalação limpa OK (123 s; a espera de ~2 min na verificação de assinatura persistiu mesmo com rede) e `Wait-Healthy` aprovado, ou seja, serviço próprio servindo TLS confiável sem bypass. Falhou em "Installation must add one root": contagem de raízes não é confiável porque o Windows pode adicionar raízes próprias. Além disso o roteiro rodou **duas vezes** sem ação do usuário (provável repetição do LogonCommand); a segunda falhou com "soquete proibido". Corrigido em `b98225c`: impressão digital exata da raiz gerenciada lida de `authority.json`, preservação das raízes da linha de base, `unrelated_roots_added` no relatório e lock `C:\openems-msi-acceptance.lock` que recusa segunda execução. Rede do perfil desabilitada de novo. Relatório preservado como `results/msi-result-rootcount-0930.json`. Upgrade, falhas injetadas e remoção ainda não executados.
- Causa da execução dupla confirmada pelo usuário: o LogonCommand roda o teste **sem janela visível**, e o usuário também o iniciava por Win+R; a execução manual era a que falhava rápido com "soquete proibido". O perfil `msi-acceptance.wsb` agora **não tem LogonCommand**: iniciar só por Win+R → `C:\openems-input\RUN-MSI-TEST.cmd`.
- **Quarta tentativa (2026-10-23, ~09:45, só Win+R):** instalação limpa aprovada (check 1) e upgrade 0.2.1 concluído (123 s cada). Falhou na comparação de identidade porque `agent.json` não serializa `device_token` (o cadastro fica em `state.json`). Corrigido em `574a610`: configurações de `agent.json`, `client_id`/`device_token` de `state.json`, também verificados após falha de upgrade e de remoção; valores nunca vão para o relatório. Relatório preservado como `results/msi-result-identity-0951.json`.
- **Aceite real do MSI concluído em 2026-10-23, 10:23:** quinta tentativa com `passed: true`, `error: null`, `cleanup_errors: []` e nenhuma raiz não relacionada. Cinco cenários aprovados: instalação limpa HTTPS com raiz própria e TLS servido pelo serviço; upgrade sem `SERVER` preservando identidade, confiança, hosts e serviço; upgrade com falha injetada restaurando serviço e confiança; remoção com falha injetada restaurando autoridade, confiança, hosts e serviço; remoção concluída restaurando raízes e hosts originais. Evidência em `validation/sandbox-msi-2026-10-23.json` (hashes das fixtures). Passos 1–6 do `PLAN-installer-blockpage.md` concluídos. Pendentes: passo 7 (pacote para a segunda máquina, Chrome/Firefox), MSI de produção num endpoint real, assinatura, recuperação/reboot e integração com servidor real.
- Instruções para repetir o aceite (se fixtures/roteiro mudarem): abrir um Sandbox **novo** pelo `.venv/sandbox-acceptance/msi-acceptance.wsb` no host (não dentro de outro Sandbox). Iniciar por Win+R → `C:\openems-input\RUN-MSI-TEST.cmd` (o perfil não inicia nada sozinho). Depois ler `results/msi-result.json` e, se `passed: true`, preservar em `validation/sandbox-msi-<data>.json`. Se as fixtures/roteiro mudarem, recompilar com `tools/build-msi-fixtures.ps1 -Wix .venv/wix-tools/wix.exe` (com `DOTNET_ROOT=.venv/dotnet-sdk`) e copiar `deploy/test-msi-sandbox.ps1` para `msi-input/`.
- Branch `feature/https-blockpage` enviada ao GitHub em 2026-10-22 sem PR (CI roda só em `main`, PR e disparo manual).

### Continuação — aceite em Sandbox

- `deploy/test-trust-sandbox.ps1` prepara tarefa SYSTEM somente dentro de Windows Sandbox. Recusa o host de desenvolvimento antes de qualquer escrita; testa configuração sem CA implícita, instalação explícita, ACL/owner SYSTEM, identidade estável, remoção exata e limpeza repetida.
- Testes de segurança do roteiro em `tests/test_sandbox_validation.py`: ausência de efeitos no host e sintaxe PowerShell. Falhas foram verificadas e commitadas antes da implementação.
- Pacote local ignorado em `.venv/sandbox-acceptance/`: `trust-acceptance.wsb`, binário e roteiro em `input/`, saída em `results/`. Rede e clipboard desabilitados; entrada somente leitura; apenas resultados compartilhados para escrita. Nenhum segredo/configuração real foi incluído.
- Sandbox iniciado; usuário confirmou que abriu. **Não considerar instalação/remoção real da CA validada** até `result.json` aprovado da tentativa atual. Diagnóstico em `results/bootstrap.log`. O roteiro atual usa diretório local único por tentativa e permite repetir no mesmo Sandbox sem reaproveitar resultados.
- O teste da CA não substitui os aceites HTTPS nos navegadores, recuperação do serviço ou MSI. O serviço e a confiança do host continuam inalterados.
- Verificação final desta continuação: **446 testes Python aprovados, 39 opcionais ignorados e 5 de instalação real deselecionados**, com binário release explicitamente selecionado. Inclui 3 contratos do roteiro (recusa do host e parser). `git diff --check` aprovado. Revisão independente do roteiro concluída; as correções para resultado obsoleto/parcial e a conferência de ACL/segunda remoção foram incorporadas. Resultado real do Sandbox continua pendente.
- Diagnóstico real posterior: `WDAGUtilityAccount` existe e `CExecSvc` está Running, mas `C:\ProgramData\Microsoft\Windows\Containers` não existe no Sandbox do usuário. A primeira versão do roteiro recusou esse ambiente antes de qualquer teste da CA. Corrigido para exigir perfil + serviço de execução ativo; `-ProbeEnvironment` apenas informa a detecção, sem criar arquivos/tarefas/certificados. Quatro casos de regressão foram escritos e verificados vermelhos antes da correção. Launcher compartilhado restaurado para execução do teste real; aguarda nova tentativa do usuário.
- Após essa correção: **450 testes aprovados, 39 ignorados e 5 deselecionados**. Revisão independente não encontrou regressão bloqueadora. Sem resultado real de confiança até este checkpoint.
- Primeiro teste real como SYSTEM confirmou configuração sem CA implícita, mas instalação falhou. ACL fornecida pelo usuário mostrou `AU` com Modify (`0x1301bf`) herdado na pasta customizada; `Authority::prepare_directory` corretamente recusa esse pai. O roteiro agora aplica explicitamente owner Administradores e DACL protegida, com FullControl somente para SYSTEM/Administradores, antes de iniciar a tarefa. Cada tentativa usa `C:\openems-acceptance-<guid>`. `-Plan` descreve essa configuração sem efeitos, com teste de regressão que verifica ACL, isolamento das tentativas e ausência de escrita no host. O agente não teve suas proteções relaxadas. Oito testes do roteiro aprovados; nova tentativa real pendente.
- Suíte após correção da ACL: **451 aprovados, 39 ignorados e 5 deselecionados**; revisão independente da correção aprovada. Script atualizado copiado para a pasta de entrada compartilhada do Sandbox. O relatório existente ainda é a tentativa anterior com falha; não reutilizar esse resultado como evidência da nova versão.
- **Aceite real da CA concluído em 2026-10-22:** nova tentativa no Windows Sandbox produziu `passed: true`, confirmada no arquivo compartilhado e pelo usuário. Cinco verificações aprovadas: configure sem CA implícita; instalação como SYSTEM com owner/ACL exclusivos; identidade estável na repetição; remoção do arquivo e restauração das raízes originais; segunda remoção bem-sucedida. Evidência preservada em `validation/sandbox-trust-2026-10-22.json`. O resultado substitui a falha anterior do roteiro, sem invalidar as pendências de navegadores, revogação dinâmica, recuperação/reboot e MSI.
- Próximo cenário preparado em `deploy/test-https-browser-sandbox.ps1`: agente real como SYSTEM, servidor de política simulado em `127.0.0.1:18013`, CA Windows real, portas 80/443 e hosts somente no Sandbox. `SslStream` valida confiança/hostname sem callback de bypass. Abre Edge para confirmação humana e depois exige ACK da liberação, mesmo processo vivo, listener TLS disponível e HTTP íntegro, além de comparar hosts e raízes com baseline na limpeza. Limite de dez minutos no worker; descarte o Sandbox se a limpeza não reportar sucesso. Launcher local ignorado: `.venv/sandbox-acceptance/input/RUN-HTTPS-BROWSER-TEST.cmd`. Três novos contratos foram verificados vermelhos antes da implementação; onze testes dos dois roteiros passaram. Revisão independente aprovada. **Ainda aguarda resultado real do navegador**; não estender esse aceite ao backend real, Chrome ou Firefox.
- Suíte local com o roteiro de navegador: **454 aprovados, 39 ignorados e 5 deselecionados**, usando o binário release explicitamente selecionado. Sem push/CI.
- Tentativa HTTPS de 2026-10-22 gerou `browser-ready.json` com TLS confiável e `browser-result.json` com revogação/limpeza aprovadas. **Não aceitar o check visual Edge desse relatório:** usuário esclareceu que digitou YES antes de o navegador abrir. Captura posterior mostrou `ERR_INTERNET_DISCONNECTED`, após encerramento/limpeza em Sandbox com rede desabilitada. Aceite Edge permanece pendente. Preparado perfil local ignorado `.venv/sandbox-acceptance/https-browser-network.wsb`, com Networking Enable, clipboard desabilitado, entrada somente leitura e início automático do roteiro. Fechar o Sandbox anterior antes de repetir; aguardar página RSM visível antes da confirmação humana. Sem mudança no agente instalado ou na confiança do host.
- **Repetição válida em 2026-10-22, 16:22 (America/Sao_Paulo): Edge HTTPS aprovado.** Novo Sandbox com rede habilitada; usuário confirmou a página sem erro antes de digitar YES. Relatório novo de 16:22:19 contém `passed: true`, `error: null` e `cleanup_errors: []`. Validação automática de TLS sem bypass, liberação da política simulada sem restart e restauração de hosts/raízes concluídas. Evidência preservada em `validation/sandbox-edge-https-2026-10-22.json`; substitui o aceite visual prematuro da tentativa anterior. Permanecem pendentes Chrome/Firefox, integração com servidor real, recuperação/reboot e MSI. Nenhuma alteração do agente/CA do host.

- Implementados listener HTTPS em loopback, autorização por SNI e Host, revogação pela política vigente e limites de conexões/leitura. Não há proxy de sites permitidos.
- CA por máquina com DPAPI, diretório/chave restritos ao SYSTEM, validação da persistência e certificados de servidor por domínio com validade de até 24 horas.
- Configuração nativa: `block_page_https`, `block_page_https_port` (443) e `authority_path` (subdiretório privado `https/authority.json`). HTTPS requer `block_page` e execução contínua; `run-once` recusa essa combinação.
- Comandos explícitos: `install-block-page-trust --config <agent.json>` e `remove-block-page-trust --config <agent.json>`. No Windows, operações que acessam a CA exigem SYSTEM. Serviço não instala confiança automaticamente. Remoção sem autoridade é idempotente.
- Desinstalação nativa e MSI removem o certificado exato pertencente à instalação; falha da limpeza impede que seja anunciada como concluída. Upgrade não executa essa remoção.
- Nenhuma CA foi instalada e o serviço/executável instalado nesta máquina não foi substituído. O build local não atualiza o MSI publicado.
- Testes usam CA efêmera, cliente TLS com raiz própria, portas efêmeras e store de confiança simulado. Validação real de instalação/remoção da CA e do MSI, e aceite em Chrome/Edge/Firefox, continuam pendentes de Windows descartável. Não executar aqui os testes `OPENEMS_SERVICE_TESTS=1`.
- Sem push, PR, publicação de MSI ou execução de CI nesta continuação; commits locais incluem `[skip ci]`.
- Validação final local: **39 testes Rust**, `cargo fmt --check`, Clippy sem avisos e build de release aprovados; **482 testes Python aprovados**, com 5 testes Windows de instalação real deselecionados por marcador. Os 18 contratos/comandos/vetores nativos passaram usando o novo executável de release. O MSI modificado teve contrato XML verificado, mas não foi compilado nem instalado nesta continuação.

O restante da F2 (DNS local, curingas, categorias, horários, SafeSearch e políticas de navegador) permanece pendente.

Estado em 2026-10-22. O plano completo de cada fase, com critérios de aceite, está em `roadmap-v2.md`.

## Andamento por fase

| Fase | Estado | O que falta |
|---|---|---|
| F1 — Agente nativo (Windows) | Quase pronta. Agente Rust em `agent-rs/` com paridade do agente Python (testes de contrato em `tests/test_native_agent.py`). MSI transacional com `BLOCKPAGE`/`BLOCKPAGEHTTPS` aceito em Sandbox (instalação, upgrade, rollback, remoção). Resiliência aceita em Sandbox com MSI de produção: recuperação após crash, servidor fora do ar, reboot sem servidor. Componente de sessão implementado na F5 5c. | Aceite do componente de sessão (lista no topo). Assinatura de código (depende de certificado da RSM). Segunda máquina física (Chrome/Firefox). |
| F2 — Filtro web completo | Parcial. HTTPS local aceito em Sandbox (Edge). Recorte 1 aceito em Sandbox: resolvedor DNS com NRPT do serviço, curingas e `allowed` (branch `feature/dns-resolver`). Recorte 2 aceito em Sandbox: SafeSearch forçado e horários (branch `feature/dns-safesearch-schedules`). Recorte 3 aceito em Sandbox: antiburla com WFP, NXDOMAIN para DoH e políticas de navegador (branch `feature/dns-anti-bypass`). Recorte 4a aceito em Sandbox: categorias baixadas, conferidas por digest e mantidas em cache offline (branch `feature/web-categories`). Recorte 4b aceito em Sandbox: registro de bloqueios com categoria e nome da categoria na página de bloqueio. Rotas e telas do painel, aviso de capacidades e tarefa diária da UT1 cobertos por testes (branch `feature/block-log`). | Editor de políticas com escolha de categorias (F7); servidor real com PostgreSQL e Docker; validação LGPD do registro; licença da UT1; Chrome/Firefox na segunda máquina. |
| F3 — Controle de aplicativos | Não iniciada. Hoje só encerra o processo pelo nome. | Tudo. |
| F4 — USB | Não iniciada. | Tudo. |
| F5 — Antiadulteração | Partes 5a e 5b aceitas em Sandbox: serviço protegido, watchdog, eventos, código de uso único, liberação de remoção, gerador offline, `cleanup` e painel. Parte 5c implementada: componente por sessão com ícone e avisos, reabertura pelo serviço e fechamento no upgrade/remoção. | Aceite da 5c e reboot com serviço desativado pelo registro (lista no topo). |
| F6 — Dentro/fora da empresa | Implementada na branch `feature/network-locations`: locais, sinais, perfis internos, decisão offline, ACK e painel. | Aceite real em Sandbox (lista no topo); sinais locais Linux/macOS na F8. |
| F7 — Painel novo | Parcial. React em `web/`, servido em `/panel/` (a raiz já redireciona). Visão geral, endpoints com detalhe e login prontos. | Editores de política, regras, convites e auditoria (hoje ainda pelo console antigo em `/console/`). Rotas de servidor `/api/v1/stats/overview` e `/api/v1/events` (o painel usa mocks até elas existirem; contrato em `web/src/mocks/data.ts`). Remover o console antigo ao final. |
| F8 — macOS e Linux | Não iniciada (o agente Rust já compila e passa nos testes de contrato no Linux, no CI). | Serviço, empacotamento e recursos de cada sistema. Mac exige teste manual e Apple Developer ID. |
| F9 — Android e iOS | Não iniciada; precisa de especificação própria. | — |

## Combinados de trabalho

- **CI só no fim.** O usuário pediu um único PR com CI ao final de todas as fases, para economizar minutos. O CI roda apenas em push na `main`, em PR e por disparo manual. Commits enviados direto para a `main` levam `[skip ci]` na mensagem.
- **TDD** (ver `CLAUDE.md` do usuário): testes que falham primeiro, commit `test(scope): ...`, depois implementação.
- **Paridade de política:** qualquer mudança em `agent/policy.py` exige regenerar `contract/policy-vectors.json` com `python tools/gen_policy_vectors.py`; o Rust (`agent-rs/tests/policy_vectors.rs`) e o Python (`tests/test_policy_vectors.py`) leem os mesmos vetores.
- **Testes que instalam serviço ou MSI** só rodam em runner descartável do CI (`OPENEMS_SERVICE_TESTS=1`), nunca na máquina de desenvolvimento.

## Como verificar localmente

```bash
python -m pytest -q -m "not windows_only"
```
```bash
cd agent-rs && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test && cargo build --release
```
```bash
cd web && npm run lint && npm run typecheck && npm run test:coverage && npm run build
```

Os testes de contrato do agente nativo usam o binário em `agent-rs/target/` (defina `OPENEMS_REQUIRE_NATIVE_AGENT=1` para falhar em vez de pular). Os contratos PostgreSQL e Redis precisam de `OPENEMS_TEST_DSN` e `OPENEMS_TEST_REDIS`.

## Ambiente de teste do usuário (esta máquina)

- Servidor real via `docker compose up -d --build`, com `.env` gerado por `deploy/new-env.ps1` (segredos só no `.env`, que não vai para o git).
- Agente instalado pelo MSI e depois substituído pelo build de `agent-rs/target/release` (a versão do MSI não tinha as correções de log e recadastro). Página de bloqueio ligada.
- Validado pelo usuário: cadastro, política aplicada e confirmada, bloqueio de site, encerramento do Bloco de Notas, página de bloqueio em HTTP.
- Ainda não testado pelo usuário: resiliência (servidor parado, processo morto, reinício da máquina) e desinstalação.
