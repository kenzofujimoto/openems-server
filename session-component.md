# F5 parte 5c — componente de sessão e reboot com serviço desativado

Fecha a F5 (`roadmap-v2.md`: "componente de sessão iniciado a cada logon de usuário") e a pendência da F1 ("tarefa no logon, notificações"). Aprovado pelo usuário em 2026-10-25 junto com o restante do roadmap ("faça tudo menos a 9"); as decisões abaixo seguem as recomendações.

## O que entrega

- **`openems-session.exe`**, um segundo executável, sem janela de console (subsistema Windows), que roda na sessão de cada usuário:
  - ícone na área de notificação com o estado: "proteção ativa" ou "sem contato com o servidor desde HH:MM";
  - balão de aviso quando o serviço registra algo que o usuário precisa saber. Hoje: aplicativo encerrado pela política. As fases F3 (aplicativos) e F4 (USB) acrescentam os seus avisos pelo mesmo caminho.
- **O serviço abre o componente** em toda sessão interativa ativa (console ou RDP) a cada ciclo (15 s). Isso cobre o logon, as sessões já abertas na instalação, o reboot e um componente encerrado pelo usuário.
- **Reboot com o serviço desativado pelo registro:** a tarefa watchdog já roda no boot; a 5c acrescenta o aceite em Sandbox que prova que ela restaura o tipo de início e inicia o serviço depois de `Start=4` no registro e reboot.

## Decisões

| # | Decisão | Escolha | Alternativa descartada |
|---|---|---|---|
| 1 | Como iniciar na sessão | O serviço (SYSTEM) usa `WTSEnumerateSessions`, `WTSQueryUserToken` e `CreateProcessAsUser` para abrir `openems-session.exe` em cada sessão ativa que ainda não o tem | Tarefa agendada no logon para o grupo Usuários: não cobre sessões já abertas na instalação, depende de mais um objeto que um administrador apaga, e um `.exe` de console abriria uma janela preta |
| 2 | Canal serviço → sessão | Arquivo `session.json` ao lado do `state.json`, gravado só pelo serviço, legível por Usuários (`D:P(A;;FA;;;SY)(A;;FR;;;BA)(A;;FR;;;BU)`). O componente lê a cada 5 s | Pipe nomeado ou RPC: mais código e mais superfície de ataque, sem ganho para avisos que toleram 5 s de atraso |
| 3 | Conteúdo | Estado (protegido, último contato com o servidor) e até 20 avisos com id crescente, hora, tipo e texto em português. **Nenhum dado pessoal**: só o nome do aplicativo (e, na F4, o produto USB) | Mostrar domínios bloqueados: a página de bloqueio já informa no navegador |
| 4 | Avisos repetidos | O componente guarda em memória o último id mostrado. Na partida, só mostra avisos dos últimos 60 s, para não despejar o histórico a cada logon | Gravar o último id visto em disco: exigiria escrita do usuário em pasta protegida |
| 5 | Atualização e remoção | Na parada normal, o serviço encerra os componentes de todas as sessões; o upgrade e a remoção do MSI param o serviço antes de trocar arquivos, então o `.exe` não fica em uso. O componente também sai sozinho em `WM_CLOSE`, `WM_QUERYENDSESSION` e `WM_ENDSESSION` (Restart Manager) | Deixar o Windows Installer pedir reboot (3010) |
| 6 | Instância única | Mutex `Local\openems-session` por sessão | — |
| 7 | Proteção | O componente é do usuário e só informa: se ele o encerrar, o serviço o abre de novo no ciclo seguinte. Não é evento de adulteração | Registrar como adulteração: geraria ruído no painel por algo que não desliga proteção nenhuma |

## Testes

- Rust: quadro de avisos (limite, ids, arquivo), escolha do que mostrar, texto da dica e do balão, linha de comando do processo da sessão.
- Nativo (Python): o agente em `run` encerra um aplicativo bloqueado e grava o aviso em `session.json`; `openems-session --print` mostra o estado e os avisos que exibiria, sem interface.
- MSI: o pacote instala `openems-session.exe` e a compilação passa.
- **Aceite em Sandbox** (`deploy/test-session-sandbox.ps1`, duas fases com reboot, como o de resiliência):
  1. depois da instalação, `openems-session.exe` roda na sessão do usuário do Sandbox;
  2. encerrado, volta em até 30 s;
  3. um aplicativo bloqueado é encerrado e o aviso chega ao `session.json`;
  4. upgrade com o componente aberto termina com 0 (sem pedido de reboot);
  5. `Start=4` no registro, serviço encerrado e reboot: depois do boot, o serviço está rodando de novo com início automático, o servidor simulado recebe `service_config_restored` ou `service_started_by_watchdog`, e o componente está aberto;
  6. a remoção termina com 0 e não deixa componente rodando nem o `.exe`.

## Limites

- O balão usa a API clássica (`Shell_NotifyIcon`). No Windows 10 e 11 ele aparece como notificação do sistema; se o usuário desligar as notificações, só o ícone fica.
- Sessões sem usuário interativo (serviços, tela de logon) não recebem o componente.
