# Aceite final do roadmap desktop

## Ações web — entrega de 27/10/2026

Permitir/Bloquear/Monitorar usa [matriz de aceite própria](docs/web-filter-actions-acceptance.md). O build desta entrega é preparado separadamente em `.venv/web-actions-acceptance/`, preservando os pacotes e resultados anteriores. Os quatro roteiros abaixo continuam como regressões de sessão/locais/controles; não substituem o aceite das ações web nem dos navegadores.

```powershell
.venv\Scripts\python.exe tools\build_final_acceptance.py --output .venv/web-actions-acceptance
```

Use o manifesto dessa pasta para identificar a revisão e os hashes. Compilar e gerar os MSIs não equivale a executar a nova rodada de aceites; resultados de 26/10 só valem para seus próprios bytes.

**Resultado de 27/10/2026** ([evidência](validation/web-actions-guest-2026-10-27.json)): três Sandboxes novos com o MSI `20e9d24e…` e o agente `5290604d…`, servidor/painel da `main` e migração 008 aplicada. A matriz prioritária passou: Permitir, Bloquear, Monitorar, monitoramento geral, exceções, precedência, horários, categoria ausente e digest inválido. Também passaram a sonda DNS e Chrome/Firefox com perfis novos. Netflix passou só em DNS. Na continuação do mesmo dia ([evidência](validation/web-actions-followup-2026-10-27.json)) passaram: reinício offline com cache completo e incompleto, token expirado/reenrollment, retry do mesmo lote, fila saturada, seletor por teclado e modo escuro. O YouTube, sem conta, substituiu a Netflix e passou no Chrome e no Firefox: o vídeo trava com o CDN bloqueado e toca com ele liberado. O aviso de listas desatualizadas também passou. Fica **pendente** só o aceite no Windows físico e em VM com USB/WDAC ([roteiro da segunda máquina](docs/second-machine-acceptance.md)). As falhas de harness das rodadas 1 e 2 estão registradas. No Sandbox, o DNS upstream é o resolvedor do host: não use domínios que o agente do host bloqueia (`example.com`) e trate respostas loopback como não atribuíveis.

## Rodada anterior

Estado inicial: **pendente**. Testes locais, compilação, inspeção de MSI e geração de pacote não equivalem a um aceite no sistema operacional. A F9 continua fora do escopo. O estado de implementação de cada fase está em `HANDOFF.md`.

Rodada real concluída em **26/10/2026**, com os pacotes/manifestos `779b483`: sessão passou nas duas fases, com reboot real; locais passou 8/8. USB passou nos quatro checks automatizados e aplicativos nos seis checks de inventário/rede/limpeza. Permanecem pendentes o USB físico e o bloqueio antes da execução por WDAC em VM compatível. Ambos retornam `manual_required`, com `automation_passed: true`, sem erros de limpeza. O consolidado e os relatórios finais estão em `validation/`; os pacotes atuais já foram preparados.

## Preparar uma única versão para todos os testes

No repositório, depois de concluir e commitar o código nativo:

```powershell
.venv\Scripts\python.exe tools\build_final_acceptance.py
```

O comando compila o release, gera os MSIs de produção atual e de upgrade e copia **os mesmos bytes** para os quatro pacotes pendentes. Não inicia Sandbox nem instala nada. Recusa fontes nativas ainda não commitadas. Os manifestos guardam o commit e o SHA-256 dos pacotes e roteiros; os launchers recusam arquivos modificados. Refaça a preparação se alterar código ou roteiro. Não misture MSIs de rodadas diferentes.

Os perfis ficam em `.venv/sandbox-acceptance/`; entradas são mapeadas só para leitura em `C:\openems-input`, e os relatórios voltam para `.venv/sandbox-acceptance/results`. Feche um Sandbox antes de abrir o seguinte. Use sempre um **Sandbox novo** para cada linha abaixo.

| Ordem | Perfil | Comando em Win+R dentro do Sandbox | O que precisa passar | Relatório |
|---|---|---|---|---|
| 1 | `session.wsb` | `C:\openems-input\RUN-SESSION-TEST.cmd` | Ícone por sessão, reabertura se encerrado, aviso de app fechado, upgrade sem reboot. Reinicie **o Sandbox por dentro** quando solicitado e rode o mesmo comando novamente: watchdog recupera serviço desativado no registro, componente retorna e desinstalação o fecha. | `session-phase1.json`, `session-result.json` |
| 2 | `locations.wsb` | `C:\openems-input\RUN-LOCATIONS-TEST.cmd` | Política interna por CIDR + MAC reais; mesma faixa com outro gateway volta à externa; ACK e avisos corretos; reinício offline dentro e fora; remoção restaura DNS/hosts. | `locations-result.json` |
| 3 | `usb.wsb` | `C:\openems-input\RUN-USB-TEST.cmd` | Instalação, inventário, regra de armazenamento sem afetar HID, cache no reinício offline, remoção. **Não aceita USB físico**: sem dispositivo adequado retorna `automation_passed: true`, `physical_acceptance_pending: true`, `passed: false`. | `usb-result.json` |
| 4 | `applications.wsb` | `C:\openems-input\RUN-APPLICATIONS-TEST.cmd` | Inventário de processo real com hash; app bloqueado na rede ainda inicia, mas não conecta, enquanto cópia de controle conecta; WDAC recusa original e cópia renomeada por hash e por um editor de teste exclusivo; liberação e remoção preservam políticas/regras anteriores. | `applications-result.json` |

A fase de aplicativos precisa de Internet para `https://example.org/`; a conectividade das duas cópias é verificada antes do bloqueio. O teste de rede usa destino externo porque bloquear loopback não prova uma regra de Firewall por aplicativo. A sonda escreve um arquivo antes de conectar, permitindo separar "processo impedido de abrir" de "processo abriu, conexão recusada".

O editor usado no teste WDAC é um certificado de assinatura exclusivo, criado e confiado **somente dentro do guest**, e removido ao terminar. Nunca se nega o editor da Microsoft ou outro editor compartilhado pelo sistema. O teste por hash exige recusa do Windows antes que o executável escreva seu primeiro arquivo; encerrar um processo depois de aberto não conta.

CiTool e ConfigCI precisam existir no guest. CiTool vem com Windows 11 22H2 e Windows Server 2025; a remoção de política unsigned sem reboot exige Windows 11 24H2 ou posterior. Ausência de recurso, ACK recusado ou reboot pendente **não são aprovação**. Nesse caso, repita em uma VM descartável com versão suportada, preservando o relatório e o `agent.log`, e só aceite depois de confirmar aplicação, execução bloqueada e remoção após o reboot necessário. Fontes: [CiTool](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/operations/citool-commands), [remoção de políticas](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/deployment/disable-wdac-policies).

Os roteiros gravam evidência parcial a cada etapa. `status: failed`, `cleanup_errors` preenchido, tempo esgotado ou serviço instalado ao final impedem o aceite. Não repita uma rodada no mesmo Sandbox: preserve os JSONs e descarte esse guest.

Para repetir aplicativos em uma VM Windows descartável com CiTool funcionando, copie `applications-input` para `C:\openems-input` dentro da VM. Em PowerShell elevado, crie a mesma atestação de VM usada pelo roteiro USB e execute diretamente o roteiro de controles (o launcher de Sandbox não se aplica à VM):

```powershell
Set-Content -LiteralPath C:\openems-disposable-vm.txt -Value 'OPENEMS DISPOSABLE USB ACCEPTANCE' -Encoding ASCII
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\openems-input\test-controls-sandbox.ps1 -Kind Applications -DisposableVm -OutputDirectory C:\openems-results
```

A atestação é compartilhada pelos dois roteiros; aplicativos não exige pendrive. O teste ainda verifica modelo virtual e hipervisor. Preserve `applications-result.json` e confirme limpeza antes de descartar o guest.

Sessão e locais agora exportam os logs MSI e `agent.log` automaticamente para subpastas `results/session-diagnostics-*` e `results/locations-diagnostics-*`, inclusive em falha. Depois de terminar o CMD, confirme que a pasta apareceu no projeto antes de descartar o guest. Se aparecer aviso de falha ao exportar, mantenha o Sandbox aberto para recuperar os logs. A primeira rodada retornou MSI 1603; a reprodução com logs identificou DLL de runtime ausente (`vcruntime140.dll`, `0xC0000135`). O build foi corrigido para carregar a configuração de runtime estático também quando iniciado na raiz. Use somente os pacotes reconstruídos após essa correção.

USB não exige enumeração de Code Integrity. No roteiro de aplicativos, enumeração WDAC indisponível deixa execução pendente e permite continuar o teste de rede; não constitui aceite de WDAC nem dispensa a VM suportada.

## USB físico: VM Windows com passthrough

Uma pasta compartilhada não é um pendrive. A [configuração documentada do Sandbox](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-configure-using-wsb-file) não oferece um parâmetro de passthrough de armazenamento USB. Use uma VM Windows descartável com snapshot limpo e o pendrive de teste redirecionado para ela. Conecte somente dispositivos de teste; os dados físicos do pendrive não são revertidos pelo snapshot da VM.

1. Copie a pasta `usb-input` final para `C:\openems-input` **dentro da VM** e conecte um pendrive dispensável com VID, PID e serial reportáveis. Verifique sua letra, por exemplo `E:`. Não use disco de boot/sistema.
2. Confirme que o modelo da máquina é virtual e crie, dentro desse guest, a atestação explícita:

   ```powershell
   Set-Content -LiteralPath C:\openems-disposable-vm.txt -Value 'OPENEMS DISPOSABLE USB ACCEPTANCE' -Encoding ASCII
   ```

3. Em PowerShell elevado **na VM**, execute, substituindo somente a letra correta:

   ```powershell
   powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\openems-input\test-controls-sandbox.ps1 -Kind USB -DisposableVm -PhysicalDrive E: -OutputDirectory C:\openems-results
   ```

4. O roteiro valida hipervisor/modelo virtual + atestação, sobe sua tarefa SYSTEM e recusa disco que não seja USB ou que seja de boot/sistema. Cria e remove somente seu próprio arquivo canário. Deve comprovar: exceção por VID/PID/serial, bloqueio por instância, leitura permitida e gravação recusada em somente leitura, evento no servidor, liberação e remoção. Reinsira o pendrive quando necessário para a liberação; acompanhe o andamento do JSON.
5. Preserve `C:\openems-results\usb-result.json`. Só esta rodada física pode retirar `physical_acceptance_pending`; a automação do Sandbox continua sendo apenas uma parte do aceite. Usando o pacote final intacto, o próprio roteiro confere o manifesto e inclui o recibo da versão no relatório. Após revisar o resultado físico, copie esse JSON intacto para a pasta de resultados, preservando também o relatório anterior do Sandbox com outro nome. Se a limpeza falhar, libere a política no guest e confirme acesso/gravação antes de reconectar o pendrive ao host. Não trate o descarte da VM como prova de restauração do dispositivo físico.

O controle atual decide por ciclos de inventário/aplicação em modo usuário. O teste não demonstra proteção de kernel antes da primeira montagem; esse limite precisa constar da decisão de implantação.

## Painel e servidor real

Além dos roteiros Windows, use um ambiente de homologação com PostgreSQL/Redis e pelo menos um agente dessa versão. Os testes MSW não substituem este fluxo:

- Entrar como administrador e como leitor; leitor consulta, mas não publica políticas nem muda cadastros. Sessão expirada mostra login/erro adequado; ações usam CSRF.
- Publicar perfis de web, aplicativos e USB; conferir digest/versão e ACK real. Atualizar só uma seção deve preservar as outras. Categorias, listas permitidas, curingas, horários e SafeSearch devem chegar ao agente com suas advertências de capacidade.
- Exercitar grupos/regras, convites, auditoria, administração e configuração/instalador conforme as funções implementadas. Conferir inventários e eventos reais nas fichas, sem credenciais em tela/log de auditoria.
- Navegar por teclado, inclusive formulários e diálogos; alternar modo escuro e recarregar. Conferir que as funções migradas não dependem do console antigo.
- Repetir HTTP/HTTPS, SafeSearch, categorias e antiburla com a versão final. Os aceites históricos de F2 pertencem aos binários anteriores. Chrome/Firefox em uma segunda máquina física e a assinatura de código continuam sendo aceites externos quando ainda não houver evidência.

## Linux: VM descartável própria

Windows Sandbox não valida systemd, systemd-resolved, USBGuard ou fapolicyd. Compile agente e helper como ELF Linux compatíveis e gere DEB/RPM conforme `deploy/linux/SUPPORT.md`; RPM exige `rpmbuild`. Use uma VM com snapshot e instale somente o pacote apropriado à arquitetura/distribuição. Um build em contêiner sem privilégios valida compilação/empacotamento, não enforcement real.

Os artefatos locais desta rodada ficam em `.venv/linux-build/packages/`, com manifestos SHA-256. Foram compilados em Debian 13 amd64; comece o aceite DEB nessa distribuição. Para outra distribuição, confira a compatibilidade de glibc ou recompile no ambiente correspondente. A geração do RPM não demonstra compatibilidade com todas as versões de Fedora/RHEL.

Exemplo DEB dentro da VM, com perfil de homologação previamente publicado:

```bash
sudo dpkg -i ./openems-agent_0.5.0_amd64.deb
read -r -s -p 'Convite de homologação: ' OPENEMS_INVITATION
export OPENEMS_INVITATION
sudo --preserve-env=OPENEMS_INVITATION /usr/bin/openems-agent configure \
  --server https://SEU-SERVIDOR --devid linux-acceptance \
  --config-path /etc/openems/agent.json --dns-filter
unset OPENEMS_INVITATION
sudo systemctl enable --now openems-agent.service
sudo systemctl status openems-agent.service
```

Conferir cadastro/ACK, DNS bloqueado/permitido pelo sistema, cache e restart após reboot, transição de local offline e restauração de DNS ao parar/falhar o serviço. Com USB passthrough, testar allow/block e HID. Com fapolicyd configurado conforme `SUPPORT.md`, negar executável dispensável por hash, renomear, confirmar recusa e liberar. Remover o pacote e comprovar que só os trechos gerenciados desapareceram, políticas externas ficaram e estado privado foi preservado. Um trecho gerenciado alterado fora do agente deve impedir limpeza destrutiva e manter o journal de recuperação.

Aceitar explicitamente os limites atuais: NetworkManager sem systemd-resolved, USB somente leitura/instância Windows e políticas de app por editor/nome/rede não devem receber ACK de sucesso como se fossem implementadas. Não habilitar opções Windows de CA HTTPS/WFP/browser como se fossem recursos Linux.

## macOS: compatibilidade e itens externos

`deploy/macos/SUPPORT.md` descreve o pacote de compatibilidade e os pré-requisitos de assinatura. O pacote exige um binário Mach-O assinado, Developer ID Installer, notarização e aceite em Mac. Testar launchd, cadastro/ACK, cache após reboot, bloqueio explícito por hosts, fallback por nome de processo, liberação e limpeza.

**Network Extension para DNS e Endpoint Security para USB/apps ainda precisam de implementação nativa, entitlements e validação em Mac.** Não marcar a F8 completa nem inferir esses recursos a partir de launchd/pacote/compilação. O modo de compatibilidade não satisfaz o aceite completo dessas extensões.

## Consolidar evidências

Depois dos Sandboxes, execute no repositório:

```powershell
.venv\Scripts\python.exe tools\build_final_acceptance.py --summarize .venv\sandbox-acceptance\results
```

O resumo só aceita relatórios da versão atual com `passed: true`, sem hardware pendente. Ausência, JSON parcial, recibo de outra compilação, falha ou limpeza incompleta permanecem pendentes/falhos. O resultado físico da VM deve ser preservado e revisado; substitua o relatório USB consolidado apenas pelo JSON real da rodada física, mantendo a evidência anterior, nunca por um arquivo editado para mudar `passed`. Mantenha também os registros de homologação do painel, da VM Linux e do Mac. O CI fica para a rodada final combinada com o usuário; este roteiro não o dispara.
