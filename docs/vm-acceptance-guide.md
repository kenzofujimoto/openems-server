# Guia: VM descartável para aceite de USB e WDAC

Como recriar a VM Windows usada no aceite de 28–29/10/2026 e rodar os testes de controles (USB físico e Applications/WDAC) do mesmo jeito. A VM original foi apagada em 30/10/2026; as evidências estão em `validation/vm-*` e `validation/windows-controls-vm-*`.

O último aceite aprovado foi o do agente `675308c` (MSI 0.4.0): [Applications/WDAC](../validation/vm-applications-final-675308c-result-2026-10-29.json) e [USB](../validation/vm-usb-final-675308c-result-2026-10-29.json).

## Por que VM e não o PC físico

- USB e WDAC alteram o Windows de verdade (políticas Code Integrity, classes de dispositivo, firewall). **Nunca rode `test-controls-sandbox.ps1` no Windows físico.**
- O Windows Sandbox não repassa pendrive USB e não tem Code Integrity funcional (`0x80073BC3`).
- Windows Home não tem CiTool, então WDAC não roda nele (o agente pula as regras `if_present` e recusa as obrigatórias com `unsupported`).

## Versões usadas

| Item | Valor |
|---|---|
| Hipervisor | VMware Workstation 26.0.1 build-25688693 |
| ISO | `26300.9457.260913-1737.26h2_ge_release_svc_refresh_CLIENTENTERPRISEEVAL_OEMRET_x64FRE_en-us.iso` (Windows 11 Enterprise Evaluation, baixada de microsoft.com) |
| SHA-256 da ISO | `BC3F24086EBADC94489066B5AD78089E2CF5C3491E90E790BB81A2B199C10E38` (8.225.329.152 bytes) |
| Guest efetivo | Windows 11 Enterprise Evaluation 10.0.26300 (a marca d'água mostrava 26100; vale o que o preflight reportar) |
| VMware Tools | 13349 |
| Hardware | 2 vCPU, 4096 MiB, disco 80 GiB, rede NAT, TPM virtual (exige criptografia da VM) |
| Pendrive de teste | `PENMACK`, Generic Flash Disk, VID `058F`, PID `6387`, 4 GB, sem dados importantes |
| Host | Windows 11 Home 26300, Docker parado durante os testes para liberar RAM |

Requisitos do guest: CiTool e ConfigCI presentes (Windows 11 22H2+). Remover política unsigned sem reboot exige 24H2 ou posterior.

## 1. Criar a VM

1. Baixe a ISO de avaliação no site da Microsoft e confira o SHA-256 (`Get-FileHash -Algorithm SHA256`). Não use ISO de terceiros.
2. Nova VM no VMware: Windows 11 x64, 2 vCPU, 4 GB, 80 GB, NAT. Adicione TPM virtual; o VMware pede uma senha de criptografia. **Quem guarda essa senha é você**; o agente de código nunca deve pedir nem registrar a senha.
3. Se o boot falhar com `No PCIe slot available for SCSI0`, desligue a VM e acrescente as pontes PCI/PCIe padrão no `.vmx` (`pciBridge0.present = "TRUE"`, `pciBridge4.present = "TRUE"`, `pciBridge4.virtualDev = "pcieRootPort"`, `pciBridge4.functions = "8"`, repetindo para 5, 6 e 7).
4. Em USB, deixe a conexão automática **desligada**: o pendrive é conectado manualmente só na hora do teste.
5. Instale o Windows (conta local), instale o VMware Tools e reinicie.
6. Crie uma pasta compartilhada **só para resultados** (`OpenEMSResults`, leitura/escrita) apontando para uma pasta vazia do host. Não compartilhe o repositório nem `.env`.
7. Rode um preflight no guest (PowerShell elevado) e confira: modelo `VMware20,1`, hipervisor presente, `C:\Windows\System32\CiTool.exe` presente, sem reboot pendente, sem agente OpenEMS instalado.
8. Desligue o Windows Setup se ele estiver aberto e só então tire o snapshot **`clean-preflight-before-controls`**. Um snapshot tirado com o Setup aberto não é limpo (aconteceu no snapshot UID 1).

## 2. Preparar o pacote no host

No repositório, com o código nativo commitado (o script recusa fontes sujas):

```powershell
.venv\Scripts\python.exe tools\build_final_acceptance.py
```

Isso compila o release, gera o par de MSIs (atual + upgrade) e copia os mesmos bytes para `.venv/sandbox-acceptance/{usb,applications}-input`, com manifesto de commit e SHA-256. Os launchers recusam arquivos alterados. Se mudar código ou roteiro, refaça o pacote; nunca misture MSIs de rodadas diferentes.

Para levar as entradas à VM, gere uma ISO só com `usb-input`, `applications-input` e um `RECEIPT` (sem segredos) e monte-a no CD da VM com "Connected". Uma ISO só de leitura impede que o guest altere a entrada. Na rodada original isso foi feito por um script local não versionado; qualquer gerador ISO 9660/Joliet serve (por exemplo, `IMAPI2FS` via PowerShell ou `oscdimg` do Windows ADK). Registre o SHA-256 da ISO.

O MSI de teste precisa do **mesmo commit** que está sendo aceito. Para o Rust compilar no host, é preciso o Visual Studio Build Tools com o componente C++ (`link.exe`); sem ele, `cargo` falha com `linker link.exe not found`.

## 3. Rodar os testes dentro da VM

Antes de cada rodada: **restaure o snapshot `clean-preflight-before-controls`**, monte a ISO da rodada e ligue a VM. Uma rodada por snapshot limpo; nunca repita no mesmo guest.

Dentro da VM, PowerShell **como administrador**:

```powershell
New-Item -ItemType Directory -Force C:\openems-input, C:\openems-results | Out-Null
Copy-Item D:\applications-input\* C:\openems-input -Recurse -Force   # D: = CD da ISO
Set-Content -LiteralPath C:\openems-disposable-vm.txt -Value 'OPENEMS DISPOSABLE USB ACCEPTANCE' -Encoding ASCII
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\openems-input\test-controls-sandbox.ps1 -Kind Applications -DisposableVm -OutputDirectory C:\openems-results
```

Para USB, restaure o snapshot de novo, copie `usb-input`, conecte o pendrive de teste à VM (VM > Removable Devices > Connect), confira a letra e rode:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File C:\openems-input\test-controls-sandbox.ps1 -Kind USB -DisposableVm -PhysicalDrive E: -OutputDirectory C:\openems-results
```

O roteiro confere hipervisor, modelo virtual e o arquivo de atestação, recusa disco de boot/sistema e só cria/remove o próprio arquivo canário. Reinsira o pendrive quando o roteiro pedir.

Ao terminar, copie `C:\openems-results\*` para a pasta compartilhada `\\vmware-host\Shared Folders\OpenEMSResults\`.

## 4. Critério de aprovação

- `passed: true` no `*-result.json`, sem `cleanup_errors`, sem tempo esgotado e sem serviço OpenEMS instalado ao final.
- Applications: inventário com hash, rede bloqueada por executável (a cópia de controle conecta), WDAC recusa o original e a cópia renomeada (por hash e por editor de teste exclusivo do guest) **antes** do primeiro arquivo escrito, liberação e remoção preservando políticas anteriores.
- USB: exceção por VID/PID/serial, bloqueio por instância, leitura sim e escrita não em somente leitura, evento no servidor, liberação e remoção.
- Ausência de recurso, ACK recusado ou reboot pendente **não são aprovação**.

Preserve os JSONs originais em `validation/` com a data (`vm-applications-<rodada>-result-AAAA-MM-DD.json`) e registre a rodada em `ACCEPTANCE.md` e `HANDOFF.md`.

## 5. Pendente: catálogo de aplicativos (`if_present`)

As regras geradas pelo catálogo (`catalog-*`, `if_present: true`) ainda não passaram por aceite WDAC. A rodada deve provar, numa VM limpa e com um app de teste instalado no guest:

1. Regra `if_present` de um app **ausente** é ignorada sem falhar o ACK.
2. Regra de um app **presente** é aplicada e bloqueia a execução.
3. Com todas as regras ausentes, a política OpenEMS é removida.
4. A revalidação de hora em hora (`optional_checked_at`) aplica a regra depois que o app aparece.
5. "Bloquear rede" do catálogo cria a regra de firewall por executável, e "Bloquear" encerra o processo.

## 6. Instruções para o agente de código

Cole isto no início da sessão de quem for conduzir o teste (Claude Code, Codex etc.):

> Você vai conduzir um aceite Windows do OpenEMS numa VM descartável. Siga `docs/vm-acceptance-guide.md` e `ACCEPTANCE.md`.
>
> - Nunca rode `test-controls-sandbox.ps1`, `agent-usb.ps1` ou `agent-applications.ps1` no Windows físico, nem a suíte que os invoca de verdade. No host, só testes unitários e de contrato.
> - Não afrouxe critérios, prazos de ACK (90 s) nem timeouts para fazer passar. Falhou: preserve o JSON, diagnostique, corrija com TDD (teste vermelho commitado antes) e faça uma nova rodada num snapshot limpo.
> - Não altere TLS, antivírus, Defender ou configurações de segurança do host.
> - Não peça nem registre a senha de criptografia da VM, o `.env` ou chaves. Leia segredos só dentro de comandos, sem imprimir.
> - O operador humano faz o UAC e os cliques dentro da VM. Prepare atalhos `.lnk` numerados na pasta compartilhada (`NN - <ação> as administrator.lnk`) e diga exatamente qual executar.
> - Antes de descartar o guest, confirme remoção normal do agente (liberação com ACK e `msiexec /x` com código 0) e ausência de serviço, watchdog, NRPT e políticas OpenEMS.
> - Commits de evidência usam `docs(acceptance): ... [skip ci]`; correções seguem conventional commits com `Co-Authored-By`.
> - Registre cada rodada no topo de `HANDOFF.md` com o commit, o SHA-256 do MSI e o link do JSON.

## 7. Limpeza

1. Confirme a remoção normal do agente no guest e copie os resultados.
2. Desligue a VM, feche o VMware e apague a pasta da VM (ela ocupa ~45 GB com snapshots).
3. Remova a VM da biblioteca do VMware (Remove from Library).
4. Apague a ISO de entrada e os pacotes de `.venv/` que não forem mais usados.
