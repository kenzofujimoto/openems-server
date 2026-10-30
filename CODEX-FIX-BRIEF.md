# Briefing de correção: controles Windows (WDAC + USB) — 28/10/2026

Diagnóstico feito na VM descartável `OpenEMS Disposable Acceptance` (Windows 11 Enterprise Evaluation 10.0.26300, Windows PowerShell 5.1) depois de os aceites USB físico e Applications/WDAC falharem. Toda a evidência está em `validation/` deste repositório e registrada em `validation/vm-provisioning-2026-10-28.json` (blocos `*_diagnostic`, `*_test` e `cipolicy_output_probe`).

O código do produto **não foi alterado**. Os arquivos abaixo são idênticos entre a revisão aceita (`18cd811`) e o `main` de `openems-server`, então a correção vai para o `openems-server`.

## Por que o agente só registrava `LocalError`

`agent-rs/src/windows_control.rs` descarta o stderr, e os scripts `deploy/agent-*.ps1` devolvem só `control_failed`/`restart_required`. O runtime grava `policy enforcement failed (LocalError)` e o ACK leva `enforcement failed: LocalError`. Para chegar à causa, rodei como SYSTEM no guest cópias instrumentadas dos scripts (o `catch` também emitia a exceção). As cópias estão em `.venv/windows-vm/results/diag-*.ps1`.

## Defeitos confirmados

| # | Arquivo:linha | Defeito | Evidência | Correção validada no guest |
|---|---|---|---|---|
| 1 | `deploy/agent-applications.ps1:261` | `Merge-CIPolicy -PolicyPaths $allow` abre a entrada para escrita. `%SystemRoot%\schemas\CodeIntegrity\ExamplePolicies\AllowAll.xml` pertence ao TrustedInstaller, e SYSTEM e Administrators só têm ReadAndExecute, daí `UnauthorizedAccessException`. | `vm-wdac-adapter-diagnostic-2026-10-28.json` | Copiar o template para `$script:directory` (SYSTEM-only) e fazer o merge da cópia. A política aplicou em 36,9 s, ficou enforced, a fixture foi negada (CodeIntegrity 3077 com o ID OpenEMS) e o `--remove-policy` funcionou sem reboot (`vm-wdac-template-copy-test-2026-10-28.json`). |
| 2 | `deploy/agent-applications.ps1:247-250` (`New-CIPolicyRule`) | O cmdlet escreve `"Scan completed successfully"` direto no `Console.Out`, antes do JSON. O `serde_json::from_slice` em `windows_control.rs:81` rejeitaria o sucesso como `Windows control returned invalid output`. Silenciar os streams 3-6 do PowerShell **não** resolve. | `vm-cipolicy-output-probe-2026-10-28.json` | Trocar `[Console]::Out` por `TextWriter.Null` durante as chamadas ConfigCI e restaurar em `finally`. Com isso, o stdout fica só com o JSON. |
| 3 | `deploy/agent-usb.ps1:231` | `Set-Disk -IsOffline $true` lança `CimException` "Removable media cannot be set to offline" num pendrive. O journal já tinha gravado `applied_offline`/`disabled_by_us`, e o `Disable-PnpDevice` não era alcançado. | `vm-usb-adapter-diagnostic-2026-10-28.json` | Não tentar offline em mídia removível; usar `DenyInstanceIDs` + `Disable-PnpDevice`. |
| 4 | `deploy/agent-usb.ps1:126,132,184,194` | No PS 5.1, `Get-ItemPropertyValue -ErrorAction SilentlyContinue` lança `PSArgumentException` (terminante) quando a **chave existe e o valor não**. Com a chave ausente, retorna nulo. Afeta apply e cleanup. | `vm-usb-skip-offline-test-2026-10-28.json` (falhou na linha 194 com a chave `Restrictions` existente e vazia); comportamento reproduzido no host só com leitura | Leitura segura: `if (-not (Test-Path $Path)) { $null } else { (Get-Item $Path).GetValue($Name, $null) }`. |

Com as correções 3+4 juntas (`vm-usb-safe-read-test-2026-10-28.json`): bloqueio padrão com código 0 em 9,3 s, USBSTOR com problem code 22, canário inacessível, evento `usb_block` e HID intacto. A limpeza restaurou leitura e escrita e removeu os valores de restrição.

## Observações secundárias (decidir no plano, não necessariamente corrigir)

- A limpeza USB deixa a subchave `HKLM\...\DeviceInstall\Restrictions\DenyInstanceIDs` vazia.
- O serial do PENMACK no `Win32_DiskDrive` vem como caractere de controle U+0003 seguido de `1`. Regras de allow por serial (`test-controls-sandbox.ps1:428`) podem não casar, ou ser rejeitadas pela validação `text()`. Não foi testado.
- Os progress records do ConfigCI vão para o stderr como CLIXML; `$ProgressPreference='SilentlyContinue'` evitaria o ruído.
- Com o defeito 1, a aplicação WDAC levou 89,9 s, colado no prazo de 90 s do ACK do harness.
- Diagnóstico: vale considerar devolver no JSON de erro um código estável (ex.: `OPENEMS_*`/tipo de exceção, sem paths nem dados sensíveis) e propagá-lo ao ACK/log, para a próxima falha não sair só como `LocalError`.

## Restrições

- Seguir `~/.claude/CLAUDE.md`: explorar, apresentar um plano com riscos e estratégia de testes, **esperar a aprovação do Kenzo**, depois TDD (testes falhando commitados primeiro), conventional commits e branch `fix/…`. Nada de push/PR sem pedido.
- Não usar o harness de aceite (`deploy/test-controls-sandbox.ps1`) como lugar da correção nem afrouxar os critérios dele.
- Testes sugeridos: o padrão já existente em `agent-rs/src/windows_control.rs` (testes `cfg(windows)` que fazem prepend de funções mock, por exemplo `Get-PnpDevice`, `Get-Disk`, `Set-Disk`, `Merge-CIPolicy`, `New-CIPolicyRule` escrevendo em `[Console]::Out`, ao script real). O caminho `apply` exige SID SYSTEM; definir no plano um seam testável, sem enfraquecer a checagem em produção. O host do Kenzo é Windows Home, **sem ConfigCI/CiTool**, então mocks são obrigatórios para o caminho WDAC.
- Depois do merge: gerar um MSI novo (os hashes mudam; atualizar os pacotes `usb-input`/`applications-input` e os manifestos), restaurar o snapshot `clean-preflight-before-controls` (UID 2) e repetir as fases USB e Applications/WDAC na VM. Só essa execução conta como aceite.
