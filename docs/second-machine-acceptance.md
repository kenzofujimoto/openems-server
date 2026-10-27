# Aceite na segunda máquina

Roteiro para o notebook com pendrive, Chrome e Firefox. Ele cobre o que o Windows Sandbox não comprova: o agente num Windows físico com navegadores reais, e USB físico/WDAC numa VM descartável. Os resultados da Sandbox de 27/10 estão em [validation/web-actions-guest-2026-10-27.json](../validation/web-actions-guest-2026-10-27.json) e na rodada 4 do HANDOFF.

## O que levar

1. Clone a `main`: `git clone https://github.com/kenzofujimoto/openems-server.git`.
2. Copie o pacote `openems-second-machine-2026-10-27.zip` (pendrive ou nuvem). Antes de usar, confira o SHA-256 informado no HANDOFF:

   ```powershell
   Get-FileHash .\openems-second-machine-2026-10-27.zip -Algorithm SHA256
   ```

3. Extraia em `.venv\second-machine\` dentro do clone. A pasta `.venv/` é ignorada pelo Git. Confira `msi\openems-agent.msi` contra `20e9d24e1a9b59fb96eec25fbd66e3c67bea82a33b27efbe1183db0f098a17c4`. Não recompile; os aceites valem para esses bytes.

O pacote não tem `.env`, senhas, convites, CA, estado de agente nem perfis pessoais. Cada máquina gera os próprios segredos.

## Parte A — Chrome e Firefox no Windows físico

O agente será instalado de verdade no notebook e passará a filtrar o DNS dele até a remoção. Faça numa sessão em que você possa ficar sem alguns sites por alguns minutos. Não use VPN nem DNS próprio no navegador durante o teste.

1. **Servidor local.** Com Docker Desktop, na pasta do clone:

   ```powershell
   powershell -ExecutionPolicy Bypass -File deploy\new-env.ps1
   docker compose up -d --build
   docker compose run --rm --no-deps server python -m app.migrations
   ```

   Guarde a senha do administrador que o primeiro comando mostra. O último comando deve responder `applied: none`, porque a inicialização já cria o esquema, ou listar 001–008.
2. **Listas de homologação.** Publique as listas de teste do pacote. Elas não são UT1:

   ```powershell
   docker compose --profile categories run --rm --no-deps -v "${PWD}\.venv\second-machine\categories-src:/src:ro" categories python tools/update_categories.py /src /var/lib/openems/categories
   ```

3. **Painel** em `http://localhost:8013/panel/`. Entre como administrador e revise com o teclado: Tab, Enter e Esc no seletor Permitir/Bloquear/Monitorar. Confira os três ícones com rótulo, o aviso de listas (saúde "atual") e o modo escuro. Crie o grupo `WebActions` com:
   - Jogos (`games`) = Bloquear;
   - Áudio e vídeo (`streaming`) = Monitorar;
   - Compras (`shopping`) = Permitir;
   - monitoramento geral desligado.
4. **Convite.** Gere um convite de uso único para `WebActions` no painel e não o salve em arquivo.
5. **Instalação.** Em PowerShell elevado, na pasta `.venv\second-machine\msi`:

   ```powershell
   $invitation = Read-Host 'Convite' -AsSecureString
   $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($invitation))
   msiexec /i openems-agent.msi /qn /norestart /l*v "$env:TEMP\openems-install.log" SERVER=http://127.0.0.1:8013 VDOM=WebActions DNSFILTER=1 INVITATION=$plain
   Remove-Variable plain, invitation
   ```

   Confira o SHA-256 do executável instalado (`5290604d7f008cb279c01ccca0d1664edfb4415ffc0d0200987bf6465ea8bf04`):

   ```powershell
   Get-FileHash 'C:\Program Files\openems\openems-agent.exe'
   ```

   No painel, a máquina deve aparecer com a política aplicada (ACK).
6. **Sonda DNS**, a mesma da Sandbox:

   ```powershell
   foreach ($d in 'www.example.net','www.example.org','www.ietf.org') { Clear-DnsClientCache; Resolve-DnsName $d -Type A -DnsOnly -NoHostsFile -QuickTimeout }
   ```

   Esperado: `www.example.net` = `0.0.0.0`; os outros dois resolvem para endereços públicos. Uma resposta `127.x` indica outro bloqueio na máquina e invalida a linha.
7. **Navegadores com perfis novos.** Use pastas temporárias e nunca o perfil pessoal:

   ```powershell
   & 'C:\Program Files\Google\Chrome\Application\chrome.exe' --user-data-dir="$env:TEMP\oems-chrome-$(Get-Random)" --no-first-run https://www.example.net/
   & 'C:\Program Files\Mozilla Firefox\firefox.exe' -no-remote -profile (New-Item -ItemType Directory "$env:TEMP\oems-ff-$(Get-Random)").FullName https://www.example.net/
   ```

   Em cada navegador:
   - `https://www.example.net/` deve dar erro de conexão ou de nome;
   - `https://www.example.org/` deve carregar "Example Domain";
   - `https://www.ietf.org/` deve carregar a IETF.

   Depois de até um minuto, o painel deve mostrar um evento **bloqueado** para `www.example.net` e um **monitorado** para `www.example.org`. Não pode haver nenhum evento para `www.ietf.org`. Espere mais de um minuto entre os dois navegadores, porque o agente deduplica por minuto.
8. **YouTube (substitui a Netflix).** As listas do pacote já põem `youtube.com`, `googlevideo.com` e `ytimg.com` em `streaming`.
   - Com `streaming` = Bloquear e exceções `youtube.com`, `*.youtube.com` e `*.ytimg.com`, a página do vídeo abre, mas o vídeo não toca.
   - Somando `googlevideo.com` e `*.googlevideo.com` às exceções, o vídeo toca.
9. **Remoção.** `msiexec /x openems-agent.msi /qn`. Depois:
   - `Get-DnsClientNrptRule` não deve ter regra com comentário `openems-agent managed DNS filter`;
   - um site comum deve voltar a resolver.

   Pare o servidor com `docker compose down`, se quiser.

Registre a versão dos navegadores, os horários, as respostas DNS, a política, o ACK e os eventos do painel. Capturas de tela ajudam; não guarde URLs completas nem senhas.

## Parte B — USB físico e WDAC em VM descartável

Nunca rode `test-controls-sandbox.ps1` no Windows físico. Ele aplica controles de USB e de aplicativos e exige VM.

1. Crie uma VM Windows 11 24H2 ou posterior. Use VMware Workstation Pro, que é gratuito, ou VirtualBox com controlador USB 3.0. O Hyper-V não repassa pendrive. Tire um snapshot limpo.
2. Copie `usb-input` e `applications-input` do pacote para dentro da VM. Cada um vai para `C:\openems-input` na rodada correspondente: restaure o snapshot entre elas.
3. Conecte um pendrive **dispensável** e redirecione-o para a VM. Siga a seção "USB físico: VM Windows com passthrough" do [ACCEPTANCE.md](../ACCEPTANCE.md). Ela tem a atestação `C:\openems-disposable-vm.txt` e o comando com `-PhysicalDrive`.
4. Para WDAC, restaure o snapshot e rode `-Kind Applications` conforme a mesma seção do ACCEPTANCE.md.
5. Traga `usb-result.json` e `applications-result.json` intactos.

## Depois

Com o Claude da segunda máquina:
1. Salve as evidências sanitizadas em `validation/`:
   - `second-machine-browsers-AAAA-MM-DD.json`;
   - `vm-usb-AAAA-MM-DD.json`;
   - `vm-applications-AAAA-MM-DD.json`.
2. Atualize `HANDOFF.md` e `ACCEPTANCE.md`.
3. Faça os commits com `[skip ci]`. Pendência não vira aceite; uma falha fica registrada como falha. F9 e CI continuam fora do escopo.
