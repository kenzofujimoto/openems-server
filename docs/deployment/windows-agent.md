# Agente Windows — instalação MSI

**Execução inicial exclusivamente em VM/Sandbox autorizada.** A instalação pode modificar serviço/ACL, NRPT/DNS, políticas de navegador, filtros WFP, hosts e confiança de certificados. Não usar diretamente na estação de trabalho.

## Construir pacote

~~~powershell
cd agent-rs
cargo test --locked
cargo build --release --locked
cd ..
dotnet tool install --global wix --version 5.0.2
wix build agent-rs/installer/openems-agent.wxs -arch x64 -d Version=0.1.0 -d AgentExe=agent-rs/target/release/openems-agent.exe -o openems-agent.msi
~~~

O `0.1.0` é exemplo de build e **não** representa release homologado. Distribuição corporativa exige assinatura e versionamento.

## Instalar em laboratório

~~~powershell
msiexec.exe /i .\openems-agent.msi /qn SERVER="https://ems.exemplo.net" DEVID="VM-LAB-01" VDOM="Default" INVITATION="CONVITE_DE_TESTE"
~~~

Opções `BLOCKPAGE=1`, `BLOCKPAGEHTTPS=1`, `DNSFILTER=1` e `ANTIBYPASS=1` são opt-in. Ligar uma opção por vez, testar portas locais 53/80/443, VPN, EDR, DNS corporativo e reversão. `ANTIBYPASS` depende de DNS local. O WiX usa sequência de preparação/rollback/commit e serviço de inicialização automática.

## Verificar

- Serviço `openems-agent` presente e reiniciável; logs sem segredos.
- `C:\ProgramData\openems\agent.json` protegido; não revelar conteúdo.
- Identidade, último contato, grupo efetivo, política desejada/aplicada e erros no servidor.
- NRPT, WFP e CA pertencentes **apenas** à instalação esperada.
- Reboot, modo offline e remoção testados em VM.

## Remover

Com segredo/código ativados e sob mudança aprovada:

~~~powershell
msiexec.exe /x .\openems-agent.msi /qn UNINSTALLCODE="XXXXX-XXXXX"
~~~

Código ilustrativo. Parâmetros MSI podem aparecer no monitoramento da linha de comando apesar da opção Hidden do WiX. Não divulgar código em logs ou histórico. Quando a chave-mestra não está configurada, há caminho de remoção sem código com evento correspondente: não assumir proteção garantida.

Ver [guia de desinstalação](../guides/uninstall-management.md) e [recuperação](../operations/disaster-recovery.md).
