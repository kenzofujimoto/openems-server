# Interface de linha de comando — agente Rust

Fonte: `agent-rs/src/main.rs`. Conferir `openems-agent.exe --help` para flags exatas da versão compilada.

| Comando | Operação |
| --- | --- |
| `run-once` | Um ciclo de sincronização, aplicação e relatório |
| `run` | Serviço em primeiro plano |
| `configure` | Escreve `agent.json` protegido |
| `install-service` / `uninstall-service` | Instala/remove serviço Windows |
| `installer-prepare` / `installer-rollback` / `installer-commit` | Transação MSI |
| `cleanup-hosts` | Remove bloco `hosts` gerenciado |
| `install-block-page-trust` / `remove-block-page-trust` | Gerencia somente CA desta instalação |
| `cleanup` | Remove proteções após autorização de remoção forçada |
| `uninstall-code` | Gera códigos offline a partir de chave-mestra/client_id |
| `configure-recovery` / `watchdog` / `service` | Comandos internos Windows |

## Teste sem tocar no SO

~~~powershell
.\openems-agent.exe run-once --server http://127.0.0.1:8013 --devid VM-LAB-01 --dry-run --hosts-file .\hosts-test
~~~

Cadastro pode exigir convite. Não executar `install-service`, `installer-prepare`, `cleanup`, alterações reais de hosts/NRPT/WFP ou operação da CA fora de VM descartável.

## Propriedades de MSI

`SERVER`, `INVITATION`, `VDOM`, `DEVID`, `HOSTSFILE`, `BLOCKPAGE`, `BLOCKPAGEHTTPS`, `DNSFILTER`, `ANTIBYPASS` e `UNINSTALLCODE`. Propriedades ocultas no log não impedem exposição em lista de processos.

~~~powershell
msiexec.exe /i .\openems-agent.msi /qn SERVER="https://ems.exemplo.net" DEVID="VM-LAB-01" INVITATION="CONVITE_DE_TESTE"
~~~

A instalação e desinstalação precisam de aprovação de mudança. Ver [guia Windows](../deployment/windows-agent.md).
