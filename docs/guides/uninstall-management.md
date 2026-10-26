# Desinstalação com código

Fontes: `app/uninstall_codes.py`, `agent/uninstall.py`, `agent-rs/src/removal.rs` e WiX. Evidência: `validation/sandbox-uninstall-2026-10-25.json` (11 verificações em Sandbox; **não** homologação de frota).

~~~mermaid
sequenceDiagram
  participant Admin as Admin
  participant API as Servidor
  participant MSI as Agente / MSI
  Admin->>API: POST endpoints/uninstall_code {devid}
  API->>API: Avança contador atômico por client_id
  API-->>Admin: Código de uso único
  Admin->>MSI: Remover com UNINSTALLCODE
  MSI->>MSI: Valida segredo, código, contador e lockout
  alt Autorizado
    MSI->>MSI: Limpa serviço, NRPT, WFP, hosts e CA da instalação
  else Recusado
    MSI-->>Admin: MSI rejeita e reverte transação
  end
~~~

## Modelo de autorização

O segredo do cadastro é derivado por HMAC da `OPENEMS_UNINSTALL_MASTER_KEY` e do `client_id`. A API o entrega uma vez e exige prova de armazenamento; depois retorna 409. O segredo, contador, falhas, lockout e liberação ficam em `uninstall.json` com ACL para SYSTEM. Cinco códigos errados bloqueiam a tentativa durante uma hora. Um token de liberação por grupo ou toda a frota pode permitir remover sem código quando sincronizado.

**Limite deliberado:** quando o segredo não foi entregue/configurado, há condição de remoção sem código, registrada como `uninstall_without_secret`; não descrever como inviolável. Perda do segredo com entrega confirmada pode bloquear remoção até reabertura administrativa.

## Procedimentos

- Obter código via painel (papel administrador); registrar autorização e não copiar código para ticket.
- Remover num ambiente com acesso e configuração conhecidos:

~~~powershell
msiexec.exe /x .\openems-agent.msi /qn UNINSTALLCODE="XXXXX-XXXXX"
~~~

- Em desastre, gerar localmente o código **sem servidor** a partir de chave-mestra guardada em cofre e `client_id`:

~~~powershell
python tools/uninstall_code.py --master-key-file "C:\cofre\master-key.txt" --client-id "CLIENT_ID"
~~~

Comandos e propriedades MSI podem ser registrados no SO; não executar com segredos reais em console monitorado ou logs. A interface de controle pode reabrir entrega do segredo ou liberar remoção por grupo, sempre com auditoria.

Consulte [MSI](../deployment/windows-agent.md), [chaves](../security/identity-and-trust.md) e [desastre](../operations/disaster-recovery.md).
