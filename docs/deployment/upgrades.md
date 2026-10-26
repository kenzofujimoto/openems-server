# Atualização e rollback

## Servidor

1. Fixar commit, mapear migrações em `migrations/` e compatibilidade de agentes antigos.
2. Fazer backup consistente do PostgreSQL, volume de categorias, configurações e segredos (especialmente chave de remoção).
3. Testar migrações, autenticação, eventos e ACK contra uma cópia sanitizada; validar CI.
4. Subir nova imagem sob janela de mudança e observar erros, reinícios e backlog.
5. Para rollback, avaliar o schema. Trocar somente a imagem não desfaz migrações irreversíveis.

## Agente Windows

~~~mermaid
flowchart TD
  Build[Build / versão / assinatura] --> Sandbox[Testar MSI em Windows Sandbox]
  Sandbox --> Gate{Aprovado?}
  Gate -->|Não| Stop[Corrigir antes de distribuir]
  Gate -->|Sim| Pilot[Piloto supervisionado]
  Pilot --> Check{ACK, DNS, VPN e CA íntegros?}
  Check -->|Não| Backout[Rollback com evidência]
  Check -->|Sim| Fleet[Implantação progressiva]
~~~

Testar upgrade/downgrade, preservação de `client_id` e `state.json`, política offline, NRPT, WFP, CA, serviço e autorização de desinstalação. A presença de `MajorUpgrade` no MSI não equivale a teste de upgrade.

**Não alterar `OPENEMS_UNINSTALL_MASTER_KEY`** com agentes instalados sem procedimento criptográfico de migração; o segredo por máquina depende dela.

Ver [checklist](production-checklist.md), [validação](../validation/test-matrix.md) e [recuperação](../operations/disaster-recovery.md).
