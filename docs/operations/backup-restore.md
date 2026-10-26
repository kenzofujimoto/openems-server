# Backup, restore e integridade

## Escopo mínimo de backup

- PostgreSQL: endpoints, credenciais hasheadas, perfis/versionamento, regras, admin/sessões persistidas, IdPs, auditoria, eventos e contadores de desinstalação.
- `.env` e segredos geridos externamente, principalmente `OPENEMS_SESSION_SECRET` e **`OPENEMS_UNINSTALL_MASTER_KEY`**.
- Volume `categories` e manifesto, versões de código/imagens, configuração proxy e certificados.
- Redis: decidir se dump/AOF precisa ser restaurado ou se filas/replay podem ser reconstruídos sob risco controlado.

Backup não deve conter segredo em log, chat ou repositório. Restringir acesso, criptografar e testar recuperação periodicamente.

## Exemplo de dump PostgreSQL em host Bash

~~~bash
# No diretório com docker-compose.yml; destino local deve ser seguro.
docker compose exec -T postgres pg_dump -U postgres -d openems -Fc > openems-$(date +%Y%m%d).dump
~~~

**Em PowerShell**, redirecionamento de saída binária pode alterar bytes conforme a versão; prefira executar `pg_dump` no host com `-f` e canal autenticado ou usar cópia binária validada. Nunca publicar dumps.

## Restore — ambiente isolado

1. Provisionar Postgres da mesma versão ou versão suportada; parar serviços que escrevem no banco.
2. Validar integridade dos arquivos e recuperar segredos de cofre.
3. Restaurar o dump em base **descartável nova**; por exemplo `pg_restore --clean --if-exists -U postgres -d openems backup.dump` no ambiente adequado, confirmando schema e owners.
4. Subir a versão compatível da API, executar testes de saúde, sessões, perfil/ACK e leitura de eventos.
5. Conferir `uninstall_state`: restore de contador antigo pode permitir inconsistência com códigos já usados; não reconectar endpoints reais antes de análise.
6. Retornar produção apenas sob mudança aprovada; documentar RPO/impacto de eventos e filas ausentes.

## Política

RPO e RTO ainda não estão definidos pelo projeto. O operador deve estabelecê-los, testar restore completo de banco/chaves e garantir retenção/exclusão também nos backups. Ver [recuperação](disaster-recovery.md) e [privacidade](../security/privacy-lgpd.md).
