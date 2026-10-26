# Implantação do servidor — Docker e TLS

Fontes: `Dockerfile`, `docker-compose.yml`, `docker-compose.tls.yml`, `deploy/nginx.conf` e `deploy/new-env.ps1`.

| Serviço | Uso | Persistência |
| --- | --- | --- |
| postgres:16 | Dados operacionais e migrations | `pgdata` |
| redis:7 | Fila e estado temporário | `redisdata` |
| server | API Python 3.14 e React compilado | Banco e volume `categories` RO |
| categories (profile opt-in) | Atualização de catálogo | `categories` |

O runtime usa UID não privilegiado, filesystem read-only, `tmpfs` e capacidades removidas. O servidor expõe `127.0.0.1:8013:8013` no host; banco e cache **não** são publicados.

## Laboratório

~~~powershell
powershell -ExecutionPolicy Bypass -File deploy/new-env.ps1
docker compose up -d --build
docker compose ps
~~~

## Acesso remoto por HTTPS

~~~powershell
powershell -ExecutionPolicy Bypass -File deploy/new-env.ps1 -BaseUrl https://ems.exemplo.net
docker compose -f docker-compose.yml -f docker-compose.tls.yml config
docker compose -f docker-compose.yml -f docker-compose.tls.yml up -d --build
~~~

`ems.exemplo.net` é placeholder; requer DNS sob controle do operador, TLS válido e adaptação dos caminhos de certificado definidos no Nginx. O proxy termina TLS, comunica-se com o `server` na rede Docker e deve restringir acesso administrativo. Não expor `OPENEMS_LAB_MODE` fora de loopback.

## Operação e backup

~~~bash
docker compose ps
docker compose logs --tail 200 server
docker compose restart server
~~~

Antes de atualização, exportar dados e segredos; não reexecutar `new-env.ps1 -Force` em produção sem plano, porque isso troca segredos importantes embora preserve a chave de desinstalação.

O serviço `categories` só deve ser habilitado com `--profile categories` depois de confirmar URL e licença da fonte UT1 e configurar `OPENEMS_UT1_URL`. O Compose intencionalmente não define URL padrão.

Ver [configuração](../reference/configuration.md), [backup](../operations/backup-restore.md), [checklist](production-checklist.md).
