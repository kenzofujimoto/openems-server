# Início rápido — laboratório

Escopo: subir **apenas o servidor** em uma máquina de desenvolvimento. Não instalar o agente no computador de trabalho; testes com DNS, certificados e WFP devem usar Windows Sandbox/VM descartável.

## Pré-requisitos

Docker Compose v2, PowerShell, acesso às imagens Docker e porta `127.0.0.1:8013` livre.

~~~powershell
git clone https://github.com/kenzofujimoto/openems-server.git
cd openems-server
powershell -ExecutionPolicy Bypass -File deploy/new-env.ps1
docker compose up -d --build
docker compose ps
~~~

O script gera `.env` com segredos aleatórios e exibe inicialmente credenciais, convite e chave-mestra de remoção. Guarde-os em cofre. **Não existe senha padrão**; nunca versione o `.env`.

Abra `http://localhost:8013/panel/`. O painel React ainda é parcial e parte da administração continua em `/console/`.

## Verificação e encerramento

~~~powershell
docker compose logs --tail 100 server
curl.exe -I http://127.0.0.1:8013/
docker compose down
~~~

É esperado `401` em endpoints gerenciais sem sessão e redirecionamento na raiz. Não use `docker compose down -v` com dados relevantes: isso elimina volumes persistentes.

Para outros computadores, primeiro configurar TLS, DNS e convites; seguir [implantação](../deployment/server-docker.md), [primeiro cadastro](first-enrollment.md) e [agente Windows](../deployment/windows-agent.md).
