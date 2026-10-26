# Gate de produção

**Status atual: não homologado para uso corporativo amplo.** Checklist de autorização, não declaração de conformidade.

- [ ] Ambiente de laboratório e piloto têm responsável, escopo e aceite registrado.
- [ ] Matriz de Windows, VPN, EDR, DNS, Chrome/Edge/Firefox, CA e captive portal validada em máquinas representativas.
- [ ] Instalação, reboot, crash, modo offline, atualização, desinstalação e recuperação testados sem perda de conectividade.
- [ ] MSI/binários assinados e canal de distribuição autenticado.
- [ ] TLS de produção, segregação Postgres/Redis, segredos e RBAC configurados.
- [ ] Backup/restauração de dados, chaves e estado de remoção testados; RTO/RPO definidos.
- [ ] Base legal LGPD, transparência, retenção, acesso e governança de logs aprovados.
- [ ] Licenças UT1, dependências e uso da identidade visual RSM verificados.
- [ ] Funcionalidades de GUI que dependem do console legado mapeadas.
- [ ] Suíte Python, Rust, painel, CI, integração com DB/Redis e Sandbox aprovadas sem skips críticos.
- [ ] Plano de rollback, monitoramento, critérios de parada e suporte documentados.
- [ ] Riscos de compatibilidade e suporte declarados aos responsáveis.

Até fechar estes critérios, a existência de testes unitários ou evidências no Windows Sandbox **não** caracteriza produto homologado.
