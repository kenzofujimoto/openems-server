# Proteção local no Windows

## Controles implementados

- Serviço Rust sob SYSTEM, inicialização automática, recovery e watchdog/tarefa agendada.
- Arquivos/ACLs, monitoramento de alterações e eventos de adulteração.
- Filtragem por `hosts` ou DNS loopback com NRPT; mitigação de bypass via WFP e políticas de navegador.
- Página de bloqueio HTTP/HTTPS, com CA local e certificados efêmeros de domínios bloqueados.
- Remoção controlada por código HMAC e liberação administrativa assinada por endpoint.

## Limites de segurança

1. Não há resistência absoluta a administrador local/SYSTEM. Não afirmar inviolabilidade.
2. O controle de aplicativos por nome encerra processos; não previne a primeira execução ou substitui WDAC.
3. Não há controle USB de produção neste repositório.
4. DNS/NRPT fail-closed pode indisponibilizar navegação, VPN e resolução interna. Necessário ensaiar compatibilidade e restore.
5. WFP/políticas de navegador não cobrem necessariamente todo resolvedor embutido, protocolo ou versão do browser.
6. CA raiz local amplia a superfície de confiança. Deve ser removida somente com confirmação de propriedade do agente; aplicativos com pinning podem falhar em vez de exibir a página.

## Gate de teste

~~~mermaid
flowchart TD
  Opt[Opções e política aprovadas] --> VM[Windows Sandbox / VM]
  VM --> Initial[Instalação, cadastro, política]
  Initial --> Failure[Crash, reboot, offline, adulteração]
  Failure --> Network[VPN, DNS, HTTP/HTTPS, navegadores]
  Network --> Remove[Remoção, CA, WFP, NRPT e hosts restaurados]
  Remove --> Evidence[Evidência com hash, commit e pendências]
~~~

O ambiente de produção requer assinatura de MSI/binário, máquina piloto, controle de mudanças e mecanismo de recuperação com servidor indisponível. Ver [matriz](../validation/test-matrix.md).
