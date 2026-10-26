# Recuperação de desastre

**Princípio:** recuperar o serviço sem liberar indevidamente a última política válida nem perder capacidade de remoção segura.

~~~mermaid
flowchart TD
  Incident[Incidente] --> Kind{O que foi afetado?}
  Kind -->|Servidor/DB| Server[Restaurar dados e segredos íntegros]
  Kind -->|Endpoint| Agent[Diagnosticar serviço, CA, NRPT e WFP]
  Kind -->|Chave-mestra| Vault[Acionar custódia de segredos e resposta]
  Server --> Test[Testes em ambiente isolado]
  Agent --> Test
  Vault --> Test
  Test --> Gate{Convergência e rollback comprovados?}
  Gate -->|Não| Isolate[Manter mitigação e investigação]
  Gate -->|Sim| Recover[Retomar gradualmente com monitoramento]
~~~

## Cenários

| Cenário | Resposta |
| --- | --- |
| API fora do ar | Agente deve manter última política validada em cache; verificar sincronização/ACK após recuperação |
| PostgreSQL perdido | Restaurar backup consistente e segredos; conferir schema, identidades, perfis, auditoria e contadores |
| Redis indisponível | Restaurar serviço de filas e revisar mensagens pendentes/replay/SAML; verificar comportamento de múltiplas instâncias |
| Chave-mestra de remoção perdida | Não gerar nova chave silenciosamente: os segredos dos agentes dependem da antiga. Acionar cofre e plano autorizado |
| DNS/NRPT/WFP danificados | Recuperar com procedimento suportado, sob SYSTEM quando exigido, identificando apenas artefatos OpenEMS |
| CA local danificada | Restaurar confiança da instalação correta ou remover com rotina controlada; não limpar outras CAs |
| `uninstall.json` corrompido | Estado danificado pode bloquear desinstalação; reabrir entrega de segredo/liberar remoção pelo fluxo administrativo aprovado |

## Critérios de recuperação

1. Servidor com TLS válido, sessão admin e conexão DB/Redis operacional.
2. Agente autenticando e recebendo o perfil certo; aplicação com ACK e digest compatível.
3. Rede, DNS interno, VPN, página de bloqueio e certificados com funcionamento normal.
4. Eventos e auditoria novamente disponíveis, sem exposição de segredos.
5. Remoção/rollback em VM comprovados; registrar tempo real do incidente e perdas de dados.

Não há RTO/RPO oficiais. Definir antes de produção. Ver [backup](backup-restore.md) e [diagnóstico](troubleshooting.md).
