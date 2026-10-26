# Diagnóstico e solução de falhas

**Primeiro:** determinar se é laboratório ou endpoint real, identificar versão/commit, opções MSI, último ACK e alterações em DNS/CA. Nunca alterar o dispositivo em produção sem autorização e plano de rollback.

| Sintoma | Diagnóstico provável | Ação segura |
| --- | --- | --- |
| Painel inacessível | Compose, proxy TLS, DNS ou porta 8013 | Verificar `docker compose ps`, logs e certificado |
| HTTP 401 na API | Sessão inválida ou token ausente | Renovar login; não habilitar `LAB_MODE` em produção |
| HTTP 403 | Falta de permissão, CSRF ou escopo de endpoint | Conferir papel, header CSRF, token e grupo |
| Convite rejeitado | TTL, usos, VDOM, credencial já existente | Emitir novo convite e investigar duplicidade |
| Máquina aparece, mas não aplica | Erro local, perfil inválido, capacidade ou conectividade | Comparar `desired_profile`, `applied_digest` e `last_error` |
| Falha de DNS / perda de rede | Resolvedor 53, NRPT, WFP, upstream, VPN | Diagnosticar em console local/VM; preparar rollback de regras da instalação |
| HTTPS bloqueado dá erro de certificado | CA não confiável, pinning ou mismatch Host/SNI | Conferir confiança e escopo da página; não desabilitar TLS global |
| Categoria não bloqueia | Manifesto não publicado, cache ou digest errado | Inspecionar volume `categories`, versões, permissões e logs |
| Sem eventos web | Modo `hosts`, ausência de filtro DNS ou falha no envio | Verificar `web-filter:dns`, ciclo do agente e servidor |
| Desinstalação retorna 1603 | Código ausente/errado, lockout, segredo corrompido | Usar código válido/política de liberação; inspecionar log MSI sanitizado |
| Serviço não para | ACL de antiadulteração para SYSTEM | Procedimento suportado por MSI; não forçar remoção sem autorização |

## Ordem de diagnóstico

~~~mermaid
flowchart TD
  Start[Sintoma] --> Server{Servidor alcançável?}
  Server -->|Não| TLS[Compose, rede, proxy e TLS]
  Server -->|Sim| Identity{Autenticação correta?}
  Identity -->|Não| Cred[Convite, sessão ou device token]
  Identity -->|Sim| Policy{Política aplicada?}
  Policy -->|Não| Logs[ACK, versão, digest, last_error, cache]
  Policy -->|Sim| Windows[NRPT, WFP, CA, DNS upstream, processos]
  Logs --> Safe[Correção e revalidação em VM]
  Windows --> Safe
  TLS --> Safe
  Cred --> Safe
~~~

Não apagar chaves, `state.json`, `uninstall.json`, regras NRPT ou certificados sem identificar propriedade e autorização. Ver [disaster recovery](disaster-recovery.md), [proteção](../security/endpoint-protection.md).
