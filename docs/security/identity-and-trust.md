# Identidade, sessões e certificados

Fontes: `app/auth.py`, `app/sessions.py`, `app/enrollment.py`, `app/api.py`, `app/saml.py` e `agent-rs/src/authority.rs`.

## Identidade administrativa

Login verifica PBKDF2-SHA256 e aplica rate limit. Sessões são revogáveis e podem usar cookie `openems_session` (HttpOnly, SameSite Strict, Secure fora do modo laboratório) ou Bearer; escrita por cookie exige `X-CSRF-Token`. `viewer` tem permissão de leitura. `admin` e `superadmin` atualmente possuem as mesmas permissões `read`, `write` e `manage_idp`.

## Dispositivos

~~~mermaid
sequenceDiagram
  participant Agent as Agente
  participant API as Servidor
  Agent->>API: Convite + devid
  API-->>Agent: client_id + device_token
  Agent->>API: client_id + Bearer nas consultas
  API->>API: Valida identidade e cadastro ativo
  API-->>Agent: Perfil autorizado
  Agent->>API: ACK de aplicação
~~~

`devid` é identificador, `client_id` identifica cadastro, `device_token` é a credencial. O servidor guarda hash da credencial. Re-enrollment de dispositivo existente exige prova de posse; uma máquina revogada deixa de autenticar. Rotação exige distribuição coordenada para evitar perda de conexão.

## SAML

O backend implementa SP SAML 2.0, assinatura XML, condições de tempo/audience, correlação de requisições e replay cache. Cada IdP exige configuração de issuer, URLs, certificados e ensaios reais de login e rollover. Existência de testes criptográficos **não** implica validação de qualquer IdP de produção.

## Chaves e CA

- TLS remoto: `OPENEMS_BASE_URL` requer HTTPS para endereço externo; o proxy deve ter certificado válido e renovação sob gestão do operador.
- Página de bloqueio HTTPS: CA **exclusiva da máquina**, chave protegida localmente, não enviada ao servidor; não é a CA do servidor.
- Segredos: `.env`, senha de DB, sessão, convite, token de dispositivo, chave-mestra de remoção e `uninstall.json` não devem aparecer em repositório, capturas, tickets ou logs.
- `OPENEMS_UNINSTALL_MASTER_KEY` deve ser preservada em cofre externo e backup segregado durante todo o ciclo de vida da frota.

Ver [ameaças](threat-model.md), [remoção](../guides/uninstall-management.md), [configuração](../reference/configuration.md).
