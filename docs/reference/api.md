# API HTTP — referência de rotas

Fonte: `app/api.py`, `app/schemas.py`. Quando servidor estiver em execução, `/openapi.json` expõe schema gerado pelo FastAPI. Este resumo explica as restrições e principais contratos; não substitui o OpenAPI nem os testes.

## Autorização

- `POST /api/v1/auth/login` aceita `username` e `password`, cria sessão revogável e cookie `openems_session`. `GET /api/v1/auth/session` informa papel e token CSRF; `POST /api/v1/auth/logout` revoga.
- Cookie HttpOnly, SameSite Strict e Secure fora do laboratório. Em mutações autenticadas por cookie, passar `X-CSRF-Token`. Bearer administrativo é aceito para sessão.
- Dispositivo usa `Authorization: Bearer DEVICE_TOKEN` e `client_id`; registro inicial por convite é exceção. Sem sessão/credencial: 401; sem permissão/CSRF: 403; política/estado incompatível: 409; corpo inválido: 422; login limitado: 429.

## Gestão (`/api/v1`)

| Método | Rota | Função |
| --- | --- | --- |
| POST | `/auth/login` | Login |
| GET / POST | `/auth/session` (GET), `/auth/logout` (POST) | Sessão |
| GET | `/endpoints/index`, `/count`, `/detail?devid=` | Endpoints |
| POST | `/endpoints/credentials/rotate`, `/endpoints/revoke` | Autenticação |
| POST | `/enrollment/invitations` | Convites por grupo/uso/TTL |
| POST / GET | `/profiles/{vdom}` (POST), `/profiles` (GET) | Políticas |
| POST / GET / DELETE | `/assignment_rules`, `/assignment_rules/{rule_id}` | Atribuição |
| GET | `/report/fct/host_tags?devid=` | Tags |
| GET | `/events?limit=`, `/stats/overview`, `/categories`, `/audit` | Visibilidade |
| POST | `/endpoints/uninstall_code`, `/endpoints/uninstall_secret/reset` | Remoção |
| GET / POST | `/uninstall_release` | Liberação grupo/frota |

Para publicar, enviar **o corpo** da política, não um envelope:

~~~http
POST /api/v1/profiles/Default
Content-Type: application/json
X-CSRF-Token: <csrf-do-ambiente>
Cookie: openems_session=<sessao-do-ambiente>

{"web_filter":{"blocked":["example.test"]},"app_control":{"blocked":["demo.exe"]}}
~~~

A resposta inclui `vdom`, `version`, `digest` e `warnings` de capacidade. `POST /api/v1/assignment_rules` usa `id`, `target_vdom`, `priority`, `enabled` e `conditions`.

## Canal do dispositivo (`/fct/api/public/v1`)

| Método | Rota | Função |
| --- | --- | --- |
| POST | `/register/` | Primeiro cadastro/recadastro |
| POST | `/refresh/`, `/update_client_id/` | Identidade |
| GET | `/config/`, `/config/assigned/` | Perfil por grupo/efetivo |
| POST | `/messages/pull/` | Notificações |
| POST | `/config/ack/` | Confirma versão/grupo/digest e êxito |
| POST | `/host_tags/` | Tags |
| GET | `/categories/`, `/categories/file/` | Manifesto/dados |
| POST | `/events/`, `/tamper/` | Telemetria |
| POST | `/uninstall_secret/`, `/uninstall_secret/ack/` | Segredo inicial |

ACK de produção exige `client_id`, `vdom`, `version`, `digest`, `success` e `error` opcional. O servidor rejeita ACK incoerente, não aceita mero recebimento como aplicação confirmada.

## SAML

`GET /fct_saml/{prefix}/metadata`, `GET /fct_saml/login`, `POST /fct_saml/{prefix}/acs` e `POST /fct_saml/parse_remote_metadata`. A importação de IdP é ação gerencial protegida. Tratar SAMLResponse, RelayState e certificados como dados sensíveis conforme contexto.

Nunca publicar tokens/cookies de ambiente real em exemplos.
