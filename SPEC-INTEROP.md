# Especificação de Interoperabilidade — Protocolo de Endpoint Management (clean-room)

**Objetivo:** descrever, a partir de comportamento observável, a interface que um
endpoint tipo FortiClient usa para falar com um servidor de gerência (EMS), de modo
que um **servidor open-source compatível** possa ser escrito **do zero** a partir
deste documento, sem copiar código proprietário.

**Base de evidência:** strings/endpoints estáticos de binários legalmente instalados
(ver `findings/`). Nenhum fluxo de rede foi capturado em execução — campos marcados
`[obs]` vêm de strings dos binários; `[inferido]` são deduções; `[a capturar]`
precisam de captura de tráfego real (mitmproxy/pcap contra um EMS de laboratório)
para fechar o formato exato.

> **Clean-room / legal:** este documento descreve *interface e comportamento*
> (não protegidos por copyright). A implementação open-source deve ser escrita
> **só a partir desta spec**, por quem não leu o código da Fortinet, sem usar as
> marcas Fortinet/FortiClient e sem copiar binários, assets ou código deles.
> EULAs e leis variam por jurisdição; valide com um advogado antes de distribuir.

---

## 1. Visão geral da topologia

```
  Endpoint (agente)                         Servidor de gerência (EMS compatível)
  ┌──────────────┐    TLS / TCP 8013        ┌───────────────────────────────┐
  │ daemon ESNAC │ ───────────────────────► │ Device Access Server (nativo) │
  │ (registro +  │   /fct/api/public/v1/*   │  -> fila/cache (Redis)         │
  │  telemetria) │ ◄─────────────────────── │  -> banco (SQL)               │
  └──────────────┘   config push            └───────────────┬───────────────┘
        ▲                                                    │
        │ SSO SAML (/fct_saml/*)                             │ REST /api/v1/* (console/admin)
        ▼                                                    ▼
     IdP (SAML)                                   Web console + API de gerência
```

- **Canal de endpoint:** TCP **8013** [obs], TLS [inferido]. Alta frequência
  (registro, keepalive, telemetria).
- **Canal de administração:** API REST `/api/v1/...` + console web.
- **Autenticação de usuário:** SAML (EMS atua como Service Provider).

---

## 2. Canal endpoint ↔ EMS (porta 8013)

### 2.1 Parâmetros de registro (do lado do agente) [obs]
O agente registra com: endereço do EMS **ou** invitation code, porta (default 8013),
site/VDOM (default "Default"), e uma chave opcional.

| Parâmetro | Significado |
|---|---|
| `address / invitation` | host do EMS ou código de convite |
| `port` | TCP, default **8013** |
| `vdom / site` | agrupamento lógico no EMS, default `Default` |
| `key` | chave de registro (opcional) |

### 2.2 Endpoints REST do canal de endpoint [obs]
Base: `https://<ems>:8013/fct/api/public/v1/`

| Método | Caminho | Função [inferido] |
|---|---|---|
| `POST` | `/fct/api/public/v1/register/` | registro inicial do endpoint |
| `POST` | `/fct/api/public/v1/refresh/` | renovação de sessão/token |
| `POST` | `/fct/api/public/v1/update_client_id/` | atualização do identificador do cliente |

### 2.3 Identidade do endpoint [obs]
Campos usados para identificar cada endpoint nos registros de telemetria:

| Campo | Descrição |
|---|---|
| `devid` | device ID único do endpoint |
| `uid` | user/host id |
| `fgtserial` | serial do FortiGate associado (se houver) |
| `emsserial` | serial do EMS |
| `regip` | IP de registro |
| `fctver` | versão do agente |
| `os` | sistema operacional |
| `hostname`, `pcdomain` | nome/domínio da máquina |

### 2.4 Telemetria / postura [obs]
- **host tags** (Zero-Trust): JSON `{"host_tags":"<...>"}` — tags de postura que o
  servidor usa para regras ZTNA, consultáveis por serial de FortiGate.
- **avatar**: identidade/representação do endpoint, enviada **em chunks** (há limite
  máximo por chunk) — `[a capturar]` o tamanho de chunk e o encoding exato.
- **keepalive**: mensagem periódica (há "heart beat duration/last time" no agente)
  — `[a capturar]` o intervalo e o payload.
- **config push**: o servidor devolve "configuration update" — perfil que o agente
  aplica e sela localmente.

### 2.5 Sequência de registro (reconstrução) [inferido]
```
1. Agente -> POST /register/ { devid, fctver, os, hostname, (invitation|key), vdom }
2. EMS    -> 200 { client_id, emsserial, config/profile, polling_interval }
3. Agente -> POST /update_client_id/ (se o EMS reatribuir id)
4. loop:
   Agente -> keepalive + host_tags + avatar (chunks)   [intervalo a capturar]
   EMS    -> config update (quando o perfil muda)
5. refresh de sessão via /refresh/ quando o token expira
```

---

## 3. API de administração `/api/v1/*` (console) [obs]

Rotas confirmadas por strings (amostra). Formato de payload = `[a capturar]`.

| Caminho | Função |
|---|---|
| `GET /api/v1/endpoints/index` | lista de endpoints |
| `GET /api/v1/endpoints/count` | contagem |
| `GET /api/v1/endpoints/export` | exportação |
| `GET /api/v1/endpoints/cloud/summary` | resumo (cloud) |
| `GET /api/v1/endpoints/{type}/bar|bubble` | dados de dashboard |
| `POST /api/v1/report/fct/avatar` | ingestão de avatar |
| `GET /api/v1/report/fct/host_tags` | tags ZTNA por serial de FortiGate |

Domínios de controller observados (≈80): `endpoint`, `endpoint_policy`, `device`,
`deployment`, `compliance_verification_rule_set`, `certificate`, `alert`, `event`,
`forensics`, `fabric_device_auth`, `ad_connector`, `acme`, `chromebook_policy`,
`group_assignment_rule`, `forti_gate_connection_details`, `forti_sandbox`…

---

## 4. Autenticação SAML `/fct_saml/*` [obs]

| Caminho | Função |
|---|---|
| `GET /fct_saml/login` | inicia login SAML |
| `POST /fct_saml/{prefix}/acs` | Assertion Consumer Service |
| `GET /fct_saml/{prefix}/metadata` | metadata do SP (o EMS) |
| `POST /fct_saml/parse_remote_metadata` | importa metadata do IdP |

O EMS é **Service Provider**; integra com IdP SAML externo (e também MSAL/Entra ID
no lado do agente).

---

## 5. Modelo de dados mínimo (para o servidor open-source) [inferido]

```
Endpoint(devid PK, hostname, os, fctver, user, last_seen, status, vdom)
Registration(devid FK, client_id, emsserial, invitation/key, reg_ip, created_at)
HostTag(devid FK, tag, source, updated_at)        # base das regras ZTNA
Avatar(devid FK, blob/chunks, fingerprint)
Policy(id, vdom, profile_xml/json)                # config empurrada ao endpoint
TelemetryEvent(devid FK, type, payload, ts)       # tráfego/UTM/eventos
FortiGateLink(devid FK, fgtserial)                # correlação com FortiGate
```

---

## 6. Arquitetura de referência da implementação open-source

Totalmente independente de tecnologia (o original usa Apache+Django+C++; você escolhe):

| Camada | Sugestão livre |
|---|---|
| API endpoint (8013/TLS) | FastAPI ou Go, endpoints `/fct/api/public/v1/*` |
| API de gerência | FastAPI/Django REST `/api/v1/*` + console (React) |
| Fila/cache | Redis |
| Banco | PostgreSQL |
| SSO | python3-saml / qualquer lib SAML (SP) |
| TLS | certificado próprio; o agente valida — `[a capturar]` o pinning |

### Roadmap sugerido
1. **Capturar tráfego real** contra um EMS de laboratório (mitmproxy) para fixar os
   payloads exatos de `register/refresh/keepalive/avatar/host_tags` — isto fecha os
   `[a capturar]` desta spec. Fazer isso **só com um EMS que você tem direito de usar**.
2. Implementar o `/register/` mínimo e ver um agente de teste registrar.
3. Adicionar keepalive + host_tags + avatar.
4. Config push (perfil) e políticas.
5. Console `/api/v1/*` e SAML.

---

## 7. Pendências para fechar a spec (`[a capturar]`)
- Formato exato (JSON? protobuf?) dos corpos em `/fct/api/public/v1/*`.
- Intervalo e payload de keepalive; tamanho de chunk do avatar.
- Esquema de autenticação do canal 8013 (token? mTLS? invitation flow).
- Validação de certificado do lado do agente (pinning).
- Semântica completa do config push (formato do perfil).

> Todos os itens acima se resolvem com **captura de tráfego** de um ambiente de
> laboratório próprio — não por mais leitura do binário. Esse é o próximo passo
> técnico para transformar esta spec de interoperabilidade numa implementação.
