# Interfaces e limites de confiança

~~~mermaid
flowchart LR
  Browser[Navegador / administrador] -->|HTTPS cookie + CSRF| Proxy[Proxy TLS]
  Agent[Agente Rust] -->|HTTPS credencial do dispositivo| Proxy
  IdP[IdP SAML] -->|SAML Response assinada| Proxy
  Proxy --> API[FastAPI :8013]
  API --> PG[(PostgreSQL)]
  API --> Redis[(Redis)]
  Agent --> DNS[DNS local 53 / NRPT / WFP]
  Agent --> Page[Página local HTTP/HTTPS 80/443]
~~~

| Fronteira | Canal | Autorização |
| --- | --- | --- |
| Admin → gestão | `/api/v1/*` | Sessão revogável, cookie HttpOnly, CSRF em mutações, papéis |
| Agente → endpoint channel | `/fct/api/public/v1/*` | `client_id` + token do dispositivo, convites no registro |
| Admin → IdP | `/fct_saml/*` | Fluxos e validação SAML; conferir implantação real do IdP |
| Servidor → Postgres/Redis | Rede interna Compose | Credenciais e segmentação operacionais |
| Endpoint → OS | APIs/serviço privilegiado | SYSTEM / ACL / WFP / NRPT |
| Endpoint → servidor | HTTP apenas para loopback/laboratório ou opt-in explícito; HTTPS remoto | TLS e controle de segredos |

**Portas e observações:** `8013` HTTP interno/proxy; `53` DNS local UDP/TCP; `80` e `443` são listeners locais da página de bloqueio quando habilitados. `docker-compose.yml` não publica PostgreSQL nem Redis no host. `deploy/nginx.conf` e `docker-compose.tls.yml` são exemplos de proxy, não substitutos da emissão/renovação de certificados.

O agente não executa TLS interception de conexões de sites permitidos. A CA por endpoint é empregada para página de bloqueio HTTPS e exige análise de risco específica. A classe de aplicativos com pinning pode apresentar erro de certificado em vez da página.

Ver [API](../reference/api.md) e [confiança](../security/identity-and-trust.md).
