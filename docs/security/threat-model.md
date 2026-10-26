# Modelo de ameaças

**Escopo:** API FastAPI, canal administrativo, cadastro de dispositivos, agente com privilégios SYSTEM, persistência, MSI e certificados locais. Análise arquitetural qualitativa; **não substitui** pentest, revisão de código ou homologação de segurança.

## Fronteiras de confiança

~~~mermaid
flowchart LR
  Internet[Redes não confiáveis] --> TLS[Proxy HTTPS]
  Browser[Admin no navegador] -->|Cookie / CSRF| TLS
  Endpoint[Agente Windows SYSTEM] -->|Token do dispositivo| TLS
  IdP[IdP SAML] -->|Resposta SAML assinada| TLS
  TLS --> API[FastAPI]
  API --> DB[(PostgreSQL)]
  API --> R[(Redis)]
  Endpoint --> OS[NRPT / WFP / CA / serviço]
  LocalUser[Usuário e administrador local] -.->|Pode tentar adulterar| OS
~~~

## Matriz de ameaças

| Risco | Controle implementado | Limite e ação adicional |
| --- | --- | --- |
| Roubo de sessão / CSRF | Sessões revogáveis, HttpOnly, SameSite, CSRF | TLS, expiração, acesso ao host e monitoramento |
| Cadastro forjado | Convite com TTL/uso, token por dispositivo e prova de posse | Distribuição segura, revogação/rotação coordenada |
| Acesso à política de outro dispositivo | Autenticação do `client_id` e escopo de grupo | Revisão de IDOR e regressão negativa |
| Política falsificada / ACK indevido | Digest, versão, validação e ACK após enforcement | Administrador/SYSTEM controla a máquina local |
| CA comprometida | Chave por máquina, ACL/DPAPI e remoção por instalação | Chave raiz local é alvo crítico; testar pinning e extração |
| Perda de DNS | Recuperação, watchdog e reversão NRPT | Política fail-closed pode interromper conectividade |
| Remoção indevida | Código HMAC, contador, lockout e trilha | Liberação ampla, servidor sem chave e admin local |
| Vazamento de telemetria | Agregação, limite, RBAC, retenção | Domínio + dispositivo pode identificar pessoa |
| Execução de MSI malicioso | Pacote/serviço transacional | Assinatura e cadeia de distribuição pendentes |
| Interop com terceiros | Especificação clean-room e limites explícitos | Payloads reais não validados; testes autorizados pendentes |

## Ameaças residuais

O usuário com permissão de administrador local ou SYSTEM é adversário privilegiado: as proteções do agente em modo usuário não constituem garantia absoluta. WFP reduz determinados caminhos de bypass, não substitui driver de proteção integral. Um atacante que controle o servidor, proxy ou a chave-mestra pode afetar toda a frota. O plano de recuperação precisa considerar perda parcial desses ativos.

Ver [controle de identidade](identity-and-trust.md), [proteção de endpoint](endpoint-protection.md), [desastre](../operations/disaster-recovery.md).
