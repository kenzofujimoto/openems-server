# Revisão de segurança — 27/10/2026

Revisão da `main` em `a306290`. Escopo: servidor/painel, agente Windows (Rust), imagem Docker, CI e dependências. Os scanners rodaram em contêineres descartáveis sobre um `git archive` só para leitura; os digests das imagens estão em [validation/security-review-2026-10-27.json](../validation/security-review-2026-10-27.json). O DAST ativo rodou contra uma pilha isolada com segredos aleatórios, nunca contra a homologação compartilhada com o agente do host.

## Resultado por ferramenta

| Área | Ferramenta | Resultado |
|---|---|---|
| Segredos no histórico (471 commits) | gitleaks | 13 alertas, todos em `contract/uninstall-vectors.json`: vetores derivados de `test-only-master-key`. Falso positivo, falta allowlist |
| SAST multilinguagem | Semgrep (default, OWASP Top 10, Python, TS, React, Rust, Dockerfile, Actions, secrets) | 3 ERROR, todos falsos positivos: SQL com fragmentos constantes e XML de relatório de cobertura local. 19 WARNING: 16 actions por tag mutável, `Host` no nginx e 2 menores. 75 INFO de `unsafe` Rust em FFI Win32 já comentado |
| SAST Python | Bandit | Nenhum HIGH. MEDIUM revisados: SQL constante, bind `0.0.0.0` que é IP do arquivo hosts, ElementTree no SAML (abaixo) |
| Dependências Python | pip-audit, osv-scanner, Trivy | **Reais:** `starlette 0.41.3` (via `fastapi 0.115.6`, até 7,5), `python-multipart 0.0.20` (3 HIGH, incluindo escrita arbitrária de arquivo CVE-2026-24486), `anyio 4.9.0` (9,3), `certifi` (9,1), `idna`, `urllib3`, `msgpack`, `setuptools`, `pygments`, `pytest` |
| Dependências Rust e painel | osv-scanner (`Cargo.lock`, `package-lock.json`) | Sem vulnerabilidades conhecidas |
| Imagem de produção | Trivy image | Python: 22 corrigíveis (10 HIGH). Debian 13.7 base: 164 sem correção publicada. A imagem inclui pytest, playwright e Node.js, que não são de produção |
| Dockerfile | hadolint, Trivy misconfig | Sem erro; falta `HEALTHCHECK`; bases sem digest |
| DAST passivo | ZAP baseline | 0 FAIL; avisos: Permissions-Policy, COOP/CORP, CSP `style-src 'unsafe-inline'`; "IP privado" é um exemplo de CIDR (falso positivo) |
| DAST ativo autenticado | ZAP API scan (OpenAPI, Bearer) | **0 FAIL, 117 regras aprovadas** (SQLi, XSS, path traversal, injeção de comando, SSRF etc.), nenhum 500 no servidor sob ataque |

## Revisão manual

Confirmados como corretos:
- Bearer ou cookie `HttpOnly`/`Secure`/`SameSite=Strict`; CSRF exigido em escrita por cookie;
- papéis verificados; limite de login por usuário+IP e por IP;
- token de dispositivo com 32 bytes aleatórios, hash e comparação em tempo constante, invalidado em revogação/rotação;
- arquivos de categoria servidos só se listados e com digest conferido;
- TLS do agente com rustls; `agent.json`/`state.json` com ACL privada;
- SAML com assinatura (signxml/lxml sem entidades e sem rede);
- contêiner não-root, `read_only`, `cap_drop: ALL`.

## Achados priorizados

| # | Severidade | Achado | Correção proposta |
|---|---|---|---|
| 1 | Alta | `python-multipart`/`starlette`/`anyio`/`certifi`/`urllib3` vulneráveis em produção | Atualizar FastAPI/Starlette e `python-multipart`; travar transitivas com hashes (`--require-hashes`) |
| 2 | Média | Ferramentas de teste (pytest, playwright + Node.js, ruff) na imagem de produção | Separar `requirements-dev.txt`; imagem só com runtime; remover pip/setuptools da camada final |
| 3 | Média | `/docs` e `/openapi.json` públicos sem autenticação | Desligar fora do modo laboratório |
| 4 | Média | Actions por tag mutável, bases Docker sem digest, sem Dependabot | Fixar SHA e digest; Dependabot para pip, npm, cargo, docker e actions |
| 5 | Baixa | Checagem de DTD do SAML em bytes ASCII: um documento UTF-16 passa (o expat atual limita a expansão) | `defusedxml`, ou checar após decodificar |
| 6 | Baixa | Convite consumido permanece no `agent.json` (legível só por SYSTEM/Administradores); com o padrão de 10 usos do `new-env.ps1`, um admin local poderia cadastrar outras máquinas | Apagar o convite após o registro bem-sucedido (exige MSI novo) |
| 7 | Baixa | Faltam Permissions-Policy, COOP, CORP | Adicionar no servidor e no nginx |
| 8 | Baixa | nginx repassa `$http_host` | Usar `$host` com `server_name` explícito |
| 9 | Info | Debian base com 164 CVEs sem correção | Monitorar com gate só para corrigíveis; avaliar base mínima |

Não houve achado crítico explorável no código próprio. O risco concreto hoje está nas dependências do servidor.
