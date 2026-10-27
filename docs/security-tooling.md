# Scanners e gates de segurança

Um comando roda localmente os mesmos gates do CI (`.github/workflows/security.yml`). Cada scanner roda num contêiner fixado por digest; só Docker, Git e Python 3.11+ são necessários no host, e `cargo-deny` para o gate de dependências.

```powershell
python tools/security_scan.py                  # todos os gates estáticos
python tools/security_scan.py --only sast      # um gate
python tools/security_scan.py --dast           # inclui o DAST (pilha descartável)
```

Os relatórios (JSON, SARIF, HTML do ZAP e SBOM) ficam em `.venv/security-reports/<data>/`, fora do Git. O código de saída é 1 quando algum gate falha.

| Gate | Ferramentas | Bloqueia |
|---|---|---|
| `secrets` | gitleaks em todo o histórico | qualquer segredo fora da allowlist `.gitleaks.toml` (só os vetores gerados de teste) |
| `sast` | Semgrep (default, OWASP Top 10, Python, TS, React, Rust, Dockerfile, Actions, secrets) + regras próprias em `.semgrep/` | severidade ERROR; WARNING/INFO vão para o SARIF |
| `dependencies` | pip-audit (lock com hashes e dev), osv-scanner (`requirements.txt`, `web/package-lock.json`, `agent-rs/Cargo.lock`), cargo-deny (`agent-rs/deny.toml`) | qualquer advisory conhecido; licença fora da lista; registry/git desconhecido |
| `container` | hadolint, Trivy config e imagem, SBOM CycloneDX | aviso do hadolint; misconfig HIGH/CRITICAL; vulnerabilidade HIGH/CRITICAL **com correção** na imagem |
| `workflows` | actionlint, zizmor | erro de sintaxe/expressão; achado médio ou maior do zizmor |
| `dast` | ZAP baseline e API scan ativo autenticado (OpenAPI gerado do código) | alerta Low ou maior não aceito; exceção não tratada no servidor |

No CI rodam também:
- **CodeQL** (`security-extended`: Python, TS, Actions e Rust);
- **OpenSSF Scorecard**;
- **dependency-review** nos PRs;
- `npm audit --omit=dev`;
- **Dependabot** semanal para pip, npm, cargo, Docker e Actions.

O CI de qualidade continua cobrindo testes, cobertura mínima (`tools/check_quality.py`), clippy com `-D warnings`, ruff (inclui as regras de segurança `S`) e ESLint com `eslint-plugin-security` e zero avisos.

## Exceções

Achados revisados entram em `security/accepted-findings.json` com motivo e data de validade. Uma exceção vencida reprova o scan e obriga uma nova revisão. Não silencie um scanner com `# nosec`/`noqa` sem o motivo na mesma linha.

## Atualizar versões

- **Actions:** fixadas por SHA, com a versão em comentário. O Dependabot propõe as atualizações.
- **Imagens dos scanners** (`IMAGES` em `tools/security_scan.py`): atualizar o digest deliberadamente e rodar o scan inteiro.
- **Lock Python:** `requirements.txt` é gerado do `requirements.in` com o comando descrito no cabeçalho do `.in`. Os testes recusam lock desatualizado ou sem hash.
- **Bases da imagem:** fixadas por digest no `Dockerfile`; o Dependabot cobre o ecossistema `docker`.

## Hooks locais

`pip install pre-commit` e `pre-commit install` ativam o ruff, o gitleaks das mudanças em stage, o ESLint do painel e o `cargo fmt` em cada commit.
