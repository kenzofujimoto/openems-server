# Política de segurança

## Versões suportadas

Só a `main` recebe correções. Os pacotes do agente (MSI/DEB) suportados são os gerados a partir dela, identificados por revisão e SHA-256 nos manifestos de aceite.

## Reportar uma vulnerabilidade

Não abra issue pública. Use o reporte privado do GitHub em <https://github.com/kenzofujimoto/openems-server/security/advisories/new> e informe:
- componente (servidor, painel, agente Windows/Linux, instalador);
- versão ou revisão;
- passos para reproduzir;
- impacto esperado.

Não envie dados pessoais reais nem credenciais de produção. Use contas e máquinas de teste.

- Confirmação do recebimento: até 3 dias úteis.
- Avaliação inicial e severidade (CVSS): até 7 dias.
- Correção de falhas críticas ou altas: o mais rápido possível, com aviso publicado junto da versão corrigida.

Pesquisa de boa-fé, sem acesso a dados de terceiros, sem negação de serviço e com tempo razoável para a correção, não será alvo de ação legal.

## Fora do escopo

- Ataques que exigem administrador local já comprometido na máquina do agente.
- Achados só de scanners, sem prova de impacto.
- Falta de cabeçalhos já listados como aceitos em `security/accepted-findings.json`.

## Como o projeto se protege

Gates de segurança no CI e no comando local `python tools/security_scan.py`:
- segredos no histórico;
- SAST: Semgrep, regras próprias, CodeQL e ruff `S`;
- dependências: pip-audit, osv-scanner, cargo-deny, npm audit e Dependabot;
- imagem e IaC: Trivy, hadolint e SBOM CycloneDX;
- workflows: actionlint e zizmor;
- DAST: ZAP passivo e ativo autenticado numa pilha descartável;
- OpenSSF Scorecard.

Detalhes em [docs/security-tooling.md](docs/security-tooling.md). A revisão mais recente está em [docs/security-review-2026-10-27.md](docs/security-review-2026-10-27.md).
