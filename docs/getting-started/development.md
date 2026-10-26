# Desenvolvimento e execução de testes

## API Python

~~~bash
python -m venv .venv
# Linux: source .venv/bin/activate
# PowerShell: .venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
uvicorn --factory app.api:build --host 127.0.0.1 --port 8013
~~~

Sem `OPENEMS_DATABASE_URL`, stores em memória; não usar para produção. Configurar PostgreSQL/Redis via Compose para testar a persistência. O modo `OPENEMS_LAB_MODE` foi construído para testes em loopback, não para exposição remota.

## Agente Rust

~~~bash
cd agent-rs
cargo fmt --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked
cargo build --release --locked
~~~

Requer toolchain com suporte à edição Rust 2024. As opções que instalam serviço, alteram hosts, NRPT, WFP, CA ou drivers exigem ambiente Windows **descartável** e aprovação operacional.

## Painel web

~~~bash
cd web
npm ci --no-audit --no-fund
npm run lint
npm run typecheck
npm run test:coverage
npm run build
npm run dev:mock
~~~

O modo `dev:mock` usa MSW e não prova que o backend realiza as operações simuladas.

## Contratos e integração

~~~bash
python -m pytest -q -m "not windows_only"
python tools/gen_policy_vectors.py
python tools/gen_uninstall_vectors.py
~~~

Regenerar vetores **somente** quando houver alteração do contrato e revisar o diff. `OPENEMS_TEST_DSN` e `OPENEMS_TEST_REDIS` habilitam os contratos de integração com instâncias descartáveis. `OPENEMS_REQUIRE_NATIVE_AGENT=1` obriga a existência do binário de release. `OPENEMS_SERVICE_TESTS=1` só em runner/VM Windows descartável.

Consulte [estratégia de testes](../development/testing.md), [CI](../development/ci-cd.md) e [contribuição](../../CONTRIBUTING.md).
