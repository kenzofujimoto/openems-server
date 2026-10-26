# Estratégia de testes e evidências

## Pirâmide de verificação

| Camada | Implementação | Ambiente seguro |
| --- | --- | --- |
| Contratos de política e códigos | `contract/*.json` compartilhados Python/Rust | Sem efeitos no SO |
| API e segurança | Pytest, testes de sessão, SAML e fluxo de dispositivo | Local/CI |
| Persistência | PostgreSQL 16 / Redis 7 descartáveis | CI de integração |
| Agente nativo | `cargo test`, fmt, clippy e build release | Host de build |
| Painel React | Vitest, Testing Library, MSW e browser tests | CI/navegador controlado |
| Serviço, MSI, NRPT/WFP e CA | Harness PowerShell/Windows Sandbox | VM descartável |

~~~bash
python -m pytest -q -m "not windows_only"
cd agent-rs && cargo fmt --check && cargo clippy --locked --all-targets -- -D warnings && cargo test --locked
cd ../web && npm run lint && npm run typecheck && npm run test:coverage && npm run build
~~~

Para PostgreSQL/Redis, configurar `OPENEMS_TEST_DSN` e `OPENEMS_TEST_REDIS` com serviços descartáveis. Para obrigar a execução do agente compilado, `OPENEMS_REQUIRE_NATIVE_AGENT=1` (gerar binário release antes). `OPENEMS_SERVICE_TESTS=1` executa testes reais de serviço e **não deve ser usado no equipamento de desenvolvimento**. Critérios de cobertura segundo `tools/check_quality.py`: 95% em módulos críticos, 90% serviços e 80% demais, conforme classificação no script.

## Evidência

Cada `validation/*.json` tem escopo, ambiente, resultado, checks, lacunas e, em diversos casos, commit/hash. Não transformar evidência de backend simulado em prova de end-to-end com Postgres, ou uma captura de Edge em compatibilidade Chrome/Firefox.

## Gate por mudança

- Novo comportamento => teste que falha antes da implementação.
- Mudança de política => regenerar vetores Python/Rust, conferir hash e ACK.
- Mudança de MSI/Windows => instalação, atualização, falha e remoção em VM.
- Mudança de telemetria => validação de tamanho, retenção, acesso e privacidade.
- Atualizar documentação e estado de capacidades junto com feature.

Veja [CI](ci-cd.md), [matriz de validação](../validation/test-matrix.md), [evidências](../validation/evidence-index.md).
