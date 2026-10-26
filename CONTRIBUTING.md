# Contribuindo com o OpenEMS

## Antes de começar

Leia [documentação](docs/index.md), [status](docs/status.md), [segurança](SECURITY.md), [licenças](docs/security/licensing.md) e [estratégia de testes](docs/development/testing.md). O projeto é experimental e alguns recursos alteram o sistema operacional.

## Fluxo de mudança

1. Abrir issue/PR com escopo, motivação, riscos, compatibilidade e critério de aceite.
2. Criar branch específica para o recorte. Preservar histórico/contract vectors; testes falhando antes da mudança quando aplicável.
3. Manter mudanças pequenas: lógica, testes, migração/configuração e documentação atualizada no mesmo PR.
4. Executar testes seguros e anexar relatórios; MSI/Windows Service/NRPT/WFP/CA **apenas em VM descartável**.
5. Solicitar revisão de segurança para alteração de autenticação, segredo, SAML, política, watchdog, certificado e desinstalação.
6. Atualizar `docs/status.md`, evidência `validation/` e `CHANGELOG.md` se houver mudança observável.

## Comandos básicos

~~~bash
python -m pytest -q -m "not windows_only"
cd agent-rs && cargo fmt --check && cargo clippy --locked --all-targets -- -D warnings && cargo test --locked
cd ../web && npm run lint && npm run typecheck && npm run test:coverage && npm run build
cd .. && python tools/check_docs_links.py
~~~

Não commitar `.env`, tokens de dispositivos, logs com dados pessoais, segredos da CA, chave de desinstalação ou código/ativos proprietários. Compatibilidade FortiClient requer evidência clean-room autorizada; ver [interoperabilidade](docs/validation/interoperability.md).

Documentos em português técnico; símbolos e nomes de API/código mantidos no idioma original.
