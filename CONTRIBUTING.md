# Contribuir com o OpenEMS

Consulte o [índice de documentação](docs/README.md) para localizar o componente e a [matriz de aceite](ACCEPTANCE.md) para conferir o escopo dos testes. Para reportar vulnerabilidades em privado, siga a [política de segurança](SECURITY.md).

## Propor uma mudança

1. Descreva o problema, o comportamento esperado e o ambiente em que ele ocorre.
2. Abra um PR em rascunho com escopo pequeno. Para mudanças de comportamento, inclua primeiro um teste de regressão que falhe.
3. Registre os testes executados, as limitações e eventuais efeitos sobre políticas existentes, atualização ou remoção do agente.
4. Use dados fictícios em capturas e relatórios. Mantenha credenciais, arquivos `.env`, chaves privadas e tokens fora do Git.

## Verificações locais

O CI usa Python 3.14 e Node.js 24. Em um ambiente virtual Python, instale as dependências de desenvolvimento e execute os testes rápidos do serviço e de atribuição de políticas:

```bash
python -m pip install -r requirements-dev.txt
python -m ruff check app agent tools tests
python -m pytest -q tests/test_service.py tests/test_rules.py
```

Para alterações no painel, execute a partir da raiz do repositório:

```bash
npm ci --prefix web
npm run lint --prefix web
npm run typecheck --prefix web
npm run test:coverage --prefix web
npm run build --prefix web
```

Os [workflows do CI](.github/workflows/ci.yml) detalham os testes de integração com PostgreSQL e Redis e os checks do agente Rust. Execute os cenários reais de serviço, MSI e aplicação de controles apenas em uma [VM descartável](docs/vm-acceptance-guide.md).
