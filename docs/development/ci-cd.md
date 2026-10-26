# CI e gates de qualidade

Workflow: `.github/workflows/ci.yml`. Executa em push para `main`, qualquer PR e via `workflow_dispatch`. Um PR draft pode disparar execução normal de CI.

| Job | Ambiente | Validação |
| --- | --- | --- |
| `panel` | Node 24 | Lint, TypeScript, Vitest coverage, build |
| `integration` | Python 3.14, PostgreSQL 16, Redis 7 | Lint, contratos, browser, build Rust Linux e Python |
| `windows-service` | Windows | Testes Python e mocks de serviço com cobertura |
| `native-agent` | Windows + WiX 5.0.2 | Rust fmt/clippy/test, build MSI, contratos e instalação |
| `coverage` | Linux | Combinação Linux/Windows, limiares, skips |

`tools/check_quality.py` rejeita skips exigidos e cobertura abaixo do gate. Artefatos de CI incluem resultados JUnit/cobertura e MSI, mas **MSI de CI não é release assinado ou homologado**.

### Qualidade documental

Um verificador de caminhos Markdown foi incluído em `tools/check_docs_links.py`. Executar a partir de qualquer diretório:

~~~bash
python tools/check_docs_links.py
~~~

Ele confere links relativos internos de `README.md`, guias, arquivos de comunidade e documentação. Links externos, âncoras e semântica Mermaid devem ser verificados separadamente. Recomenda-se acrescentar ao CI um job de Markdown link-check e Mermaid render, sem alterar a lógica do produto.

Antes de merge: ler diff, revisar precisão contra código, confirmar testes de produto relevantes e autorização de marca/licença.
