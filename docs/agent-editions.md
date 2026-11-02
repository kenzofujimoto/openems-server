# Edições do agente: OpenEMS e RSM Brasil

O agente tem as mesmas duas identidades do painel (`web/src/lib/brand.ts`, seção "Edição RSM mantida em paralelo" de `docs/design/redesign-perfis-de-seguranca.md`). **OpenEMS é o padrão**; a edição RSM Brasil é uma opção explícita de build. A edição muda só o que o usuário vê. Política, eventos, contrato com o servidor, nomes de serviço, caminhos e `UpgradeCode` do MSI são os mesmos nas duas.

## Como gerar cada edição

| Peça | OpenEMS (padrão) | RSM Brasil |
|---|---|---|
| Agente nativo e componente de sessão | `cargo build --release` | `cargo build --release --features rsm` |
| MSI | `wix build installer/openems-agent.wxs ... ` | `wix build installer/openems-agent.wxs ... -d Edition=rsm` |
| Fixtures/pacotes do Sandbox | `tools/build-msi-fixtures.ps1 -Production ...` | `tools/build-msi-fixtures.ps1 -Production -Edition rsm ...` |
| Agente Python de referência | sem variável | `OPENEMS_AGENT_EDITION=rsm` no ambiente |
| Serviço do agente Python | `install_service.ps1 ...` | `install_service.ps1 -Edition rsm ...` |
| Painel (referência) | `npm run build` | `npm run build:rsm` / `docker build --build-arg PANEL_BRAND=rsm .` |

Exemplo completo da edição RSM, a partir de `agent-rs/`:

```bash
cargo build --release --locked --features rsm
```

```bash
wix build installer/openems-agent.wxs -arch x64 -d Version=0.1.0 -d Edition=rsm -d AgentExe=target/release/openems-agent.exe -d SessionExe=target/release/openems-session.exe -o openems-agent-rsm.msi
```

Os dois binários informam a edição em `--version` (`openems-agent 0.1.0 (rsm)`). `build-msi-fixtures.ps1` confere isso e recusa empacotar binários de uma edição com o MSI da outra. O `-d Edition=rsm` do WiX não muda os binários: compile-os com `--features rsm`.

O `UpgradeCode` é o mesmo, então instalar uma edição sobre a outra é uma atualização normal. Quem já usa o MSI RSM em produção deve passar a gerar com `--features rsm` e `-d Edition=rsm`; sem isso, a próxima versão instalada passa a mostrar a identidade OpenEMS.

## O que muda

| Item | OpenEMS | RSM Brasil (texto mantido byte a byte) |
|---|---|---|
| Título da bandeja e prefixo da dica | `OpenEMS Endpoint` | `RSM Endpoint` |
| Dicas da bandeja | `OpenEMS Endpoint: proteção ativa`, etc. | `RSM Endpoint: proteção ativa`, `RSM Endpoint: aguardando a política da empresa`, `RSM Endpoint: proteção ativa, sem contato com o servidor[ desde dd/mm hh:mm]` |
| Página de bloqueio (HTTP e HTTPS) | `agent-rs/src/blockpage-openems.html`: marca OpenEMS em SVG, índigo, IBM Plex Sans | `agent-rs/src/blockpage-rsm.html`: logo RSM, azul/verde RSM, Prelo/Noto Sans, rodapé "RSM Brasil · O poder de ser compreendido" |
| Descrição do serviço Windows (agente e MSI) | `Applies OpenEMS endpoint policies and reports their status to the management server.` | `Applies RSM endpoint policies and reports their status to the management server.` |
| `Manufacturer` do MSI | `OpenEMS` | `RSM Brasil` |

Os textos ficam em `agent-rs/src/brand.rs` (nativo) e `agent/brand.py` + `agent/blockpage.py` (Python). A página do agente Python é a mesma do nativo para cada edição, sem a linha de categoria, que só o agente nativo preenche. O agente Python não tem bandeja; a descrição do serviço Python não cita marca e não muda.

## Testes

- Rust: `cargo test` e `cargo test --features rsm` testam as duas edições (`render_for`/`tooltip_for` recebem a edição) e conferem que o binário usa a edição do build.
- Python: `agent/test_agent.py` cobre as duas páginas e a variável de ambiente; `tests/test_agent_editions.py` compara a página Python com o modelo nativo de cada edição, o texto RSM, os metadados do MSI e os instaladores.
- Binários: `tests/test_native_session.py` lê a edição em `--version` e confere as dicas da bandeja. Com `OPENEMS_EXPECT_EDITION=openems|rsm`, falha se o binário encontrado for da outra edição. A CI roda o contrato com as duas edições no Windows e publica `openems-agent-rsm.msi` como artefato separado.
