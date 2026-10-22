# Handoff — roadmap v2

## Continuação Codex — F2 HTTPS local

Branch local: `feature/https-blockpage`. Contrato aprovado em `https-blockpage.md`.

### Continuação — aceite em Sandbox

- `deploy/test-trust-sandbox.ps1` prepara tarefa SYSTEM somente dentro de Windows Sandbox. Recusa o host de desenvolvimento antes de qualquer escrita; testa configuração sem CA implícita, instalação explícita, ACL/owner SYSTEM, identidade estável, remoção exata e limpeza repetida.
- Testes de segurança do roteiro em `tests/test_sandbox_validation.py`: ausência de efeitos no host e sintaxe PowerShell. Falhas foram verificadas e commitadas antes da implementação.
- Pacote local ignorado em `.venv/sandbox-acceptance/`: `trust-acceptance.wsb`, binário e roteiro em `input/`, saída em `results/`. Rede e clipboard desabilitados; entrada somente leitura; apenas resultados compartilhados para escrita. Nenhum segredo/configuração real foi incluído.
- Sandbox iniciado; usuário confirmou que abriu. **Não considerar instalação/remoção real da CA validada** até `result.json` aprovado da tentativa atual. Diagnóstico em `results/bootstrap.log`. O roteiro atual usa diretório local único por tentativa e permite repetir no mesmo Sandbox sem reaproveitar resultados.
- O teste da CA não substitui os aceites HTTPS nos navegadores, recuperação do serviço ou MSI. O serviço e a confiança do host continuam inalterados.
- Verificação final desta continuação: **446 testes Python aprovados, 39 opcionais ignorados e 5 de instalação real deselecionados**, com binário release explicitamente selecionado. Inclui 3 contratos do roteiro (recusa do host e parser). `git diff --check` aprovado. Revisão independente do roteiro concluída; as correções para resultado obsoleto/parcial e a conferência de ACL/segunda remoção foram incorporadas. Resultado real do Sandbox continua pendente.
- Diagnóstico real posterior: `WDAGUtilityAccount` existe e `CExecSvc` está Running, mas `C:\ProgramData\Microsoft\Windows\Containers` não existe no Sandbox do usuário. A primeira versão do roteiro recusou esse ambiente antes de qualquer teste da CA. Corrigido para exigir perfil + serviço de execução ativo; `-ProbeEnvironment` apenas informa a detecção, sem criar arquivos/tarefas/certificados. Quatro casos de regressão foram escritos e verificados vermelhos antes da correção. Launcher compartilhado restaurado para execução do teste real; aguarda nova tentativa do usuário.
- Após essa correção: **450 testes aprovados, 39 ignorados e 5 deselecionados**. Revisão independente não encontrou regressão bloqueadora. Sem resultado real de confiança até este checkpoint.
- Primeiro teste real como SYSTEM confirmou configuração sem CA implícita, mas instalação falhou. ACL fornecida pelo usuário mostrou `AU` com Modify (`0x1301bf`) herdado na pasta customizada; `Authority::prepare_directory` corretamente recusa esse pai. O roteiro agora aplica explicitamente owner Administradores e DACL protegida, com FullControl somente para SYSTEM/Administradores, antes de iniciar a tarefa. Cada tentativa usa `C:\openems-acceptance-<guid>`. `-Plan` descreve essa configuração sem efeitos, com teste de regressão que verifica ACL, isolamento das tentativas e ausência de escrita no host. O agente não teve suas proteções relaxadas. Oito testes do roteiro aprovados; nova tentativa real pendente.
- Suíte após correção da ACL: **451 aprovados, 39 ignorados e 5 deselecionados**; revisão independente da correção aprovada. Script atualizado copiado para a pasta de entrada compartilhada do Sandbox. O relatório existente ainda é a tentativa anterior com falha; não reutilizar esse resultado como evidência da nova versão.

- Implementados listener HTTPS em loopback, autorização por SNI e Host, revogação pela política vigente e limites de conexões/leitura. Não há proxy de sites permitidos.
- CA por máquina com DPAPI, diretório/chave restritos ao SYSTEM, validação da persistência e certificados de servidor por domínio com validade de até 24 horas.
- Configuração nativa: `block_page_https`, `block_page_https_port` (443) e `authority_path` (subdiretório privado `https/authority.json`). HTTPS requer `block_page` e execução contínua; `run-once` recusa essa combinação.
- Comandos explícitos: `install-block-page-trust --config <agent.json>` e `remove-block-page-trust --config <agent.json>`. No Windows, operações que acessam a CA exigem SYSTEM. Serviço não instala confiança automaticamente. Remoção sem autoridade é idempotente.
- Desinstalação nativa e MSI removem o certificado exato pertencente à instalação; falha da limpeza impede que seja anunciada como concluída. Upgrade não executa essa remoção.
- Nenhuma CA foi instalada e o serviço/executável instalado nesta máquina não foi substituído. O build local não atualiza o MSI publicado.
- Testes usam CA efêmera, cliente TLS com raiz própria, portas efêmeras e store de confiança simulado. Validação real de instalação/remoção da CA e do MSI, e aceite em Chrome/Edge/Firefox, continuam pendentes de Windows descartável. Não executar aqui os testes `OPENEMS_SERVICE_TESTS=1`.
- Sem push, PR, publicação de MSI ou execução de CI nesta continuação; commits locais incluem `[skip ci]`.
- Validação final local: **39 testes Rust**, `cargo fmt --check`, Clippy sem avisos e build de release aprovados; **482 testes Python aprovados**, com 5 testes Windows de instalação real deselecionados por marcador. Os 18 contratos/comandos/vetores nativos passaram usando o novo executável de release. O MSI modificado teve contrato XML verificado, mas não foi compilado nem instalado nesta continuação.

O restante da F2 (DNS local, curingas, categorias, horários, SafeSearch e políticas de navegador) permanece pendente.

Estado em 2026-10-22. O plano completo de cada fase, com critérios de aceite, está em `roadmap-v2.md`.

## Andamento por fase

| Fase | Estado | O que falta |
|---|---|---|
| F1 — Agente nativo (Windows) | Quase pronta. Agente Rust em `agent-rs/` com paridade do agente Python (testes de contrato em `tests/test_native_agent.py`), serviço com recuperação, MSI (WiX 5) testado em runner Windows real. | Componente da sessão do usuário (tarefa no logon, notificações). Assinatura de código (depende de certificado da RSM). MSI sem propriedade para ligar a página de bloqueio (hoje: `openems-agent.exe configure --block-page`). |
| F2 — Filtro web completo | Parcial na branch `feature/https-blockpage`: núcleo HTTPS local implementado; ver continuação acima. | Validar confiança/remoção em Windows descartável e navegadores; DNS local, curingas, categorias, horários, SafeSearch e políticas de navegador. |
| F3 — Controle de aplicativos | Não iniciada. Hoje só encerra o processo pelo nome. | Tudo. |
| F4 — USB | Não iniciada. | Tudo. |
| F5 — Antiadulteração | Parcial: serviço automático no boot com reinício após falha. | ACL do serviço, watchdog, código de desinstalação, componente no logon. |
| F6 — Dentro/fora da empresa | Não iniciada. | Tudo. |
| F7 — Painel novo | Parcial. React em `web/`, servido em `/panel/` (a raiz já redireciona). Visão geral, endpoints com detalhe e login prontos. | Editores de política, regras, convites e auditoria (hoje ainda pelo console antigo em `/console/`). Rotas de servidor `/api/v1/stats/overview` e `/api/v1/events` (o painel usa mocks até elas existirem; contrato em `web/src/mocks/data.ts`). Remover o console antigo ao final. |
| F8 — macOS e Linux | Não iniciada (o agente Rust já compila e passa nos testes de contrato no Linux, no CI). | Serviço, empacotamento e recursos de cada sistema. Mac exige teste manual e Apple Developer ID. |
| F9 — Android e iOS | Não iniciada; precisa de especificação própria. | — |

## Combinados de trabalho

- **CI só no fim.** O usuário pediu um único PR com CI ao final de todas as fases, para economizar minutos. O CI roda apenas em push na `main`, em PR e por disparo manual. Commits enviados direto para a `main` levam `[skip ci]` na mensagem.
- **TDD** (ver `CLAUDE.md` do usuário): testes que falham primeiro, commit `test(scope): ...`, depois implementação.
- **Paridade de política:** qualquer mudança em `agent/policy.py` exige regenerar `contract/policy-vectors.json` com `python tools/gen_policy_vectors.py`; o Rust (`agent-rs/tests/policy_vectors.rs`) e o Python (`tests/test_policy_vectors.py`) leem os mesmos vetores.
- **Testes que instalam serviço ou MSI** só rodam em runner descartável do CI (`OPENEMS_SERVICE_TESTS=1`), nunca na máquina de desenvolvimento.

## Como verificar localmente

```bash
python -m pytest -q -m "not windows_only"
```
```bash
cd agent-rs && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test && cargo build --release
```
```bash
cd web && npm run lint && npm run typecheck && npm run test:coverage && npm run build
```

Os testes de contrato do agente nativo usam o binário em `agent-rs/target/` (defina `OPENEMS_REQUIRE_NATIVE_AGENT=1` para falhar em vez de pular). Os contratos PostgreSQL e Redis precisam de `OPENEMS_TEST_DSN` e `OPENEMS_TEST_REDIS`.

## Ambiente de teste do usuário (esta máquina)

- Servidor real via `docker compose up -d --build`, com `.env` gerado por `deploy/new-env.ps1` (segredos só no `.env`, que não vai para o git).
- Agente instalado pelo MSI e depois substituído pelo build de `agent-rs/target/release` (a versão do MSI não tinha as correções de log e recadastro). Página de bloqueio ligada.
- Validado pelo usuário: cadastro, política aplicada e confirmada, bloqueio de site, encerramento do Bloco de Notas, página de bloqueio em HTTP.
- Ainda não testado pelo usuário: resiliência (servidor parado, processo morto, reinício da máquina) e desinstalação.
