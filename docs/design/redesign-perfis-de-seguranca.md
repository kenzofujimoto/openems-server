# Redesign dos perfis de segurança e nova identidade visual

Proposta para aprovação, 02/11/2026. Ainda não há código alterado: as imagens "novo-*" são mockups estáticos.

Objetivo: deixar as telas de **Filtro web** e **Controle de aplicativos** com os padrões de operação do FortiGate e do FortiClient EMS (categorias agrupadas, ação em lote, overrides priorizados, aplicar/cancelar) e trocar a identidade RSM por uma identidade própria do OpenEMS.

## 1. Como o painel está hoje

**Arquitetura.** `web/` é React 19 + TanStack Router/Query + Tailwind 4 + Radix + zod, com mocks MSW (`npm run dev:mock`). O FastAPI serve o painel em `/panel/`. Cada grupo (`vdom`) tem **um perfil** com as seções `web_filter`, `app_control`, `app_catalog` e `usb_control`. `PolicyWorkspace` escolhe o grupo e `PolicyForm` publica o corpo inteiro com `digest` (concorrência otimista, 409/412). Essa base fica como está: a proposta muda só a apresentação.

**Acoplamento com a RSM.**

| Onde | O quê |
|---|---|
| `web/src/styles.css` | tokens `--color-rsm-*` e fonte Prelo/Noto Sans; usados em cerca de 12 componentes (`bg-rsm-blue`, `text-rsm-green`…) |
| `Sidebar.tsx`, `LoginPage.tsx`, `index.html` | `brand/rsm-logo.png`, favicon e título "RSM Endpoint Management" |
| `mocks/data.ts`, testes | endpoints `RSM-SP-001`… (só dados de exemplo) |

**Problemas de uso encontrados.**

| Tela | Problema |
|---|---|
| Todas as políticas | O seletor de grupo é um card repetido em cada página. A página é uma coluna longa de cards, com o botão Publicar no fim e sem indicação de alterações pendentes. |
| Filtro web | Cada categoria é um card com três botões (27 categorias = 81 botões). Não há ação em lote, busca, recolher por grupo nem total por ação. Os horários repetem todas as categorias dentro de cada janela. |
| Aplicativos | As decisões por aplicativo (`app:<id>`) **só aparecem quando você busca o app**: não há lista das exceções vigentes. Regras de execução, lista de rede e lista de encerramento são textareas e formulários soltos. O inventário fica no meio da página. |

| Atual · Filtro web | Atual · Aplicativos |
|---|---|
| ![Filtro web atual](img/atual-filtro-web.png) | ![Aplicativos atual](img/atual-aplicativos.png) |

## 2. Referências

O acesso a `docs.fortinet.com` estava bloqueado na rede desta sessão. Por isso as imagens abaixo são **esquemas recriados a partir da documentação pública**, e não capturas de tela. Elas não usam marcas nem ícones originais e servem só para comparar padrões. Documentação oficial:

- FortiGate, filtro web por categoria FortiGuard: <https://docs.fortinet.com/document/fortigate/7.4.1/administration-guide/675558>
- FortiGate, filtros de categoria e overrides do Application Control: <https://docs.fortinet.com/document/fortigate/6.2.0/cookbook/19814>
- FortiClient EMS, perfil de Web Filter: <https://docs.fortinet.com/document/forticlient/7.0.1/ems-administration-guide/68075>

![FortiGate Web Filter (esquema)](img/ref-fortigate-webfilter.png)
![FortiGate Application Control (esquema)](img/ref-fortigate-appctrl.png)
![FortiClient EMS Web Filter (esquema)](img/ref-ems-webfilter.png)

O que vale copiar: (1) perfil como objeto editável, com cabeçalho e versão; (2) categorias numa tabela densa, agrupada e recolhível, com contagem; (3) toolbar de ação que vale para várias linhas selecionadas; (4) seletor de ação no cabeçalho do grupo e opção "todas as categorias"; (5) lista de exceções (URL estático / overrides) avaliada **antes** das categorias; (6) confirmar/cancelar explícito.

O que **não** copiar: cores, ícones, nomes de produto e o layout pixel a pixel da Fortinet. O README do projeto já evita a marca Fortinet, e a proposta segue essa regra: copia padrões de interação, com identidade própria.

## 3. Proposta

### Shell

- Barra superior escura com logo, breadcrumb, busca global (Ctrl K), **seletor de grupo global** (substitui o card repetido) e o usuário.
- Navegação lateral escura: Monitoramento / Perfis de segurança / Administração.
- Barra fixa de publicação: "N alterações não publicadas", Ver diferenças, Descartar e Publicar vN.
- Cada perfil é dividido em abas, sem a coluna longa de cards.

### Filtro web

![Novo filtro web](img/novo-filtro-web.png)

- Abas: **Categorias** · Filtro de URL estático (atual `DomainRulesTable`) · SafeSearch · Horários · Opções.
- Tabela agrupada, com checkbox no grupo (inclusive estado misto), toolbar Permitir / Monitorar / Bloquear para a seleção, busca e "Expandir tudo".
- Cada linha mostra a ação (pill com menu), os domínios na base, os bloqueios em 7 dias (de `/api/v1/stats` ou dos eventos) e quantas regras de URL tocam a categoria.
- O cabeçalho do grupo mostra a distribuição das ações.
- "Não classificado" aparece fixo em Permitir (é o comportamento atual). "Avisar" fica desabilitado até existir suporte no agente.
- Painel lateral com o resumo por ação, `monitor_all`, a saúde da base de categorias e os agentes sem a capability.

### Controle de aplicativos

![Novo controle de aplicativos](img/novo-aplicativos.png)

- Abas: **Categorias e overrides** · Regras de execução (WDAC) · Rede e encerramento · Inventário · Opções.
- Grade com as 14 categorias do catálogo. Cada uma tem ícone, total de apps, máquinas onde foi vista e um menu de ação (Sem regra / Permitir / Bloquear / Bloquear rede). "Todas as categorias" aplica a ação em lote.
- **Overrides de aplicativos e filtros**: uma tabela única com todas as decisões `app:<id>` e as `execution_rules` manuais, com tipo, ação, máquinas afetadas e comentário. Isso resolve a falta de lista das exceções vigentes.

![Novo override](img/novo-override.png)

- O diálogo "Novo override" tem tipo (Aplicativo / Filtro / Hash-editor-caminho), ação, busca no catálogo com seleção múltipla e o filtro "só vistos no parque". Apps da Microsoft aparecem como não bloqueáveis. Há um comentário que vai para a auditoria e um aviso do impacto antes de confirmar.

### Mapeamento para o modelo atual

| Elemento da UI | Contrato | Muda o backend? |
|---|---|---|
| Ação em lote, grupos, busca, resumo | `web_filter.category_actions` | Não |
| Bloqueios 7 dias por categoria | eventos `web_block` agregados | Talvez uma rota agregada |
| Categoria de app / "Todas" | `app_catalog.actions["category:<id>"]` | Não |
| Override por app (um ou vários) | `app_catalog.actions["app:<id>"]`, que já vence a categoria em `app/app_catalog.py` | Não |
| Override por hash/editor/caminho | `app_control.execution_rules` | Não |
| Ordem ↑↓ dos overrides | hoje não há conflito entre `app:*`; só faz sentido com filtros | Fase 2 |
| Override por **filtro** (editor, categoria + popularidade…) | — | Fase 2: novo campo no `app_catalog` |
| Comentário do override | — | Fase 2: metadado opcional |
| Avisar / Autenticar no filtro web | — | Exige agente e página de bloqueio |

## 4. Nova identidade visual

![Identidade](img/identidade.png)

- **Marca:** hexágono (perímetro) com três nós (endpoints). O nó em ciano é o agente que confirma a política. Funciona a partir de 16 px e substitui `rsm-logo.png`.
- **Cores:** Noite `#0B1220` (shell), Índigo `#4F46E5` (ação primária e seleção), Sinal `#22D3EE` (acento). As cores de ação são semânticas e fixas: Permitir verde, Monitorar azul, Bloquear vermelho, Bloquear rede laranja, Avisar âmbar, Sem regra cinza. A cor da marca nunca representa uma ação.
- **Tipografia:** IBM Plex Sans + IBM Plex Mono (OFL, via `@fontsource`), no lugar de Prelo/Noto.
- **Tokens:** renomear `--color-rsm-*` para tokens semânticos (`--color-brand`, `--color-action-allow`…), com o tema escuro redefinido nos mesmos nomes.
- **Nome:** "OpenEMS" é também o nome de um projeto open source conhecido de gestão de energia (openems.io). Recomendo checar marca e domínio antes de fixar o logotipo. A identidade funciona com outro nome sem mudar o símbolo.

## 5. Plano de implementação

1. **Identidade (1 PR):** tokens semânticos em `styles.css`, troca de `rsm-*` nos componentes, logo SVG, favicon, título, fontes Plex. Os testes não dependem de cor; só os mocks `RSM-*` podem ser renomeados.
2. **Shell:** barra superior, navegação escura, seletor de grupo global (reaproveita `GroupPicker`/`storedGroup`), barra fixa de publicação com estado de alteração (`PolicyForm` passa a expor `dirty` e diff).
3. **Filtro web:** componente `CategoryTable` (grupos, seleção, toolbar) no lugar do grid de `WebActionSelector`, e as abas. A lógica de `build()` fica igual.
4. **Aplicativos:** `AppCategoryGrid`, `OverridesTable` (lista `app:*` + `execution_rules`) e `OverrideDialog`. As textareas e o inventário vão para abas próprias.
5. **Fase 2 (backend):** overrides por filtro e comentários, agregação de bloqueios por categoria e ação Avisar.

Cada etapa mantém o contrato de política, e os testes atuais de `web/src/features/**` continuam valendo. As interações novas (seleção em lote, estado misto, diálogo de override) ganham testes próprios.
