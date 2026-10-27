# F2 — categorias e registro de bloqueios (recorte 4)

> Documento histórico de planejamento. Categorias e registro de bloqueios foram implementados posteriormente. Estado atual, matriz FortiGuard e limites: [manual do filtro web](docs/web-filter-compatibility.md). Permitir/Bloquear/Monitorar é uma [proposta separada ainda não implementada](docs/web-filter-actions-plan.md). Aceites vigentes em [HANDOFF](HANDOFF.md) e [ACCEPTANCE](ACCEPTANCE.md).

Proposta para aprovação. Nada será implementado antes do aceite deste documento. Parte do resolvedor DNS (recortes 1 a 3), já aceito em Sandbox.

## Objetivo

1. **Bloquear por categoria:** o administrador marca, por exemplo, "Jogos", e todos os domínios conhecidos dessa categoria passam a ser bloqueados, sem cadastrar um por um.
2. **Registro de bloqueios:** o painel mostra o que foi bloqueado, em qual máquina e por qual regra ou categoria. O formato é o que o painel já espera (`web/src/mocks/data.ts`: eventos `web_block` e os domínios mais bloqueados na visão geral).

## O que categoria cobre, e o que não cobre

- A categoria classifica **domínios**. "Jogos" bloqueia `store.steampowered.com`, `steamcommunity.com` e os demais domínios da lista.
- O efeito no **aplicativo** Steam é indireto: o `steam.exe` abre, mas não consegue falar com os servidores dele (login, loja e downloads falham), desde que os domínios que ele usa estejam na lista. Domínios de CDN compartilhados com outros sites (Akamai, Cloudflare) normalmente não estão nas listas e continuam liberados.
- **Impedir o programa de abrir é a F3** (controle de aplicativos): hoje o agente só encerra o processo pelo nome (`app_control.blocked: ["steam.exe"]`). Bloqueio antes da execução, por editor e hash, e "categorias de aplicativos" ficam para a F3.

## Decisões que precisam de aprovação

| Decisão | Recomendação | Alternativa |
|---|---|---|
| Fonte das categorias | Listas da Universidade de Toulouse (UT1, licença CC BY-SA 4.0, com atribuição no painel), baixadas pelo servidor uma vez por dia. As categorias da UT1 são agrupadas numa taxonomia no estilo FortiGuard (Conteúdo adulto, Jogos de azar, Jogos, Redes sociais, Streaming, Segurança: malware e phishing etc.). A FortiGuard em si não pode ser usada: é base paga e exclusiva da Fortinet | Lista mantida à mão pela RSM. Total controle, cobertura muito menor |
| Como o agente recebe as categorias | O servidor publica, por categoria, um arquivo versionado e assinado com digest SHA-256, contendo **hashes de 64 bits dos domínios**, ordenados. O agente baixa só as categorias usadas pela política dele, guarda em disco (funciona offline) e consulta por busca binária. Exemplo de tamanho: a categoria adulta, com cerca de 4 milhões de domínios, ocupa uns 32 MB em memória e em disco; as outras ficam abaixo de 1 MB | Consulta ao servidor a cada domínio novo: arquivos pequenos, mas o filtro para de funcionar sem servidor e cada site visitado vira uma consulta ao servidor |
| Formato do registro de bloqueios | Agregado por hora: máquina, domínio, motivo (regra, categoria, SafeSearch, DoH) e contagem. É enviado junto com a sincronização, com uma fila local limitada. O servidor guarda **30 dias** por padrão. Sem nome de usuário do Windows | Um evento por acesso bloqueado, com horário exato: mais detalhe, mais volume e mais dado pessoal |
| Privacidade (LGPD) | O registro de navegação bloqueada é dado pessoal do colaborador. Recomendo: retenção configurável com 30 dias por padrão, acesso só para os papéis do painel com permissão de leitura de eventos, visualizações registradas na auditoria e um aviso no painel. A base legal e a comunicação aos colaboradores ficam com a RSM (jurídico/DPO) | Desligar o registro por padrão e deixar a RSM ligar |

## Política

```json
{"web_filter": {"blocked_categories": ["games", "gambling"], "allowed": ["store.steampowered.com"],
                "scheduled": [{"blocked_categories": ["social"], "blocked": [], "days": ["mon"], "from": "08:00", "to": "18:00"}]}}
```

- `blocked_categories` aceita só os identificadores da taxonomia publicada pelo servidor. Também pode aparecer dentro das janelas de horário.
- Um domínio pertence à categoria se ele ou qualquer domínio-pai estiver na lista. A lista `allowed` continua vencendo tudo.
- Os vetores compartilhados ganham categorias simuladas, para o Python e o Rust tomarem as mesmas decisões.
- **Compatibilidade:** agentes antigos ignoram `blocked_categories`. O agente novo informa a tag `web-filter:categories`, e o painel avisa antes de publicar categorias para quem não tem essa tag.

## Agente

- Baixa as categorias usadas, confere o digest e troca de versão de forma atômica. Até a primeira cópia chegar, a categoria não bloqueia nada, e o agente avisa o painel com um erro de aplicação de política.
- A página de bloqueio mostra o nome da categoria.
- O registro de bloqueios conta em memória e manda junto com a sincronização. A fila tem limite (por exemplo, 5.000 linhas), e quando ela estoura o agente envia uma linha "eventos descartados" em vez de crescer sem limite.

## Servidor e painel

- `tools/update_categories.py` baixa a UT1, valida, monta os arquivos de hashes e publica. Na produção roda como tarefa diária; nos testes usa uma lista pequena embutida.
- Novas rotas:
  - `/fct/api/public/v1/categories/{id}/{version}` (agente, autenticado pelo token do dispositivo);
  - `/api/v1/events` e `/api/v1/stats/overview` (painel), no formato já usado pelos mocks.
- O painel ganha a escolha de categorias no editor de política (F7), os eventos e os mais bloqueados com dados reais, e o aviso de agentes antigos.

## Testes

1. **Testes que falham primeiro:**
   - montagem e verificação dos arquivos de hashes;
   - correspondência por domínio-pai;
   - `allowed` vencendo a categoria;
   - categoria dentro de janela de horário;
   - vetores Python e Rust;
   - download com digest errado recusado;
   - fila de eventos com limite e linha de descarte;
   - rotas do servidor com autorização e retenção;
   - painel com Vitest.
2. **Sandbox:** servidor simulado publica uma categoria pequena, por exemplo "games" com `steampowered.com`. Verificar o bloqueio pelo caminho do sistema, `allowed` vencendo, os eventos chegando ao servidor simulado e o funcionamento offline após o primeiro download.
3. O download real da UT1 é testado no servidor, nunca no agente.

## Riscos

- **Bloqueio indevido:** listas abertas erram. Mitigações: `allowed` por exceção e registro de bloqueios para achar os falsos positivos.
- **Cobertura menor que a da FortiGuard**, principalmente para sites brasileiros e muito novos.
- **Memória:** a categoria adulta usa cerca de 32 MB no agente.
- **Licença:** CC BY-SA exige atribuição. Se a RSM redistribuir a lista modificada, o derivado também fica sob CC BY-SA.
- **LGPD:** o registro de bloqueios precisa da validação da RSM antes de ir para produção.

Este recorte é grande. Proposta de entrega em duas partes, cada uma com seu aceite: **4a** categorias, ponta a ponta no agente e no servidor; **4b** registro de bloqueios e telas do painel.

Commits locais com `[skip ci]`, sem PR e sem CI, conforme o handoff.
