# F2 — SafeSearch forçado e horários (recorte 2)

Proposta para aprovação. Nada será implementado antes do aceite deste documento. Este recorte parte do resolvedor do recorte 1 (`dns-resolver.md`), já aceito em Sandbox.

## Objetivo

1. **SafeSearch forçado:** Google, Bing, YouTube e DuckDuckGo passam a responder sempre com a versão filtrada, sem que o usuário consiga desligar.
2. **Horários:** regras de bloqueio que valem só em janelas de dia e hora. Exemplo: bloquear redes sociais de segunda a sexta, das 8h às 18h.

## Decisões que precisam de aprovação

| Decisão | Recomendação | Alternativa |
|---|---|---|
| Como forçar o SafeSearch | Pelo DNS, como recomendam os próprios buscadores: o nome do buscador responde com um CNAME para o endereço "seguro" de cada um (`forcesafesearch.google.com`, `strict.bing.com`, `restrict.youtube.com`, `safe.duckduckgo.com`), seguido dos endereços desse destino, consultados no upstream. Funciona em qualquer navegador e não exige interceptar HTTPS | Políticas de navegador (Chrome/Edge/Firefox). Ficam para o recorte 3, como reforço |
| Modo `hosts` | SafeSearch só no modo DNS. No modo `hosts` a opção é ignorada, e o agente não informa a capacidade correspondente | Gravar no `hosts` o IP atual do endereço seguro. Funciona, mas quebra quando o buscador troca os endereços |
| Fuso dos horários | A política define o fuso (nome IANA, por exemplo `America/Sao_Paulo`), e o agente calcula a partir do relógio UTC do sistema. Por padrão, um usuário comum consegue trocar o fuso do Windows, mas não a hora; assim, trocar o fuso não burla o horário. Exige embutir a base de fusos no agente (algumas centenas de KB) | Usar o fuso local do Windows: mais simples, mas o usuário burla a regra trocando o fuso |
| Formato dos horários | Grupos separados: `web_filter.scheduled` é uma lista de `{blocked, days, from, to}`. As entradas de `blocked` e `allowed` continuam sendo texto simples | Cada entrada vira um objeto com horário próprio. Agentes antigos recusariam a política inteira |
| Nível do YouTube | `strict` por padrão, com `moderate` como opção | Só `strict` |

## Política

```json
{
  "web_filter": {
    "blocked": ["*.tiktok.com"],
    "allowed": ["www.iana.org"],
    "safe_search": {"engines": ["google", "bing", "youtube", "duckduckgo"], "youtube": "strict"},
    "timezone": "America/Sao_Paulo",
    "scheduled": [
      {"blocked": ["*.facebook.com", "*.instagram.com"], "days": ["mon", "tue", "wed", "thu", "fri"], "from": "08:00", "to": "18:00"}
    ]
  }
}
```

- `safe_search.engines` aceita só os quatro buscadores. Uma lista vazia ou a falta do campo deixa o SafeSearch desligado. `youtube` aceita `strict` ou `moderate`.
- Cada janela usa `days` (`mon`…`sun`, sem repetições, pelo menos um dia) e `from`/`to` no formato `HH:MM`, com `from` antes de `to`. Uma janela que passa da meia-noite é escrita como duas janelas. No máximo 50 janelas; as listas seguem o limite atual de 10.000 entradas.
- `timezone` é obrigatório quando houver `scheduled` e precisa ser um nome IANA conhecido.
- **Precedência:** `allowed` vence tudo, inclusive um bloqueio por horário. Fora da janela, a regra com horário não bloqueia. O SafeSearch vale mesmo para buscadores em `allowed`, porque "permitido" significa "não bloqueado", e não "sem SafeSearch".
- O Python (`agent/policy.py`) continua sendo a referência. Os vetores compartilhados ganham validação e decisões com horário fixo (por exemplo, "segunda 07:59 → libera", "segunda 08:00 → bloqueia", "domingo → libera"), e o Rust precisa reproduzir os mesmos resultados.
- **Compatibilidade:** agentes antigos aceitam a política, mas ignoram `safe_search` e `scheduled` em silêncio. O agente novo passa a informar a tag `web-filter:v2`, e o painel deve avisar antes de publicar essas opções para grupos com agentes sem ela.

## Resolvedor

- **SafeSearch:** para `A`/`AAAA` de um nome de buscador, a resposta traz o CNAME para o endereço seguro mais os registros desse destino, consultados no upstream com os mesmos limites de hoje.
  - Se o upstream falhar, a resposta é SERVFAIL. Nunca devolve o endereço normal do buscador.
  - Para os outros tipos, incluindo `HTTPS`/`SVCB`, responde sem dados, como já acontece com nomes bloqueados.
- **Nomes cobertos:**
  - Google: os domínios de busca publicados pelo próprio Google, com e sem `www.`. A lista será confirmada na implementação e embutida no agente.
  - YouTube: `www.youtube.com`, `m.youtube.com`, `youtubei.googleapis.com`, `youtube.googleapis.com` e `www.youtube-nocookie.com`.
  - Bing: `www.bing.com`.
  - DuckDuckGo: `duckduckgo.com` e `www.duckduckgo.com`.
- **Horários:** a decisão é tomada na hora de cada consulta, com o TTL de 30 s que já existe. No início e no fim de uma janela, o agente limpa o cache de DNS do Windows. A página HTTPS usa a mesma decisão. No modo `hosts`, o bloco é reescrito no ciclo seguinte à virada da janela (até 15 s).
- **Página de bloqueio:** os endereços seguros dos buscadores nunca recebem certificado local, porque são servidores reais.

## Testes

1. **Testes que falham primeiro:**
   - validação Python e vetores: fuso inválido, janela invertida, dia repetido, buscador desconhecido, decisões em horários fixos e nos limites das janelas;
   - paridade no Rust;
   - respostas DNS com CNAME e endereços do destino, usando um upstream falso;
   - SERVFAIL quando o upstream falha;
   - NODATA para os outros tipos de registro;
   - virada de janela com relógio injetado, sem esperar horário real.
2. **Sandbox:**
   - Resolver `www.google.com` e `www.youtube.com` pelo caminho do sistema e conferir o CNAME para o endereço seguro.
   - Abrir no Edge uma busca do Google e conferir que o SafeSearch aparece travado. Precisa da sua confirmação.
   - Publicar uma janela que inclui o horário atual e outra que não inclui, e conferir bloqueio e liberação sem reiniciar o serviço.
3. Nenhuma alteração de DNS nesta máquina.

## Riscos

- Os buscadores podem mudar os endereços seguros ou a lista de domínios; nesse caso a lista embutida precisa ser atualizada numa nova versão do agente. Se o destino não resolver, a resposta é SERVFAIL, nunca a busca sem filtro.
- DoH configurado no navegador e buscadores fora da lista continuam contornando o SafeSearch até o recorte 3.
- A base de fusos embutida fica desatualizada se um país mudar as regras de horário de verão; o Brasil não usa horário de verão desde 2019.
- Um administrador local ainda pode mudar o relógio do sistema.

Commits locais com `[skip ci]`, sem PR e sem CI, conforme o handoff.
