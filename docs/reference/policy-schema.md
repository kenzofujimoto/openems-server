# Schema de políticas

Contrato: `agent/policy.py`, `agent-rs/src/policy.rs` e `contract/policy-vectors.json`. Perfil publicado em `POST /api/v1/profiles/{vdom}` é um JSON direto.

~~~json
{
  "web_filter": {
    "blocked": ["*.example.test"],
    "allowed": ["portal.example.test"],
    "blocked_categories": ["games"],
    "safe_search": {"engines": ["google", "bing", "youtube"], "youtube": "strict"},
    "timezone": "America/Sao_Paulo",
    "scheduled": [
      {
        "days": ["mon", "tue", "wed", "thu", "fri"],
        "from": "09:00",
        "to": "18:00",
        "blocked": ["social.example.test"],
        "blocked_categories": ["social"]
      }
    ]
  },
  "app_control": {"blocked": ["notepad.exe"]}
}
~~~

Exemplo de estrutura, não política corporativa recomendada. Categorias exigem catálogo local válido e licença verificada.

| Campo | Regra |
| --- | --- |
| `web_filter.blocked` | Domínios exatos e `*.dominio`, até 10.000 entradas; curinga inclui domínio ápice |
| `web_filter.allowed` | Permitidos prevalecem sobre bloqueio direto/categoria |
| `web_filter.blocked_categories` | IDs publicados no catálogo, validados contra taxonomia |
| `web_filter.safe_search` | Motores habilitados e modo YouTube |
| `web_filter.timezone` | Fuso IANA |
| `web_filter.scheduled` | Até 50 janelas; exige timezone, dias `mon..sun`, `from/to` no mesmo dia |
| `app_control.blocked` | Nome exato de imagem executável; **não** hash/editor/path |

Janelas ativas acrescentam bloqueios às regras permanentes, respeitando permitidos. Janela que atravessa meia-noite precisa ser dividida. SafeSearch altera resolução DNS e não deve ser contabilizado como bloqueio de visita. O algoritmo normaliza nomes e gera digest canônico, conferido pelos mesmos vetores em Python e Rust.

**Não estão implementadas:** políticas USB, WDAC por hash/editor, DLP ou regras por localização de rede, apesar dos placeholders no roadmap/painel.

Ver [motor](../architecture/policy-engine.md) e [filtragem](../guides/web-filtering.md).
