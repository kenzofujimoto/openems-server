# Regras de domínio ordenadas

O filtro web usa uma tabela com inclusão, edição, exclusão e mudança de ordem.
A primeira regra correspondente define a ação, antes de categorias e horários.
Sem correspondência na tabela, as demais configurações continuam sendo avaliadas.
O fluxo segue a tabela de exceções do [FortiClient EMS](https://docs.fortinet.com/document/forticlient/7.4.3/ems-administration-guide/68075/web-filter),
com o escopo de domínios DNS do OpenEMS.

- **Simples:** domínio informado e seu nome com `www`, preservando a regra antiga.
- **Wildcard:** domínio informado e todos os subdomínios. Informe `facebook.com`
  e escolha Wildcard para incluir também `www.facebook.com` e `m.facebook.com`.
- **Permitir:** libera e não registra navegação.
- **Bloquear:** bloqueia e registra a tentativa.
- **Monitorar (log):** libera e registra a consulta DNS.

Por exemplo, com Redes sociais bloqueada, uma regra Wildcard para facebook.com
com Permitir ou Monitorar libera esse domínio e seus subdomínios. Uma regra que
também corresponda e esteja acima dela na tabela tem prioridade. Categorias e
horários não substituem uma correspondência explícita na tabela.

As listas antigas são apresentadas com as permissões antes dos bloqueios para
preservar a precedência anterior. Duplicatas idênticas que antes eram permitidas
continuam permitidas. A migração só é publicada quando o administrador confirma
em **Publicar política**, preservando as demais seções do perfil.

## CSV

```csv
domain,type,action
facebook.com,wildcard,allow
example.org,simple,monitor
example.net,simple,block
```

O exportador usa `simple`/`wildcard` e `allow`/`block`/`monitor`. O importador
também aceita `normal` como Simples e `log` como Monitorar. Aceita UTF-8 com BOM,
vírgula ou ponto e vírgula, CRLF e campos entre aspas. Não aceita URLs, caminhos,
endereços IP, regex, curingas no texto do domínio ou fórmulas de planilha.

A importação mostra uma prévia antes de acrescentar os registros ao rascunho.
Erros indicam a linha; duplicatas do mesmo domínio/tipo, inclusive com ações
diferentes, impedem a importação inteira. Padrões distintos sobrepostos podem
existir: a ordem resolve a correspondência. Importar não publica automaticamente.
Exportar baixa o rascunho atual, mantendo ordem, tipos e ações.

Limites: arquivo de 2 MB e 10.000 regras. A tabela tem busca e páginas de 50
registros. A numeração e os movimentos se referem à ordem global da política,
inclusive durante uma busca.

## Contrato e compatibilidade

`web_filter.domain_rules` é uma lista ordenada de objetos com exatamente
`domain`, `type` e `action`. O servidor normaliza IDNA, rejeita campos extras,
tipos/ações desconhecidos, duplicatas e mistura ambígua com listas antigas não
vazias. A ordem participa do digest da política.

Os agentes precisam de `web-filter:domain-rules:v1`, além do resolvedor DNS e das
capacidades de ação/monitoramento aplicáveis. A entrega pelo endpoint de política
atribuída e o ACK de sucesso são recusados quando faltam essas capacidades.
O painel conserva o aviso de publicação e aguarda o ACK, sem anunciar aplicação
apenas porque o administrador publicou.

Esta mudança está em branch própria; ainda precisa chegar a um novo build de
agente para uso real. O MSI/ISO 918aba2 dos testes USB/WDAC continua intacto e não
contém essa feature. Não houve push, PR, instalação, publicação em endpoint real
ou alteração de CI para entregar esta interface.

## Validação local

Testes foram commitados vermelhos antes da implementação. Passaram 139 testes do
painel, cinco cenários Chromium contra API real e 228 testes Rust, incluindo
vetores Python/Rust de normalização, digest e decisões. CSV teve cobertura de
linhas de 100%; tabela, 94,91%; painel completo, 95,45%. Lint/TypeScript/build e
fmt/Clippy passaram.

A suíte Python completa terminou com 1117 sucessos, 58 skips, quatro casos de
invocação integral do harness desmarcados e um timeout no inventário nativo
somente de leitura (90 s); a repetição isolada também falhou. Não é uma suíte
integralmente verde. Ruff passou nos arquivos alterados, mas o projeto tem uma
ocorrência fora da mudança: S603 em deploy/linux/build_package.py:123. Nenhum
prazo, teste ou regra de CI foi relaxado para ocultar essas pendências.
