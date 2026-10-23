# F2 — resolvedor DNS local (recorte 1)

Proposta para aprovação. Nada será implementado antes do aceite deste documento.

## Objetivo do recorte

Trocar o arquivo `hosts` por um resolvedor DNS do próprio agente, para permitir curingas (`*.exemplo.com`) e lista de permitidos. A página de bloqueio HTTP/HTTPS continua a mesma, apenas passa a usar a mesma regra de correspondência.

Ficam para os próximos recortes da F2, nesta ordem:

2. SafeSearch forçado e horários por regra.
3. Antiburla: políticas de navegador contra DoH, firewall para as portas 53/853 e endpoints DoH conhecidos.
4. Categorias sincronizadas pelo servidor e registro de bloqueios no painel.

## Decisões que precisam de aprovação

| Decisão | Recomendação | Alternativa |
|---|---|---|
| Como o Windows passa a usar o resolvedor | Regra NRPT para o namespace `.` apontando para `127.0.0.1`. Não altera as placas de rede, acompanha a troca de rede (DHCP, Wi-Fi, cabo) sozinha, e regras mais específicas, como as de VPN corporativa, continuam valendo. Rollback e desinstalação removem só a regra criada pelo agente. Ainda precisa ser validada em Sandbox | Trocar o DNS de cada placa para `127.0.0.1`/`::1`. Funciona em qualquer Windows, mas precisa acompanhar placas novas e a troca de rede, e restaurar as configurações antigas de cada uma |
| Se o resolvedor parar | Bloqueia em caso de falha: sem o resolvedor, a máquina fica sem DNS até a recuperação do serviço reiniciá-lo (5 s na primeira falha). Assim, matar o processo não desliga o filtro | Libera em caso de falha: o agente remove a regra quando não consegue escutar. A máquina continua navegando, mas matar o processo também desliga o filtro |
| Significado de `*.exemplo.com` | Bloqueia `exemplo.com` e todos os subdomínios. A entrada `exemplo.com` sem curinga continua bloqueando só o domínio e o `www.`, como hoje | Curinga só para subdomínios, sem incluir `exemplo.com`, como no FortiGate |
| Biblioteca para mensagens DNS | `hickory-proto`, só para ler e montar as mensagens. Encaminhamento e limites ficam no nosso código | Parser próprio: zero dependências, mas mais código sensível para manter |

## Política

- `web_filter.blocked` passa a aceitar `*.dominio.tld`. O curinga só é aceito no primeiro rótulo e depois de pelo menos dois rótulos válidos. `*.com`, `a.*.com`, `*` e IPs são recusados.
- Novo campo `web_filter.allowed`, no mesmo formato, que vence o bloqueio. Exemplo: bloquear `*.google.com` e liberar `mail.google.com`.
- A correspondência é uma só, usada pelo resolvedor e pela página HTTPS (SNI e Host).
- O Python (`agent/policy.py`) continua sendo a referência. Os vetores de `contract/policy-vectors.json` são regenerados e os dois agentes precisam reproduzir os mesmos resultados.
- **Compatibilidade:** um agente antigo recusa a política inteira se encontrar um curinga e continua aplicando a última política válida. Também ignora `allowed` em silêncio. Por isso o agente novo informa a capacidade `web-filter:dns` nas tags, e o painel deve avisar antes de publicar curingas num grupo que ainda tenha agentes sem ela.

## Resolvedor

- Escuta em `127.0.0.1:53` e `[::1]:53`, por UDP e TCP, e só no loopback. Se a porta estiver ocupada, a instalação falha antes de criar a regra NRPT, como já acontece com a porta 443.
- **Nome bloqueado:**
  - com a página de bloqueio ligada, `A` responde `127.0.0.1` e `AAAA` responde `::1`;
  - sem a página, responde `0.0.0.0` e `::`;
  - para os demais tipos, incluindo `HTTPS`/`SVCB`, responde sem dados (NODATA);
  - TTL curto, de 30 s.
- **Nome permitido:** a consulta é encaminhada aos servidores DNS das próprias placas de rede, relidos no máximo a cada 5 s (uma troca de rede vale em até 5 s), com timeout de 2 s e fila limitada.
  - Uma resposta que vier de um endereço diferente do servidor consultado, ou com outro ID, é descartada.
  - O resolvedor nunca encaminha consultas para si mesmo (loopback).
- `use-application-dns.net` responde NXDOMAIN, que é o sinal padrão para o Firefox desligar o DoH automático. Não substitui o recorte de antiburla.
- Limites: tamanho de mensagem, conexões TCP simultâneas e consultas por segundo. Mensagens inválidas são descartadas.
- Uma mudança de política vale em até um ciclo e limpa o cache de DNS do Windows (`ipconfig /flushdns`), como já acontece hoje.
- Sem cache próprio neste recorte, porque o cliente DNS do Windows já guarda as respostas.

## Configuração, instalação e transação

- Nova opção `dns_filter` no `agent.json`, desligada por padrão, e nova propriedade `DNSFILTER=1` no MSI. Com o DNS ligado, o agente remove o bloco gerenciado do `hosts`, para não haver duas fontes de bloqueio. Sem ele, o comportamento atual continua igual.
- **Ajuste aprovado em 2026-10-23:** quem cuida da regra NRPT é o serviço, não o instalador.
  - O serviço cria a regra só depois que o resolvedor está escutando na porta 53 e a remove ao parar normalmente, inclusive no upgrade e no desligamento.
  - Se o processo for morto ou travar, a regra fica e o DNS para até a recuperação reiniciar o serviço (5 s), de modo que matar o processo não desliga o filtro.
  - Parar o serviço normalmente é ação de administrador e desliga o filtro.
  - A regra é identificada exatamente pelo comentário do agente, pelo namespace `.` e pelos servidores de loopback. Antes de criar, o serviço remove apenas sobras com essa mesma identidade.
  - O instalador remove, na desinstalação, uma sobra deixada por um travamento. Rollbacks são cobertos pela parada normal do serviço.
- Tudo continua exigindo SYSTEM e opt-in explícito: nenhum upgrade liga o DNS sozinho.

## Testes

1. **Testes que falham primeiro:**
   - vetores de política para curingas e `allowed`, em Python e em Rust;
   - correspondência com casos de borda: IDNA, maiúsculas, ponto final, sufixo parecido (`exemplo.com.br` ≠ `*.exemplo.com`);
   - respostas DNS para nome bloqueado, permitido e malformado;
   - encaminhamento para um upstream falso em porta efêmera, incluindo timeout e resposta falsificada;
   - autorização da página HTTPS usando curinga.
2. **Testes Rust e de contrato:** usam só portas efêmeras e upstream simulado. Nada altera o DNS desta máquina.
3. **Roteiro novo no Windows Sandbox**, com o MSI de produção:
   - regra NRPT aplicada;
   - bloqueio por curinga e liberação por `allowed`, conferidos com `Resolve-DnsName` e TLS confiável;
   - processo morto e recuperação, observando o comportamento escolhido para falha;
   - mudança de política sem reiniciar;
   - rollback de upgrade com falha injetada (fixtures);
   - desinstalação restaurando o NRPT original.
4. Edge no Sandbox com confirmação humana depois de a página aparecer. Chrome e Firefox ficam para a segunda máquina.

## Riscos

- Falha no resolvedor afeta todo o DNS da máquina. Mitigações: opt-in, recuperação do serviço, testes de limites e de malformação, e o aceite em Sandbox antes de qualquer máquina real.
- O comportamento da regra NRPT para `.` precisa ser comprovado em Sandbox. Se falhar, a alternativa é trocar o DNS das placas, que exige nova aprovação.
- A interação com VPN, como o FortiClient da empresa, e com portais cativos de Wi-Fi só pode ser validada numa máquina física.
- Até o recorte 3, DoH configurado no navegador, ou um DNS escolhido manualmente pelo usuário em algum aplicativo, continua contornando o filtro.

Commits locais com `[skip ci]`, sem PR e sem CI, conforme o handoff.
