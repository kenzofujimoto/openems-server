# F2 — antiburla do filtro web (recorte 3)

Proposta para aprovação. Nada será implementado antes do aceite deste documento. Parte do resolvedor DNS (recortes 1 e 2), já aceito em Sandbox.

## Objetivo

Hoje um usuário contorna o filtro de três formas:

- ligando o DNS seguro (DoH) no navegador;
- usando um aplicativo que consulta um DNS público direto, em vez do DNS do Windows (porta 53 ou DNS sobre TLS na 853);
- usando DoH por endereço IP, como `https://1.1.1.1/dns-query`.

Este recorte fecha essas três portas. Também faz o Firefox confiar na CA do agente, para a página de bloqueio HTTPS abrir nele sem aviso.

## Decisões que precisam de aprovação

| Decisão | Recomendação | Alternativa |
|---|---|---|
| Como bloquear DNS direto (53 e 853) | Filtros do WFP, a plataforma de filtragem do Windows por baixo do Firewall. Bloqueiam as portas remotas 53 e 853 (UDP e TCP) para todos os programas, **exceto o executável do agente** e o tráfego de loopback. O Firewall comum não permite "todos menos um programa", porque nele um bloqueio sempre vence uma liberação | Regras do Firewall do Windows só para a 853 e para os IPs de DoH conhecidos, sem a 53. É mais simples, mas qualquer `nslookup` com servidor próprio continua burlando |
| Quem cuida dos filtros | O serviço, como a regra NRPT. Cria os filtros depois que o resolvedor escuta, remove na parada normal, e um travamento deixa os filtros (o bloqueio continua). A desinstalação remove sobras, identificadas pelo provedor e pela subcamada WFP próprios do agente | Instalador: os filtros ficariam mesmo com o serviço parado. Se ficassem sem o resolvedor, o Windows inteiro perderia DNS |
| DoH por IP | Filtros WFP bloqueiam as portas 443 e 853 para uma lista embutida de IPs de DoH públicos (Cloudflare, Google, Quad9, OpenDNS, AdGuard, NextDNS etc.). Os nomes desses serviços (`dns.google`, `cloudflare-dns.com`, `dns.quad9.net`…) respondem NXDOMAIN no resolvedor | Só os nomes, sem bloquear os IPs |
| Políticas de navegador | O serviço grava em `HKLM\SOFTWARE\Policies`: Chrome e Edge com `DnsOverHttpsMode=off`; Firefox com `DNSOverHTTPS` desligado e travado e `Certificates\ImportEnterpriseRoots=1`. Os valores anteriores são guardados no estado protegido e restaurados na desinstalação. Se uma GPO sobrescrever, o agente regrava no ciclo seguinte e registra no log | Só documentar para o administrador configurar por GPO |
| Ativação | Opção `anti_bypass`, desligada por padrão, que exige `dns_filter`. No MSI, `ANTIBYPASS=1`. Upgrades preservam a escolha | Ligar junto com o `dns_filter` |

## Comportamento

- **Filtros WFP:**
  - Provedor e subcamada com GUIDs fixos do agente, e filtros persistentes com peso alto dentro da subcamada.
  - A exceção é pelo App ID do executável instalado (`FwpmGetAppIdFromFileName0`). O tráfego de loopback é excluído pela flag `IS_LOOPBACK`, assim o cliente DNS do Windows continua chegando ao resolvedor em `127.0.0.1:53`.
  - O agente ainda alcança o DNS das placas na porta 53 para encaminhar as consultas.
- **Ordem:**
  - Na partida: resolvedor → regra NRPT → filtros → políticas de navegador.
  - Na parada normal, primeiro saem os filtros e depois a regra NRPT. As políticas de navegador ficam: elas não tiram o DNS de ninguém e só saem na desinstalação.
- **Lista de DoH:** embutida no agente e coberta por vetores compartilhados. Os IPs entram nos filtros e os nomes no resolvedor, com resposta NXDOMAIN.
- **Firefox:** com `ImportEnterpriseRoots`, ele passa a confiar nas raízes do repositório da máquina, inclusive a CA do agente, e a página HTTPS abre sem aviso.
- **Diagnóstico:** com `anti_bypass` ativo, o agente envia a tag `web-filter:anti-bypass`.

## Testes

1. **Testes que falham primeiro:**
   - montagem das condições WFP como dados puros: portas, loopback, App ID e IPs, sem chamar o WFP;
   - lista de DoH e vetores;
   - NXDOMAIN para os nomes de DoH;
   - cálculo dos valores de registro e restauração do estado anterior, com um registro simulado;
   - configuração, CLI e propriedade MSI.
2. **Sandbox**, com o MSI de produção e rede:
   - `Resolve-DnsName -Server 8.8.8.8` e `-Server 1.1.1.1` falham (bloqueio de DNS direto);
   - `Test-NetConnection 1.1.1.1 -Port 443` e `-Port 853` falham;
   - `dns.google` responde NXDOMAIN;
   - a resolução pelo sistema continua funcionando, e o próprio agente encaminha para o DNS da placa;
   - os valores de registro dos navegadores estão gravados;
   - processo morto: os filtros e a regra continuam; parada normal: os dois saem;
   - desinstalação: filtros, regra e registro voltam ao estado anterior.
3. Edge com DoH configurado manualmente pelo operador (Cloudflare) continua mostrando a página de bloqueio. Firefox não vem no Sandbox; fica para a segunda máquina.
4. Nada é alterado no WFP, no registro ou no DNS desta máquina.

## Riscos

- Um erro nos filtros WFP pode bloquear o DNS do próprio Windows. Mitigações: exceção de loopback, filtros só do serviço e removidos na parada normal, opt-in e aceite em Sandbox antes de qualquer máquina real.
- A exceção pelo App ID depende do caminho do executável. Um upgrade que mude o caminho precisa recriar os filtros; isso acontece porque o serviço os recria a cada partida.
- VPNs que usam DNS próprio na porta 53 a partir de outro processo (cliente de VPN) seriam bloqueadas. Hoje a regra NRPT da VPN aponta para um servidor que o Windows consulta pelo cliente DNS do sistema, o que passaria pelo loopback e pelo agente. **Precisa ser validado na máquina física com o FortiClient.**
- A lista de IPs de DoH nunca é completa: um DoH privado e desconhecido ainda passa. O recorte 4 (categorias) pode incluir listas abertas de DoH.
- Um administrador local sempre consegue remover filtros e políticas. A proteção contra isso é a F5 (antiadulteração).

Commits locais com `[skip ci]`, sem PR e sem CI, conforme o handoff.
