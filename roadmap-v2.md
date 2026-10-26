# Roadmap v2 do openems

Objetivo: chegar perto do que o FortiClient EMS oferece nas funções que não dependem de produtos Fortinet (FortiGate, FortiGuard, FortiSandbox, FortiAnalyzer, VPN/ZTNA), com um agente que não exige Python na máquina e um painel profissional.

Status: aprovado em 2026-10-22, com o agente em Rust. Andamento de cada fase em `HANDOFF.md`.

Atualização em 2026-10-26: F3/F4 e a migração completa do painel F7 foram implementadas; os aceites finais Windows estão preparados, ainda pendentes. F8 tem implementação e pacotes Linux para aceite em VM; a parte macOS permanece parcial, sem Network Extension/Endpoint Security. F9 foi explicitamente excluída pelo usuário. Consulte `ACCEPTANCE.md` para testar a versão final; compilação/testes locais não substituem esses aceites.

## Decisões que precisam da sua aprovação

| Decisão | Recomendação | Alternativa |
|---|---|---|
| Linguagem do agente | Rust: binário nativo sem runtime nem coletor de lixo; a mesma linguagem serve para drivers de kernel no Windows (filtro de rede WFP, minifiltro, bloqueio de processo) e para o núcleo compartilhado com Android e iOS | Go: entrega mais rápida no modo usuário, sem caminho para drivers de kernel |
| Página de bloqueio em HTTPS | Uma CA raiz gerada em cada máquina, com a chave protegida e nunca enviada ao servidor | Sem CA: sites HTTPS bloqueados mostram erro do navegador, não a página |
| Stack do painel | React + Vite + TypeScript strict + Tailwind + componentes no estilo shadcn/ui (Radix) + TanStack Query/Router + Zod + Recharts | |
| Identidade visual | Cores, fonte e logo da RSM Brasil (rsm.global/brazil); layout de dashboard inspirado no Pivora CRM (Dribbble) | |
| Assinatura de código | Certificado de assinatura (Windows) e Apple Developer ID (macOS) | Sem assinatura: SmartScreen e antivírus vão bloquear ou alertar no agente |

O servidor continua em Python/FastAPI. Python só deixa de ser exigido nas máquinas dos usuários.

## Identidade visual

Extraída de rsm.global/brazil/pt-br:

- Cores: azul RSM `#009CDE` (principal), verde RSM `#3F9C35`, cinza texto `#515356`, cinza médio `#888B8D`, azul escuro `#006E9D` e `#27455C`.
- Fonte: Prelo, comercial. O painel e a página de bloqueio declaram `Prelo` primeiro e usam Noto Sans (licença OFL, a mesma alternativa do site da RSM) quando a Prelo não está instalada. Para usar a Prelo de verdade, a RSM precisa fornecer os arquivos licenciados.
- Logo: o PNG oficial do site (332×140). Não há versão SVG pública; uma versão vetorial deve vir do marketing da RSM.

## Como o FortiClient faz, e como faremos

O FortiClient é um agente nativo (C/C++) com drivers de rede e de sistema, instalado por MSI/PKG/DEB, sem Python. Para chegar no mesmo modelo:

- Agente nativo em Rust, instalado por MSI (WiX) no Windows, `.pkg` notarizado no macOS e `.deb`/`.rpm` no Linux.
- O painel gera o instalador com o endereço do servidor e o convite já configurados, para implantar via GPO, Intune ou manualmente.
- O agente Python atual vira a referência de comportamento: os testes de contrato com o servidor continuam valendo para o agente nativo.

## Entregas

### F1 — Agente nativo (Windows) com paridade

Registro por convite, sincronização, ACK após aplicação real, cache offline, relatório de tags e estado. Serviço com início automático no boot e recuperação. Componente de sessão do usuário (tarefa agendada no logon) para notificações. MSI assinado.

Aceite: o agente nativo passa nos mesmos testes de contrato do agente Python; instala e desinstala sem Python na máquina; reinício da máquina mantém a política.

### F2 — Filtro web completo

- Troca do arquivo `hosts` por um resolvedor DNS local do agente (127.0.0.1), configurado como DNS do sistema. Isso permite curingas (`*.exemplo.com`), lista de permitidos, categorias, horários e SafeSearch.
- Categorias: base mantida no servidor a partir de listas abertas (por exemplo, as listas da Universidade de Toulouse, licença CC BY-SA), sincronizada com os agentes. A FortiGuard é exclusiva da Fortinet.
- SafeSearch forçado: Google, Bing, YouTube e DuckDuckGo redirecionados para os endereços "seguros" de cada um.
- Horários: cada regra pode valer só em janelas de dia e hora.
- Página de bloqueio em qualquer navegador e em HTTPS: domínio bloqueado resolve para 127.0.0.1, onde o agente atende HTTP e HTTPS. Para HTTPS, o agente gera uma CA raiz própria por máquina, instala no repositório da máquina e emite na hora um certificado para o domínio bloqueado. O servidor local só exibe a página; não intercepta nem repassa tráfego de sites permitidos.
- Antiburla: políticas de navegador (Chrome, Edge e Firefox) desligam DNS over HTTPS e fazem o Firefox confiar na CA da máquina; regras de firewall bloqueiam DNS (53) e DNS over TLS (853) para servidores que não sejam o do agente, além de endpoints conhecidos de DoH.
- Registro de bloqueios enviado ao painel.

Aceite: domínio, subdomínio por curinga, categoria e horário bloqueiam em Chrome, Edge e Firefox; HTTP e HTTPS mostram a página de bloqueio; SafeSearch forçado; DoH no navegador não contorna o bloqueio.

Riscos: a CA local é sensível. Se a chave vazar, alguém poderia se passar por sites naquela máquina. Mitigações: chave única por máquina, nunca sai dela, protegida com DPAPI de máquina e ACL só para SYSTEM, removida na desinstalação. Apps com certificate pinning mostram erro em vez da página, o que é esperado.

### F3 — Controle de aplicativos

- Bloqueio antes da execução no Windows com App Control for Business (WDAC): regras de negação por hash, editor (assinatura Authenticode), caminho ou nome. É preciso confirmar o suporte nas edições do seu parque (Pro e Enterprise).
- Inventário de aplicativos instalados e em execução, com hash, editor e caminho, enviado ao painel, para o administrador escolher o que bloquear a partir de uma lista.
- Bloqueio de rede por aplicativo com regras do Firewall do Windows.
- Encerrar o processo continua como último recurso.

Aceite: um app bloqueado por hash ou editor não abre nem renomeado; um app com rede bloqueada abre, mas não conecta.

### F4 — Controle de USB e mídia removível

- Inventário no estilo do USBDeview: VID, PID, fabricante, produto, número de série, classe, ID da instância, letra de unidade, primeira e última conexão.
- Regras de permitir, bloquear ou somente leitura por classe, VID, PID, serial ou instância, como no FortiClient.
- Aplicação com as políticas do Windows de restrição de instalação de dispositivos e de acesso a armazenamento removível.
- Eventos de dispositivo bloqueado enviados ao painel.

Aceite: pendrive fora da lista é bloqueado; pendrive liberado por VID/PID/serial funciona; regra de somente leitura impede gravação; teclado e mouse nunca são afetados por regra de armazenamento.

### F5 — Proteção contra adulteração e início automático

- Serviço com início automático no boot e recuperação em caso de falha (já existe no agente Python, será refeito no agente nativo).
- Componente de sessão iniciado a cada logon de usuário.
- Permissões do serviço restritas: só SYSTEM pode parar, reconfigurar ou remover. Arquivos e chaves de registro do agente protegidos por ACL.
- Watchdog que recoloca o serviço e a configuração de DNS se forem alterados.
- Desinstalação exige um código de uso único gerado no painel.
- Eventos de tentativa de adulteração enviados ao painel.

Aceite: usuário comum não consegue parar nem remover o agente; desinstalar sem código falha; alterar o DNS do sistema é revertido e registrado.

Limite honesto: um administrador local determinado sempre consegue desativar um agente em modo usuário. Proteção forte exige driver de kernel assinado pela Microsoft, que fica para depois. A recomendação é retirar o direito de administrador local dos usuários.

### F6 — Política dentro e fora da rede da empresa

- Cadastro de "locais de rede" no painel, combinando sinais: faixas de IP local, MAC do gateway padrão, sufixo DNS, IP público de saída visto pelo servidor e acesso a um host interno com certificado conhecido.
- Cada grupo pode ter um perfil dentro da empresa e outro fora. Dentro da empresa, o filtro web é desligado porque o firewall já filtra.

Aceite: no escritório o filtro web desliga; fora dele religa sozinho em até um ciclo de sincronização; uma rede doméstica com a mesma faixa de IP não é confundida com o escritório.

Risco: faixa de IP sozinha é fraca. Redes domésticas costumam usar 192.168.0.0/24 e 192.168.1.0/24. Por isso a regra exige pelo menos dois sinais, ou o IP público de saída do escritório.

### F7 — Painel novo

- React + Vite + TypeScript strict + Tailwind + shadcn/ui, servido pelo próprio FastAPI (mesma origem, mantém cookies e CSRF atuais).
- Telas: visão geral, endpoints (detalhe com inventário, apps, USB e eventos), políticas (web, apps, USB, locais de rede), grupos e regras, eventos de bloqueio, auditoria, administradores e configurações (convites, instaladores, locais de rede).
- Pode começar já, com a API simulada (MSW), em paralelo com o agente.
- Testes: Vitest para componentes e Playwright para fluxos; cobertura de 80% em componentes.

Aceite: todas as funções do painel atual existem no novo; o painel antigo é removido; navegação por teclado e modo escuro funcionam.

### F8 — macOS e Linux

- Linux: serviço systemd; DNS local via systemd-resolved ou NetworkManager; USB com USBGuard; controle de aplicativos limitado (fapolicyd).
- macOS: daemon launchd; filtro DNS via Network Extension; USB e controle de aplicativos via Endpoint Security. Network Extension e Endpoint Security exigem Apple Developer ID, notarização e um entitlement que a Apple precisa aprovar.

### F9 — Android e iOS

Celular não permite um agente como o de desktop. Precisa de especificação própria:

- Android: app com filtro DNS local via VpnService, e Android Enterprise (modo proprietário do dispositivo) para controle mais forte.
- iOS: só via MDM em aparelhos supervisionados, com perfis de filtro de conteúdo e DNS. Exige Apple Developer e certificado de push do MDM.
- Alternativa: integrar com um MDM existente (Intune ou outro) em vez de construir um.

## Ordem sugerida

1. F7 (painel com API simulada) e F1 (agente nativo) em paralelo.
2. F2 (filtro web e página em HTTPS).
3. F5 (adulteração e início automático).
4. F6 (dentro e fora da empresa).
5. F4 (USB).
6. F3 (aplicativos).
7. F8 (macOS e Linux).
8. F9 (celulares), após especificação própria.

## Testes e execução

Mesma regra do roadmap anterior: uma branch por entrega, testes que falham primeiro, commit `test(scope): ...`, implementação mínima, suíte completa a cada mudança, PR em draft. Cobertura: 90% em serviços, 80% em componentes, 95% em caminhos críticos. Testes que alteram DNS, firewall, USB ou serviço rodam só em VM descartável, com prova de reversão.

## O que não muda

- Servidor em Python/FastAPI, PostgreSQL e Redis.
- Modelo de segurança atual: convites, credencial por dispositivo, sessões com CSRF, papéis, SAML e auditoria.
