# Filtro web: categorias, exceções e comparação FortiGuard

Atualizado em 27/10/2026. Estado implementado conferido em `agent/policy.py`, `agent-rs/src/policy.rs` e `web/src/features/webfilter/WebFilterPage.tsx`.

## Como funciona hoje

O painel apresenta categorias publicadas pelo servidor, agrupadas por assunto e com contagem de domínios. Marcar uma categoria adiciona seu ID a `web_filter.blocked_categories`. Categorias desmarcadas não criam uma permissão prioritária: o domínio ainda pode ser bloqueado por outra categoria, regra ou horário.

Domínios sem regra de bloqueio permanecem permitidos. A lista `web_filter.allowed` tem prioridade sobre bloqueios por domínio, categoria e horário. `*.example.com` corresponde ao domínio principal e seus subdomínios; não aceita caminho de URL. Essa exceção não reclassifica o site na base e não contorna controles independentes de aplicativos ou antiburla.

As listas são publicadas pelo servidor a partir de fontes UT1, verificadas por digest e mantidas em cache no agente. O painel mostra somente categorias efetivamente publicadas. Lista indisponível não comprova ausência de risco; consulte o plano de tratamento de cobertura abaixo.

## Matriz de correspondência conceitual

Esta matriz é uma análise do projeto. **Não indica mesma cobertura, mesmos sites, importação de política FortiGate nem paridade funcional.** Mesmo uma correspondência próxima usa bases e critérios distintos.

| OpenEMS (ID) | FortiGuard de significado próximo | Relação |
|---|---|---|
| Conteúdo adulto (`adult`) | Pornography; Nudity and Risque; Lingerie and Swimsuit | Agrupada, mais ampla |
| Relacionamentos (`dating`) | Dating | Próxima |
| Jogos de azar (`gambling`) | Gambling | Próxima |
| Malware (`malware`) | Malicious Websites; parte de Crypto Mining | Parcial |
| Phishing (`phishing`) | Phishing | Próxima |
| Hacking (`hacking`) | Hacking | Próxima; fonte também inclui DDoS |
| VPN e proxies (`proxy`) | Proxy Avoidance | Parcial |
| Drogas (`drugs`) | Drug Abuse; parte de Marijuana | Parcial |
| Violência e ódio (`violence`) | Explicit Violence; Discrimination | Agrupada |
| Materiais perigosos (`weapons`) | Weapons (Sales) | Parcial |
| Pirataria (`warez`) | Parte de Illegal or Unethical | Parcial |
| Jogos (`games`) | Games | Próxima |
| Áudio e vídeo (`streaming`) | Streaming Media and Download; Internet Radio and TV | Agrupada |
| Armazenamento e download de arquivos (`filehosting`) | File Sharing and Storage; Freeware and Software Downloads | Agrupada |
| Redes sociais (`social`) | Social Networking | Próxima |
| Chat e mensageiros (`chat`) | Web Chat; Instant Messaging | Agrupada |
| Webmail (`webmail`) | Web-based Email | Próxima |
| Compras (`shopping`) | Shopping | Próxima |
| Esportes (`sports`) | Sports | Próxima |
| Notícias (`press`) | News and Media | Próxima |
| Publicidade (`ads`) | Advertising | Próxima |

Não há categorias próprias para Business, Entertainment, educação, finanças, governo, TI, IA ou domínios recém-registrados. Áudio/vídeo não equivale a toda forma de entretenimento. O grupo FortiGuard General Interest - Business contém várias categorias; não é uma categoria única que possamos importar.

Fonte dos nomes FortiGuard: [categorias oficiais do FortiOS](https://docs.fortinet.com/document/fortigate/8.0.0/fortios-log-message-reference/755423/fortiguard-web-filter-categories), consultadas em 27/10/2026. O catálogo do dispositivo depende do firmware. Base de descrições: [FortiGuard Web Filter Categories](https://www.fortiguard.com/webfilter/categories). A licença/URL de distribuição UT1 ainda exige confirmação operacional conforme HANDOFF.

## Exemplo: bloquear vídeos e permitir Netflix

1. Bloquear Áudio e vídeo.
2. Adicionar `*.netflix.com` à lista de domínios permitidos.
3. Publicar e aguardar o ACK da política pelo agente.
4. Testar login e reprodução. Identificar dependências de vídeo/CDN e incluir somente as necessárias; liberar o domínio principal não comprova reprodução completa.

Isso libera a exceção dentro de uma política de bloqueio por categorias. Não transforma a navegação numa lista global de apenas Netflix. Evitar liberar um domínio de CDN compartilhado por vários serviços sem verificar o alcance.

No FortiGate, [Web Rating Override](https://docs.fortinet.com/document/fortigate/7.6.3/administration-guide/122974/web-rating-override) pode atribuir outra categoria a uma URL. No OpenEMS atual, existe exceção por domínio na política; recategorização local e liberação temporária autenticada não estão implementadas.

## Registro e visibilidade

O agente registra bloqueios vistos pelo DNS, não todo tráfego permitido. Cache DNS, conexões persistentes, consultas de aplicativos e pré-carregamento impedem equiparar consulta a visita humana. O DNS não revela caminho, parâmetros, título da página ou identidade do usuário do Windows. Em modo hosts, essa observação DNS não está disponível.

Para os controles propostos e o plano de ampliação, consulte [Permitir/Bloquear/Monitorar](web-filter-actions-plan.md). Categorias ausentes e monitoramento são pendências explícitas, não funcionalidades anunciadas como prontas.
