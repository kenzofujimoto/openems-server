# Filtro web: categorias, exceções e comparação FortiGuard

Atualizado em 27/10/2026. Estado implementado conferido em `agent/policy.py`, `agent-rs/src/policy.rs` e `web/src/features/webfilter/WebFilterPage.tsx`.

## Como funciona hoje

O painel em integração apresenta categorias publicadas pelo servidor, agrupadas por assunto e com contagem de domínios. O seletor grava `web_filter.category_actions`: Permitir não registra navegação, Bloquear bloqueia e registra, Monitorar permite e registra o domínio observado. Políticas antigas com `blocked_categories` continuam compatíveis. Entre categorias sobrepostas, Bloquear prevalece sobre Monitorar e Permitir; a exceção por domínio tem prioridade.

Domínios sem regra de bloqueio permanecem permitidos. A lista `web_filter.allowed` tem prioridade sobre bloqueios por domínio, categoria e horário. `*.example.com` corresponde ao domínio principal e seus subdomínios; não aceita caminho de URL. Essa exceção não reclassifica o site na base e não contorna controles independentes de aplicativos ou antiburla.

As listas são publicadas pelo servidor a partir de fontes UT1, verificadas por digest e mantidas em cache no agente. O painel mostra somente categorias efetivamente publicadas e sinaliza publicação indisponível, vazia, inválida ou desatualizada. Lista indisponível não comprova ausência de risco. As ações novas exigem capacidade do agente e suas bases necessárias, inclusive categorias permitidas quando há monitoramento geral.

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
| Inteligência artificial (`ai`) | Artificial Intelligence Technology | Parcial; critérios e tamanho da fonte diferem |
| Bancos (`bank`) | Parte de Finance and Banking | Parcial |
| Serviços financeiros (`financial`) | Parte de Finance and Banking; parte de Brokerage and Trading | Parcial; não implica cobertura completa de investimentos |
| Empregos (`jobsearch`) | Job Search | Próxima conceitualmente |
| Hospedagem web (`webhosting`) | Web Hosting | Próxima conceitualmente; fonte pequena |
| Celebridades (`celebrity`) | Parte de Entertainment | Parcial; não equivale a entretenimento geral |

O catálogo em integração possui 27 categorias: as seis últimas linhas ampliam as 21 originais. Elas só aparecem para uso quando suas listas forem publicadas; a presença do ID no código não prova disponibilidade ou qualidade da base. Não há categorias gerais para Business, Entertainment, educação, governo, TI ou domínios recém-registrados. Áudio/vídeo e celebridades não equivalem a entretenimento geral. O grupo FortiGuard General Interest - Business contém várias categorias; não é uma categoria única que possamos importar.

As novas fontes são identificadas pelo [catálogo oficial UT1](https://dsi.ut-capitole.fr/blacklists/index_en.php). Fonte, licença, limites e verificação de publicação estão na [auditoria de fontes](category-source-audit.md); a ampliação não cria equivalência com a classificação comercial da Fortinet.

Fonte dos nomes FortiGuard: [categorias oficiais do FortiOS](https://docs.fortinet.com/document/fortigate/8.0.0/fortios-log-message-reference/755423/fortiguard-web-filter-categories), consultadas em 27/10/2026. O catálogo do dispositivo depende do firmware. Base de descrições: [FortiGuard Web Filter Categories](https://www.fortiguard.com/webfilter/categories). A licença/URL de distribuição UT1 ainda exige confirmação operacional conforme HANDOFF.

## Exemplo: bloquear vídeos e permitir Netflix

1. Bloquear Áudio e vídeo.
2. Adicionar `*.netflix.com` à lista de domínios permitidos.
3. Publicar e aguardar o ACK da política pelo agente.
4. Testar login e reprodução. Identificar dependências de vídeo/CDN e incluir somente as necessárias; liberar o domínio principal não comprova reprodução completa.

Isso libera a exceção dentro de uma política de bloqueio por categorias. Não transforma a navegação numa lista global de apenas Netflix. Evitar liberar um domínio de CDN compartilhado por vários serviços sem verificar o alcance.

No FortiGate, [Web Rating Override](https://docs.fortinet.com/document/fortigate/7.6.3/administration-guide/122974/web-rating-override) pode atribuir outra categoria a uma URL. No OpenEMS atual, existe exceção por domínio na política; recategorização local e liberação temporária autenticada não estão implementadas.

## Registro e visibilidade

As ações novas permitem registrar domínios DNS de categorias monitoradas e, por opção explícita `monitor_all`, outros domínios observados. Eventos monitorados ficam separados de bloqueios; descartes também não contam como bloqueios. Permitir explicitamente um domínio suprime esse registro de navegação. Ações administrativas continuam auditadas.

Cache DNS, conexões persistentes, consultas de aplicativos e pré-carregamento impedem equiparar consulta a visita humana. O DNS não revela caminho, parâmetros, título da página ou identidade do usuário do Windows. Em modo hosts, essa observação DNS não está disponível; políticas que exigem monitoramento precisam de agente e modo compatíveis.

Consulte o [plano aprovado e seus aceites](web-filter-actions-plan.md). A extensão Chrome/Firefox é opcional, desativada por padrão e ainda depende de broker nativo e aceite próprio; sem pareamento ela permanece inativa. Os pacotes MSI anteriores a esta integração não comprovam as ações novas.
