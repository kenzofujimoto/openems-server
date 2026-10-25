# F6 — política dentro e fora da rede da empresa

Critérios em `roadmap-v2.md`: no escritório o filtro web desliga; fora dele religa sozinho em até um ciclo de sincronização; uma rede doméstica com a mesma faixa de IP não é confundida com o escritório. Aprovado pelo usuário em 2026-10-25 junto com o restante do roadmap; as decisões abaixo seguem as recomendações.

## Decisões

| # | Decisão | Escolha | Alternativa descartada |
|---|---|---|---|
| 1 | Quem decide se a máquina está no escritório | **O agente**, a cada ciclo, com as definições que o servidor envia. Sem rede ou sem servidor, ele continua decidindo com os sinais locais | O servidor decide na sincronização: uma máquina que sai do escritório e perde o servidor ficaria com o filtro desligado em casa |
| 2 | Sinais | Faixas de IP local (CIDR), MAC do gateway padrão, sufixo DNS do adaptador, **IP público de saída** visto pelo servidor e **host interno com certificado conhecido** (SHA-256 do certificado do servidor TLS em `host:porta`, 2 s de limite) | — |
| 3 | Regra de casamento | Um local casa quando o **IP público** de saída está numa das faixas públicas cadastradas **ou** quando **pelo menos dois tipos** dos outros sinais casam. O servidor recusa um local que não permita isso (só um tipo de sinal e nenhuma faixa pública) | Faixa de IP sozinha: redes domésticas usam 192.168.0.0/24 e 192.168.1.0/24 |
| 4 | IP público | O servidor devolve, em `config/assigned`, o IP de origem que viu (`client_ip`). O agente usa esse valor só enquanto a última sincronização tiver menos de 3 intervalos; depois disso o sinal fica desconhecido e não casa | O agente consultar um serviço externo de "qual é meu IP": dependência de terceiros |
| 5 | Política dentro do local | Por grupo: "dentro do local X, use o perfil Y". O servidor envia ao agente, junto da política normal, a definição de cada local mapeado para o grupo e a política completa correspondente (com digest). Para "filtro web desligado", o administrador publica um perfil sem bloqueios e o usa como perfil interno | Um campo `inside` dentro do corpo da política: misturaria a definição de rede com o conteúdo do perfil e complicaria o digest |
| 6 | Na dúvida, fora | Sem casamento, sinal desconhecido ou falha ao coletar sinais: o agente aplica a política **de fora** (a mais restritiva) | — |
| 7 | Confirmação (ACK) | O agente confirma o perfil que realmente aplicou. O servidor aceita a política do grupo ou qualquer perfil interno mapeado para o grupo, e guarda o local atual da máquina (coluna nova `location` em `endpoints`, migração `005`) | — |
| 8 | Aviso ao usuário | Ao entrar ou sair de um local, o agente registra um aviso no quadro da sessão (5c): "Rede da empresa (X) detectada" / "Fora da rede da empresa" | — |
| 9 | IP real atrás do nginx | O `docker-compose.tls.yml` passa `FORWARDED_ALLOW_IPS=*` ao uvicorn, que então usa o `X-Forwarded-For` do nginx. A porta do servidor só é publicada em `127.0.0.1`, então só o nginx (e o próprio host) chega nela | Sem isso, o servidor vê o IP do contêiner do nginx, e o sinal de IP público nunca casa |

## Formato

- Local (`POST/PUT/DELETE /api/v1/network_locations`, só admin, auditado): `id` (slug), `name`, `cidrs`, `gateway_macs`, `dns_suffixes`, `public_cidrs`, `probe` (`host`, `port`, `sha256`) opcional.
- Mapeamento (`POST/DELETE /api/v1/location_policies`): `vdom`, `location_id`, `inside_vdom` (perfil que precisa existir).
- `config/assigned` ganha `client_ip` e `locations: [{ id, name, cidrs, gateway_macs, dns_suffixes, public_cidrs, probe, assignment: {vdom, version, digest, body} }]`, na ordem de prioridade (nome).
- ACK ganha `location` (id ou vazio).

## Testes

- Agente (Rust): regra de casamento (dois sinais, IP público, rede doméstica com a mesma faixa, sinal desconhecido); escolha da política; validação do digest do perfil interno; coleta de sinais no Windows (endereços, sufixo, MAC do gateway) sem quebrar sem rede.
- Servidor: validação dos locais, mapeamento, `config/assigned` com locais e `client_ip`, ACK de perfil interno, migração `005`.
- Painel: página "Locais de rede" (lista, criar, editar, excluir, mapeamento por grupo) e o local na ficha da máquina.
- Nativo: agente em `run` com um local que casa pelos sinais da máquina de teste aplica o perfil interno; com o local alterado para não casar, volta ao de fora no ciclo seguinte.
- **Aceite em Sandbox** (`deploy/test-locations-sandbox.ps1`): o servidor simulado cadastra um local com o CIDR e o MAC do gateway do Sandbox → o domínio deixa de ser bloqueado; o local muda para outro MAC do gateway (mesma faixa, como uma rede doméstica) → volta a bloquear em até um ciclo; o servidor simulado cai → o agente mantém a decisão pelos sinais locais.

## Limites

- Sinais locais podem ser forjados por quem administra a própria máquina (trocar o sufixo DNS, por exemplo). O IP público e o certificado do host interno são os sinais fortes; o painel recomenda usá-los.
- Com VPN de túnel completo, o IP público é o da VPN: cadastre a faixa pública da VPN se ela deve contar como escritório.
