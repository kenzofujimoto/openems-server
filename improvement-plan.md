# Plano de evolução do openems-server

Objetivo: tornar a gestão com o agente próprio segura, verificável e resiliente; validar compatibilidade FortiClient em uma etapa separada, com tráfego real de laboratório.

Status: proposta aguardando aprovação. A demonstração local de `example.com` usa o código existente e não implementa estas melhorias.

## Sequência proposta

| Ordem | Entrega e arquivos principais | Critério de aceite |
|---|---|---|
| 1 — P0 | Remover XSS: substituir dados interpolados em HTML/handlers por DOM seguro e listeners em `app/static/index.html`; adicionar testes de navegador. | Identificadores com aspas e HTML aparecem como texto e não executam código ao carregar/clicar. |
| 2 — P0 | Fechar acesso gerencial sem bootstrap explícito; proteger e auditar importação de IdP; aplicar permissões por ação, revogação de sessão e limitação de login. Alterar `app/api.py`, `auth.py`, stores, auditoria e console. | Sem sessão: 401; leitor não escreve: 403; logout/revogação invalidam sessão; setup aberto somente por opção explícita em loopback. Cookies seguros exigem proteção CSRF. |
| 3 — P0 | Separar ID de dispositivo de credencial, exigir convite limitado e prova de posse no recadastro; autenticar leitura de políticas, tags, fila e ACK. Alterar modelos, API, serviço, stores e agente. | Conhecer `devid` não revela credencial; A não acessa B; rotação/revogação funcionam; recadastro preserva estado. |
| 4 — P1 | Validar perfis/domínios/processos; tornar escrita do hosts segura, preservar entradas alheias, manter backup e limpar DNS; conferir resultado real de encerramento. Alterar agente, modelos e API. | Entrada inválida não altera o sistema; reaplicação é idempotente; falha preserva conteúdo anterior e não é anunciada como sucesso; rollback restaura acesso. |
| 5 — P1 | Completar sincronização: identidade da política + versão + digest, ACK após sucesso, fila consumida e reconciliação periódica. Persistir última política válida e identidade; separar enforcement de comunicação. | Troca de grupo com mesma versão funciona; ACK impossível é rejeitado; offline mantém bloqueios e controle de apps; erro/404 não remove política; reconexão converge. |
| 6 — P1 | Unificar loops CLI/serviço; tratar BOM/configuração inválida, falha de worker, recovery, logs e códigos de saída do instalador. Alterar `agent/service.py` e scripts PowerShell. | Reinício recupera política offline; serviço com worker morto não parece saudável; instalação parcial falha visivelmente e permite reversão. |
| 7 — P1 | Mostrar último contato, online/offline, política desejada/aplicada e erros; editor preserva múltiplas condições, tipos, prioridade zero e enabled; formulário de bloqueios e estados de erro acessíveis. Alterar modelos, stores, API e console. | UI só mostra aplicação confirmada; edição não perde dados; falha de API preserva dados anteriores e permite retry; navegação por teclado funciona. |
| 8 — P1/P2 | Endurecer SAML e operação: assinatura obrigatória, consumir nó verificado, validar issuer/audience/destination/recipient, correlacionar pedidos e reter replay por toda janela aceita; persistir IdPs. Adicionar migrações, TLS de implantação, redaction/retenção de capturas e CI completo. | Rejeitar assinatura ausente, wrapping, replay e respostas não correlacionadas; reinício preserva IdP; capturas não guardam credenciais; contratos PostgreSQL/Redis e testes criptográficos executam sem skips. |

## Testes e execução

Após aprovação: branch `feature/ems-reliability`; para cada entrega, escrever testes que falhem, confirmar a falha e commitar `test(scope): ...`; implementar o mínimo, executar a suíte completa após cada alteração, refatorar/lintar e commitar a unidade lógica. PRs começam como draft.

Cobertura exigida: 90%+ em serviços, 80%+ em componentes e 95%+ em caminhos críticos. Usar testes unitários, contratos PostgreSQL/Redis, API, navegador e integração Windows; testes de sistema usam arquivos/processos descartáveis. Alteração real de hosts exige backup e prova de reversão.

## Restrições e riscos

- Autenticação nova e estado de política exigem migração de banco e atualização coordenada do agente; não confundir essa mudança com compatibilidade FortiClient.
- `hosts` cobre nomes explícitos: não oferece categorias, wildcard, inspeção HTTPS nem bloqueio de conexões já abertas. A página personalizada atual atende HTTP.
- Filtragem avançada e prevenção de execução via mecanismos do Windows ficam para uma segunda especificação, após avaliar edição do SO, instalação e reversão. Não instalar CA nem prometer resistência absoluta a administrador local.
- Compatibilidade FortiClient, keepalive e avatar dependem de captura autorizada em laboratório; criar fixtures e contratos somente com formatos observados. Nenhum ambiente FortiClient real foi validado nesta proposta.

Concluído quando: aplicação confirmada e falhas visíveis no console, enforcement offline preservado, acesso não autorizado rejeitado, rollback demonstrado e verificações obrigatórias verdes.
