# Aceite Chrome/Firefox — 26/10/2026

## Redirecionamento autorizado: Windows Sandbox

O controlador do ensaio no host foi bloqueado pelo antivírus na análise do PowerShell, antes de executar qualquer alteração do serviço. O script não foi executado; o serviço anterior continuou em execução. Não reconstruir o controlador para contornar esse bloqueio. Evidência sanitizada: `.venv/host-final-browser-test/runner-security-block.json`.

O usuário autorizou seguir no Sandbox desta máquina e poderá validar em outra máquina física amanhã. O plano executável atual é:

1. Criar Sandbox com rede e mapear somente agente final, runtimes oficiais Chrome/Firefox, Node e roteiro; resultados têm uma pasta compartilhada própria.
2. Copiar executáveis para o disco do guest. Exigir WDAGUtilityAccount e CExecSvc antes de criar política, CA ou processo do agente.
3. Criar uma CA exclusiva do guest e política web sintética usando o roteiro HTTPS existente. Conferir SHA-256 do agente e PID das portas 80/443 dentro do guest.
4. Executar Chrome via CDP e Firefox via BiDi com perfis novos e validação normal de certificados. Conferir bloqueio HTTPS, navegação HTTP e site HTTPS permitido; preservar status, DOM e capturas.
5. Encerrar processos próprios e remover CA/hosts do guest, comparando com o baseline. Registrar separadamente falhas, limpeza e limites do aceite.

Riscos e limites: disponibilidade externa do site permitido e suporte dos navegadores ao ambiente Sandbox; falha não será convertida em aprovação. O resultado valida os navegadores no guest com o agente final, sem comprovar instalação/hardening no Windows físico. Nenhum serviço, certificado ou perfil pessoal do host será alterado. F9 permanece fora do escopo. Se a segurança bloquear o roteiro também no guest, interromper e registrar a evidência.

## Plano anterior do host (não executado)

Autorização: o usuário priorizou testar Chrome/Firefox com o agente final nesta própria máquina e autorizou continuar o plano, exceto F9. O aceite em uma segunda máquina continua separado.

## Plano do ensaio

1. Fazer preflight somente leitura como SYSTEM e publicar apenas metadados sanitizados. Confirmar serviço atual, CA confiada/válida, ausência de controles de dispositivo e domínio de teste já roteado para loopback.
2. Preparar checkpoint privado em ProgramData, com ACL SYSTEM/Administradores, binário final conferido por SHA-256, cópia protegida da CA existente e configuração/estado sintéticos. Configuração, credenciais e CA originais permanecem preservadas.
3. Registrar recuperação temporária independente antes de parar o serviço. Executar o binário final em foreground como SYSTEM, nas portas IPv4 80/443, com backend loopback somente web e arquivo hosts de teste. Esse modo não ativa inventário nem proteção do serviço; a rota hosts existente permite testar example.com sem modificar o hosts real.
4. Verificar TLS pelo Windows sem exceções e atestar imagem/PID/listeners antes de publicar ready. Usar perfis novos em Chrome instalado e Firefox oficial extraído; nenhuma opção de ignorar certificados e nenhuma alteração de confiança/DNS dos navegadores.
5. Nos dois navegadores, conferir HTTPS bloqueado, navegação iniciada por HTTP (registrando eventual upgrade HTTPS), domínio permitido externo e capturas. Validar PID/hash antes/depois e falhar em crash, aviso de certificado ou página diferente da esperada.
6. Encerrar o candidato, iniciar o serviço anterior e conferir hosts, configuração, estado/CA original, confiança, políticas e listeners. Remover somente as tarefas temporárias criadas para o ensaio. Guardar evidências públicas sem credenciais/chaves.

## Limites e riscos

- A troca do listener pode causar breve indisponibilidade da página de bloqueio. O controlador tem lease limitado e tarefa independente de recuperação para reiniciar o serviço anterior em falha.
- Não é uma atualização permanente do serviço: o serviço final também ativa inventário, watchdog e hardening, exigindo um procedimento de atualização/rollback próprio.
- Este ensaio valida compatibilidade/renderização e confiança TLS dos navegadores com o binário final e rota existente. DNS local, categorias, horários, SafeSearch e antiburla têm seus aceites próprios; não serão declarados aprovados com base nestas três navegações.
- USB, WDAC, produção e F9 não fazem parte deste ensaio no host.

## Evidência de entrada

- Preflight SYSTEM aprovado em `.venv/host-final-browser-test/preflight-result.json`; serviço atual em execução, CA válida/confiada, localhost:8013, nenhum controle USB/apps ativo.
- Binário final SHA-256 `BD06AC511F4F10C22F19D4CE2E49788325EB1632B87CB4E489CF672B266B8A0B`.
- Chrome instalado 156.0.8078.47. Firefox oficial 158.0.1 extraído, com assinatura Authenticode válida da Mozilla; perfis pessoais não são utilizados.
- O resultado só será aceito depois da restauração comprovada; falhas e pendências serão registradas como tais.
