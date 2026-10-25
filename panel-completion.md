# F7 — conclusão do painel

Autorizado pelo usuário junto do restante do roadmap, com aceites de Sandbox acumulados para o final.

1. Cobrir em testes o editor web (categorias, permitidos, curingas, SafeSearch e horários), a publicação com `If-Match` e a preservação das outras seções do perfil.
2. Implementar os editores de aplicativos e USB e a escolha de regras a partir do inventário autenticado. Aplicativos usam `execution_rules`/`network_blocked`; USB usa `default_action`/`rules` e só trata armazenamento.
3. Migrar os grupos/regras, eventos e auditoria para telas reais, preservando os tipos das condições e os estados de carregamento/erro/permissão.
4. Acrescentar convites de uso limitado, instalador configurado pelo operador, gestão de administradores e configuração informativa do servidor. Credenciais retornadas uma vez ficam apenas no estado da tela.
5. Completar a ficha do endpoint com inventário e ações administrativas, a navegação móvel/por teclado e o modo escuro persistido.
6. Validar testes, cobertura, tipos, lint e build. A remoção do console legado fica com o backend após confirmar a paridade.

Riscos: concorrência na publicação exige `If-Match`; capacidade nativa depende do sistema e deve permanecer visível; USB físico e políticas WDAC não são exercitados pelo navegador. Falhas da API não apagam os dados já exibidos. O painel não altera a máquina do operador.
