# F2 — página local de bloqueio em HTTPS

Recorte aprovado: atender somente domínios explicitamente bloqueados pela política válida do agente. O filtro DNS avançado, categorias, SafeSearch e políticas de navegador permanecem nas próximas entregas da F2.

## Contrato de segurança

- HTTP e HTTPS escutam somente no loopback. Falha ao abrir a porta deve aparecer antes da aplicação de uma configuração dependente desse listener.
- O servidor TLS exige SNI autorizado pela política atual. Domínios permitidos, IPs, nomes inválidos e conexões sem SNI não recebem certificado. A autorização também vale ao reutilizar certificados em cache e ao processar o pedido HTTP.
- O Host do pedido deve corresponder ao SNI. O servidor só responde com a página local: não conecta ao site de origem nem encaminha tráfego.
- Cada máquina possui uma CA própria. A chave permanece local, protegida por DPAPI de máquina e acesso restrito ao SYSTEM no Windows. Certificado público pode ser exportado; chave privada não.
- Estado corrompido, certificado incompatível ou falha de proteção não provocam regeneração silenciosa da CA nem fallback para chave desprotegida.
- Instalar confiança é uma ação administrativa explícita. Iniciar o serviço não instala uma CA automaticamente.
- Remoção e rollback só podem afetar o certificado identificado como pertencente a esta instalação. Falhas devem preservar informação suficiente para repetir a limpeza.
- Certificados, conexões e leituras possuem limites. Alterar ou remover a política revoga a autorização local para os nomes removidos.

## Validação

Testes primeiro, incluindo assinatura e validação real da cadeia TLS com uma raiz de teste, SNI/Host recusados, mudança de política, persistência da CA, adulteração e desligamento dos listeners. Portas efêmeras, arquivos temporários e store de confiança injetável evitam mudar o ambiente de desenvolvimento.

Instalação/remoção real da CA, serviço e MSI exige ambiente Windows descartável. Nenhuma CA será instalada nesta máquina durante os testes automatizados. O aceite em Chrome, Edge e Firefox depende dessa validação em ambiente descartável e das configurações de confiança de cada navegador; não é comprovado apenas por um cliente TLS de teste.

Não haverá push, disparo manual de CI ou publicação de MSI nesta entrega local. Commits usam `[skip ci]`, conforme o handoff.
