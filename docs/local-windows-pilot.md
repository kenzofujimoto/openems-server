# Piloto local no Windows

O alvo deste piloto é a máquina de desenvolvimento. O pacote de laboratório usa os MSIs congelados de ec50572 e pode ser avaliado com as ferramentas gratuitas já usadas na homologação.

## Revisão de segurança do pacote — 22/11/2026

O alerta RUSTSEC-2026-0592 foi corrigido no lockfile para próximos builds. Os MSIs ec50572 deste pacote continuam com url 2.5.8 e seus hashes originais. A análise estática não encontrou caminho para a função afetada, mas esses MSIs não são um pacote com a dependência corrigida. A distribuição de um novo build precisa de novo recibo e revisão dos aceites aplicáveis. [Revisão completa](../validation/url-rustsec-2026-0592-review-2026-11-22.json)

## Preparar a instalação

1. Confira o resultado atual na [matriz de aceite](../ACCEPTANCE.md), incluindo a comparação final das raízes e a regressão das ações web. Registre a revisão do servidor e o hash do instalador escolhido.
2. Use um servidor de laboratório com PostgreSQL e Redis próprios. Crie um grupo exclusivo, como PilotLocal, com uma política vazia. Confira as regras de atribuição para que a máquina receba esse grupo efetivo.
3. Gere no painel um convite de uso único para esse grupo. Preserve o acesso administrativo ao servidor e a chave de recuperação da remoção no cofre local.
4. Registre o estado inicial do DNS dos adaptadores, o hash do hosts, as raízes LocalMachine e CurrentUser, e as políticas existentes de aplicativos e USB. Faça o backup habitual dos arquivos de trabalho.
5. Confirme no laboratório a liberação da política, a remoção MSI com código 0 e a restauração dos itens gerenciados. Mantenha esse resultado junto ao recibo do pacote.

O MSI de produção tem SHA-256 c1e38743359a6d420c1fec05f04bf0a2ac6c8e7b85696d1ffb17e10cb358c38a. O MSI seguinte usado no teste de upgrade tem SHA-256 eba1fc2eed0964f6020849d1002e07416a044df84a0c6522b8187454a2cae112.

Se a máquina já tiver um agente, registre sua versão, hash, servidor e estado antes de instalar. Preserve a configuração e obtenha a liberação pela administração existente quando necessária. O ensaio passa a incluir atualização de uma instalação anterior; o aceite de upgrade entre os dois MSIs congelados não comprova automaticamente a migração de qualquer versão antiga. Após atualizar, confirme o novo hash, o cadastro e a política vazia antes de aplicar controles.

## Executar o piloto

Faça a instalação elevada com o MSI conferido, o endereço do servidor de laboratório e o convite de uso único. O instalador aceita SERVER, INVITATION, VDOM e DEVID. Os parâmetros e as condições estão na [definição do MSI](../agent-rs/installer/openems-agent.wxs).

Comece pelo cadastro, inventário, grupo efetivo e confirmação da política vazia. Depois aplique um caso por vez em domínios e arquivos de teste controlados. Confira o ACK, o efeito local e o evento recebido no servidor antes de avançar.

Para testar a página HTTPS, habilite BLOCKPAGEHTTPS=1 na configuração do instalador. O modo DNS usa DNSFILTER=1. Registre os parâmetros efetivamente usados. Uma alteração de modo durante o piloto precisa de uma nova verificação do DNS, dos navegadores e da remoção.

Use as matrizes existentes de [ações web](web-filter-actions-acceptance.md) e [controles em VM](vm-acceptance-guide.md) para escolher os casos já reproduzidos. Introduza aplicativos e USB somente depois de validar a liberação do caso anterior.

## Encerrar e recuperar

1. Publique a liberação das políticas e confirme o ACK da máquina.
2. Libere a desinstalação do grupo de piloto ou gere um código de uso único no painel.
3. Remova pelo Windows Installer, usando UNINSTALLCODE quando o agente exigir o código. Preserve o código fora dos relatórios e do histórico de comandos.
4. Confira o retorno do MSI, a ausência do serviço, watchdog e processos do agente, as regras gerenciadas de DNS e firewall, o hosts original e a ausência da raiz do OpenEMS.
5. Compare as leituras finais com o baseline e registre diferenças externas separadamente para investigação. A guarda do aceite exige a igualdade exata das raízes.

O pacote de laboratório atual está sem assinatura de distribuição. O piloto local deve registrar a origem e os hashes dos arquivos usados. Uma futura assinatura pública terá um recibo próprio e uma nova verificação do instalador assinado.
