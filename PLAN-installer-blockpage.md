# F1/F2 — instalação reproduzível do bloqueio web

## Resultado esperado

Instalar o agente em outro Windows e habilitar explicitamente a página HTTP/HTTPS pelo MSI, sem troca manual de executável nem cópia de chave/CA de outra máquina. Preservar cadastro, política e confiança em upgrades. Manter HTTPS desabilitado quando não solicitado.

## Sequência

1. Escrever e commitar testes que falham para opções do instalador, preservação da configuração e transação da confiança.
2. Acrescentar propriedades MSI validadas para página HTTP e HTTPS. HTTPS implica página HTTP; opções inválidas abortam antes de mudar o serviço.
3. Preservar configuração, credenciais e estado existentes durante upgrades. Definir quais mudanças explícitas de opções podem ser aplicadas sem substituir o cadastro.
4. Implementar instalação de confiança como transação: identificar se a CA é nova ou preexistente; rollback só remove a confiança criada pela transação atual, identificada exatamente. Preservar raízes e dados anteriores em upgrade ou falha.
5. Integrar configuração e confiança antes de iniciar o serviço; falhas devem interromper a instalação e produzir diagnóstico útil. Verificar disputa pelas portas.
6. Compilar MSI localmente e validar instalação limpa, upgrade, rollback e remoção em Windows descartável. Não instalar/remover MSI na máquina de desenvolvimento como parte dessa suíte.
7. Preparar pacote e roteiro para outra máquina Windows; nela o agente gera sua própria CA. Testar Firefox e Chrome/Edge sem ignorar alertas. Registrar limites de confiança próprios de cada navegador.
8. Atualizar handoff e critérios de aceite. Commits locais por unidade lógica, com `[skip ci]`; sem push, PR, publicação ou CI nesta entrega.

## Riscos e restrições

- A chave da CA permanece protegida por SYSTEM/DPAPI na máquina em que foi criada. Não distribuir a CA/chave desta máquina para os demais endpoints.
- Rollback não pode remover uma CA já confiável antes da instalação. Upgrade não pode zerar token, convite, caminhos personalizados ou confirmação de política.
- Porta 443 pode estar ocupada por outro software; a instalação deve falhar antes de anunciar proteção ativa.
- Aceite visual precisa ocorrer depois de a página aparecer. Crash de aba automatizada é uma ocorrência separada, ainda sem causa determinada.
- Assinatura de código depende de certificado apropriado da RSM; compilação e aceite funcional local não comprovam assinatura.
- Firefox é pendência até teste real; não declarar compatibilidade universal com base apenas em Chrome e Edge.

## Estratégia de teste

- TDD nativo para preservação de configuração e identidade, marcadores de transação e remoção exata da confiança, incluindo CA preexistente e falhas intermediárias.
- Contratos XML e CLI para opções, condições e ordem das ações MSI; validar opções inválidas e privilégios.
- Rodar a suíte local completa após cada unidade lógica; fmt, Clippy e build release quando houver mudanças Rust.
- Compilar o MSI com WiX e testar os cenários reais em Sandbox/runner descartável; guardar evidências. Sem testes de MSI destrutivos no host.
- Navegadores reais na segunda máquina: domínio bloqueado HTTP/HTTPS, domínio permitido, liberação da política sem reiniciar, limpeza da confiança própria.

Plano preparado para aprovação antes das mudanças de implementação, conforme as instruções AGENTS fornecidas pelo usuário.
