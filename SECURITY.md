# Política de segurança

O OpenEMS gerencia endpoints com privilégios elevados e interage com autenticação, DNS, WFP e certificados. **Não há certificação/homologação integral de produção.** Consulte [modelo de ameaças](docs/security/threat-model.md) e [status](docs/status.md).

## Reportando vulnerabilidades

Não publique exploração funcional de falha ainda não corrigida com segredos ou dados de terceiros. Solicite um canal privado aos mantenedores do repositório por meio dos contatos do perfil do projeto; **não existe e-mail de disclosure oficial confirmado nesta revisão**, portanto não inventamos um.

Ao reportar, inclua: commit/versão, SO, pré-condições, efeito, passos mínimos de reprodução seguros, logs redigidos e mitigação sugerida. Nunca envie `device_token`, sessão, chave-mestra, `uninstall.json` ou CA privada.

## Escopo sensível

- Autenticação administrativa, convite, device token, SAML/assinaturas e sessões/CSRF.
- Validação, distribuição, ACK e cache de políticas.
- Autoridade local de bloqueio HTTPS e chaves protegidas.
- DNS/NRPT/WFP, serviço SYSTEM e proteção contra adulteração.
- Código de desinstalação, entrega do segredo, liberação global e backups.
- Registro de domínios/eventos e auditoria de dados pessoais.

## Testes responsáveis

Atividades que instalam CA, interceptam DNS local, alteram ACL/serviço ou simulam falha de MSI devem ocorrer **em VM/Sandbox próprio e autorizado**. Não executar contra rede, colaborador, endpoint ou serviço de terceiro sem permissão.

Publicar mitigação com evidência e procedimento de rollback; não prometer antiadulteração absoluta perante administrador local/SYSTEM. Consulte [recovery](docs/operations/disaster-recovery.md).
