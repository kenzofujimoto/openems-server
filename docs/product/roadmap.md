# Roadmap consolidado

Esta página organiza o plano existente em [roadmap-v2.md](../../roadmap-v2.md). **Não autoriza novas implementações.** Estado detalhado em [status.md](../status.md) e [HANDOFF.md](../../HANDOFF.md).

~~~mermaid
flowchart TB
  F1[F1 Agente Windows: parcial] --> F2[F2 Filtragem web: parcial]
  F1 --> F5[F5 Antiadulteração: parcial]
  F2 --> F7[F7 Painel React: parcial]
  F5 --> F7
  F7 --> F6[F6 Redes internas/externas: planejado]
  F7 --> F3[F3 Aplicativos: básico]
  F7 --> F4[F4 USB: planejado]
  F1 --> F8[F8 Linux/macOS: planejado]
  F8 --> F9[F9 Android/iOS: planejado]
~~~

As setas representam dependências técnicas aproximadas, não cronograma oficial.

| Fase | Critério de conclusão pendente |
| --- | --- |
| F1 | Componente de logon, distribuição assinada e testes de diferentes máquinas |
| F2 | Integração completa com UI, licença de categorias, homologação de navegadores/VPN |
| F3 | Inventário, regra por hash/editor e bloqueio pré-execução comprovado |
| F4 | Inventário USB e políticas seguras para armazenamento removível |
| F5 | Sessão de logon e cenários complementares de recuperação |
| F6 | Classificação confiável de rede e perfis distintos |
| F7 | Migrar editores, auditoria, grupos, configurações e concluir remoção do legado |
| F8 | Implantação/serviço, controles e testes nativos de cada SO |
| F9 | Especificação de produto e viabilidade de MDM para dispositivos móveis |

**Prioridade documental:** toda entrega que modificar API, configuração, política, MSI, garantia de segurança ou procedimento de recuperação deve atualizar a referência correspondente e a evidência de teste no mesmo PR.
