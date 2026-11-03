# Plano: normalização estrita dos hashes WDAC por cenário

Estado: aprovado explicitamente pelo usuário em 03/11/2026 ("Aprovo o plano com TDD"). Execução iniciada pelos testes; implementação depende do estado vermelho commitado.

## Problema comprovado

- Rodada da VM: fonte `f15761c`, run `e667c411feb14967bcb4b5fa85d0354a`. A atribuição v5 recebeu seis ACKs negativos. A liberação v7 recebeu ACK positivo; a remoção normal terminou com MSI 0 e a coleta posterior confirmou ausência de controles próprios e preservação dos 14 IDs CI externos.
- O XML original exportado tem 4148 bytes e SHA-256 `24457a4c42a42d444809fb64820b126b1d639be6d93e5f3a314a2d9488fca36b`.
- Ele contém oito regras `Deny`: IDs 1–4 referenciados pelo cenário kernel `131` e IDs 5–8 pelo cenário de usuário `12`. Cada cenário referencia quatro regras, sem IDs compartilhados ou referências órfãs. Os dois conjuntos têm exatamente os mesmos quatro hashes.
- A execução isolada da função original `Assert-PrivateHashPolicy`, extraída por AST, reproduziu `OPENEMS_INVALID_HASH_POLICY`, sem executar o top-level do adaptador, ConfigCI, MSI, fixtures ou controles no host. O validador exige que todas as regras sejam referenciadas somente pelo cenário de usuário; esse formato legítimo não satisfaz a condição.
- A [Microsoft documenta os oito hashes gerados para dois cenários](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/select-types-of-rules-to-create#why-does-scan-create-eight-hash-rules-for-certain-files). A estrutura real acima foi confirmada no XML desta rodada, não presumida apenas pela documentação.

## Escopo proposto

Manter a saída final de bloqueio restrita aos hashes de aplicativo em modo de usuário. Reconhecer o formato duplicado observado, normalizá-lo no XML privado e executar novamente o validador estrito existente antes de qualquer merge/conversão/carregamento.

Quatro arquivos de implementação/teste:

1. `deploy/agent-applications.ps1`: acrescentar a normalização limitada à rota existente de uma única regra hash com amostra já verificada.
2. `tests/test_windows_control_adapters.py`: regressão positiva com o formato real e casos negativos de estrutura/referências/escopo; verificar a política entregue à conversão.
3. `tests/fixtures/windows_controls_mocks.ps1`: reproduzir o XML de dois cenários no produtor mockado e observar referências por IDs reais de regras, sem depender do prefixo sintético `D`.
4. `tests/fixtures/wdac-dual-scenario-hash.xml`: fixture inerte do XML real conferido. Nenhum executável ou segredo é adicionado.

Os registros de evidência também serão atualizados em `validation/`, `HANDOFF.md` e `ACCEPTANCE.md`.

## Sequência

1. Após aprovação, adicionar primeiro a fixture, os mocks e as especificações. A regressão com oito regras precisa falhar no adaptador atual. Rodar a suíte completa permitida no host e commitar o estado vermelho antes da implementação.
2. Implementar a menor normalização necessária. Na entrada duplicada, exigir exatamente um cenário de usuário `12` e um cenário kernel `131`, quatro referências válidas por cenário, IDs exclusivos e disjuntos, cobertura de todas as regras e igualdade exata dos conjuntos de hashes com multiplicidade. Validar todos os hashes, atributos e nós antes de descartar qualquer regra.
3. Remover apenas as quatro referências kernel e suas quatro regras hash duplicadas da cópia privada. Preservar as referências e hashes de usuário. Não remover o cenário kernel vazio necessário ao merge existente. Reexecutar o validador estrito antes do merge; o resultado deve conter quatro negações de usuário e nenhuma negação kernel.
4. Preservar o comportamento já válido de XML somente de usuário. Continuar rejeitando signers, Allow/FileAttrib, hash inválido, IDs duplicados, regra órfã, referência desconhecida/repetida ou fora do caminho esperado, cenários desconhecidos/duplicados, kernel-only, referência compartilhada, namespaces/elementos/atributos inesperados e hashes kernel não equivalentes. Preservar IDs, hashes e opções de usuário. Não comparar hashes de integridade/Authenticode/page hash com o SHA-256 bruto do arquivo: o SHA-256 pós-cópia já comprova a identidade da amostra, e são algoritmos distintos. Uma entrada inválida não deve chegar ao merge nem ao carregamento.
5. Rodar novamente as suítes completas permitidas e os gates: Python, Rust, painel, Ruff, fmt, Clippy, lint, tipos e build. Recompilar o nativo para que os testes e o MSI usem o novo adaptador embutido. Não atribuir cobertura/integrações pendentes a sucesso global.
6. Commitar a correção e gerar MSIs/manifesto/ISO separados, vinculados à revisão correta, com novo run ID. Preservar os bytes e a falha anteriores.
7. Restaurar o snapshot limpo antes da nova rodada completa do catálogo. Exigir ACK em 90 segundos, processo, rede, recusa WDAC do original/renomeado, remoção quando ausente, 3600 segundos reais de rechecagem, liberação e remoção normal do MSI com limpeza conferida. Operador faz UAC e cliques no guest.

## Restrições e riscos

- Risco principal: aceitar regras extras ao normalizar. A solução reconhece somente o formato duplicado validado; casos ambíguos continuam falhando. Não basta remover a condição de cardinalidade do validador.
- Manter verificação normal de assinatura, SHA-256 pós-cópia, amostras e catálogos privados, ACLs, opções de enforcement, diário de propriedade e preservação das políticas externas.
- Não alterar as rotas de publisher/name/path/múltiplas regras, o roteiro legado, o prazo de ACK de 90 s, o relógio ou `optional_checked_at` para fabricar a hora.
- Nenhum controle, instalador ou fixture será executado no Windows físico; testes de serviço/MSI reais ficam desabilitados e os quatro casos integrais do roteiro de controles ficam desmarcados.
- A correção do XML não garante o aceite completo. Qualquer falha posterior permanece reprovada e precisa de diagnóstico e nova rodada limpa.
- Sem push, PR, merge ou publicação nesta etapa.

## Aprovação

O plano anterior autorizava três arquivos de aceite e mantinha o produto sem alterações. Esta correção altera o adaptador embutido no agente e seus testes. A aprovação explícita exigida pelo `AGENTS.md` foi recebida em 03/11/2026; a implementação segue a sequência TDD acima.
