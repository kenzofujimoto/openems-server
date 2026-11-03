# Plano: normalização estrita dos hashes WDAC por cenário

Estado: plano original e adendo aprovados explicitamente pelo usuário em 03/11/2026 ("Aprovo o plano com TDD" e "Aprovo o adendo com TDD"). Testes vermelhos XML commitados em `15d5fe0`; testes vermelhos nativos commitados em `85f953c`; metadados HVCI em `e6867a2`. Implementação e gates locais concluídos: Python 1451, Rust 251 e painel 154 passaram. Pacote novo preparado e conferido, fonte `d87d059`, run `385b1eb0f9304a6ebb308e0620215c6f` ([recibo](../validation/catalog-vm-preparation-d87d059-2026-11-03.json)). Aceite completo na VM ainda não iniciado; snapshot limpo restaurado.

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

## Adendo necessário: limite do transporte nativo

A revisão de implementação identificou uma dependência que faltou no plano original: `windows_control.rs` entrega o script inteiro por `powershell.exe -Command`. O script atual ocupa 31523 unidades UTF-16 no checkout; a linha serializada medida ocupa 31658 unidades incluindo o terminador, restando 1109 até o [limite de 32767 do CreateProcessW](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createprocessw). A normalização estrita não cabe nessa margem. Uma sonda inerte com comentário de 40000 caracteres reproduziu `WinError 206` antes de iniciar o PowerShell; nenhum adaptador ou controle foi executado.

Os testes mockados invocam uma cópia por `-File` e, sozinhos, não cobririam essa falha do transporte real. A aprovação adicional solicitada acrescenta **somente `agent-rs/src/windows_control.rs`**, incluindo os testes nativos internos, aos quatro arquivos originais. Nenhuma dependência nova ou mudança de Cargo é proposta.

1. Depois da aprovação do adendo, escrever regressões nativas inertes primeiro, usando o limite real de criação do processo: script acima de 32767 caracteres, Unicode e preservação do JSON por stdin. Executar e commitar o estado vermelho antes de mudar o transporte.
2. Transportar somente o script confiável compilado num `control.ps1` temporário e executar o PowerShell com argumentos curtos por `-File`. O arquivo conterá BOM UTF-8 para o PowerShell 5.1; requisição, política, token e configurações continuarão apenas em memória/stdin.
3. Criar o diretório privado atomicamente com proprietário e DACL protegida para a identidade atual/SYSTEM. Recusar colisões, caminhos remotos/reparse e verificar as permissões reais. Essa criação deve funcionar tanto para o serviço SYSTEM quanto para inventário de leitura executado pela conta do usuário. Não alterar permissões de diretórios preexistentes ou configurações globais do Windows.
4. Usar `create_new` para o arquivo e manter handles que impeçam troca/escrita enquanto o filho lê. Preservar os limites de entrada/saída, prioridades, timeout de controle/inventário e protocolo JSON atuais. Não usar IEX ou avaliação de política como código.
5. Encerrar o filho e juntar leitores antes de fechar os handles e remover apenas o arquivo próprio e o diretório vazio, sem remoção recursiva. Falhas de limpeza devem aparecer como erros; proteção RAII cobre também saídas antecipadas.
6. Cobrir com testes inertes o proprietário/DACL, ausência do JSON no arquivo, concorrência, colisões/reparse, limites e limpeza após sucesso, falha, timeout e erro de criação do processo. Esses testes só podem operar em seus próprios arquivos temporários; nenhum adaptador real, instalador ou controle no host.
7. Só então concluir a normalização XML já aprovada e os gates completos, recompilar o agente, gerar o MSI/ISO separado e repetir o aceite no snapshot limpo. Como o transporte é compartilhado, os testes também devem preservar o comportamento dos demais adaptadores; USB físico continua uma rodada de regressão separada.

Na validação completa, o teste existente `agent-rs/tests/application_control.rs` também precisou de manutenção mecânica: seu launcher manual por `-Command` reproduziu o mesmo WinError 206 ao carregar a fixture maior. Ele agora grava a mesma fixture confiável com BOM e usa `-File`, preservando todas as verificações de caminhos permitidos/proibidos. Essa mudança é somente de teste; não acrescenta API nem comportamento ao produto.

Risco adicional: a integridade do arquivo temporário é crítica quando executado como SYSTEM. Criação privada desde o início, verificação de permissões, handles e limpeza explícita fazem parte do contrato, não otimizações opcionais.

Evidência do ciclo vermelho: módulo com 95 casos (29 novos); suíte Python permitida com **3 falhas esperadas, 1446 sucessos, 57 skips e quatro casos integrais desmarcados**, antes das alterações de produto. Duas regressões adicionais de metadados HVCI também foram commitadas vermelhas antes da restrição. A fixture reconstrói os bytes BOM/CRLF originais para funcionar em diferentes checkouts Git.

## Aprovação

O plano anterior autorizava três arquivos de aceite e mantinha o produto sem alterações. A normalização e seus três arquivos de teste receberam aprovação em 03/11/2026. O adendo acrescenta o transporte nativo e seus testes num quinto arquivo; esse escopo ampliado também foi aprovado explicitamente pelo usuário, antes da implementação, conforme o `AGENTS.md`.
