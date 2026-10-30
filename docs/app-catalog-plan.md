# Catálogo de aplicativos: plano proposto

Status: aprovado em 30/10/2026 e implementado com TDD na branch `feature/policy-groups-catalog` (gerador, servidor, regra `if_present` no agente, painel). Pendente: MSI novo e aceite WDAC na VM descartável para `if_present`. Wikidata e Scoop ainda não foram integrados: a primeira versão usa só o índice do winget, mais a curadoria própria.

## Objetivo

O administrador escolhe uma categoria (Jogos, Acesso remoto, P2P...) ou um app/vendor específico e marca **Bloquear** ou **Permitir**, como no catálogo do FortiClient EMS. A política resultante bloqueia a execução nas máquinas do grupo.

## O que existe hoje

- O inventário do agente envia, por máquina, os apps instalados (`DisplayName` do registro) e em execução (caminho, SHA-256, editor Authenticode, `OriginalFilename`).
- As regras de execução (hash, editor, nome original, caminho) são geradas pelo WDAC **a partir de um arquivo local**. Uma regra sem amostra na máquina faz a política inteira falhar (`OPENEMS_SAMPLE_REQUIRED`).

## Fontes (somente abertas)

| Fonte | Licença | O que fornece |
|---|---|---|
| [winget-pkgs](https://github.com/microsoft/winget-pkgs) | MIT | ~10 mil pacotes: nome, vendor (`Publisher`), apelido (`Moniker`), tags (`game`, `remote-desktop`...), às vezes o nome em Programas instalados (`AppsAndFeaturesEntries`) |
| [Scoop buckets](https://github.com/ScoopInstaller) | MIT/Unlicense | Nomes dos executáveis (`bin`) |
| [Wikidata](https://www.wikidata.org) | CC0 | Classe do software (jogo, navegador, mensageiro, acesso remoto) e desenvolvedor |
| Inventário da frota | próprio | Editor Authenticode exato e `OriginalFilename` observados |

**FortiGuard não será raspado.** A base é proprietária da Fortinet e copiá-la expõe a RSM juridicamente. Só os nomes genéricos das categorias são usados como referência de taxonomia.

## Desenho

1. `tools/build_app_catalog.py` gera o `app-catalog.json` versionado, com atribuição das fontes.
   - Cada entrada: `id`, `name`, `vendor`, `category`, `display_names`, `executables`, `sources`.
   - As categorias vêm de um mapa revisável de tags e classes Wikidata para uma taxonomia própria de ~20 categorias.
2. **Servidor:**
   - classifica cada app inventariado pelo catálogo;
   - grava os editores e nomes originais observados de verdade;
   - oferece `GET /api/v1/app_catalog` (catálogo com contagem de máquinas onde aparece).
3. **Política:** `app_control.catalog_actions: {category|app_id: "block"|"allow"}`.
   - Na publicação, o servidor expande cada bloqueio em regras de editor/nome com os valores **observados nos inventários** do grupo.
   - "Permitir" um app dentro de uma categoria bloqueada remove esse app da expansão.
4. **Agente:** regras vindas do catálogo levam `if_present: true`. Sem amostra local, a regra é ignorada e reportada, sem derrubar a política.
   - Quando um app novo aparece no inventário, o servidor reexpande e publica nova versão.
   - Exige testes vermelhos no adaptador e um novo aceite WDAC na VM.
5. **Painel:** página "Catálogo de aplicativos".
   - Categorias com Permitir/Bloquear e busca por app/vendor, com override por linha.
   - Contagem de máquinas e aviso de que o bloqueio por editor alcança todos os apps assinados por ele.

## Limites honestos

- Sem detecção por tráfego de rede (a Fortinet usa assinaturas de DPI).
- A cobertura e a qualidade dependem do mapa de categorias e da curadoria.
- O bloqueio por editor é amplo: "Valve" bloqueia tudo assinado pela Valve.
- Apps nunca vistos em nenhuma máquina não têm editor exato conhecido. Ficam classificados, mas só viram regra quando aparecem no inventário.

## Testes (TDD)

Vermelhos primeiro:
- parser e mapa de categorias do gerador, com amostras fixas;
- classificação e expansão no servidor;
- override Permitir;
- `if_present` no adaptador, com mocks;
- painel (vitest).

Depois: suítes completas, MSI novo e aceite WDAC na VM.
