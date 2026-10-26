# OpenEMS

[![CI](https://github.com/kenzofujimoto/openems-server/actions/workflows/ci.yml/badge.svg)](https://github.com/kenzofujimoto/openems-server/actions/workflows/ci.yml)

**OpenEMS** é uma implementação independente, experimental e de código aberto de gerenciamento de endpoints. Inclui servidor de políticas, agentes de referência, agente nativo para Windows e console web. **Não é uma alternativa homologada nem um substituto equivalente ao FortiClient EMS em produção.**

## Componentes

| Componente | Tecnologia | Finalidade |
| --- | --- | --- |
| API e serviço | Python 3.14, FastAPI | Cadastro, identidade, perfis, regras, eventos, auditoria e SAML |
| Persistência | PostgreSQL 16 e Redis 7 | Estado persistente, sessões, fila, replay |
| Agente Windows | Rust, serviço Windows e MSI/WiX 5 | Aplicação local das políticas, DNS, bloqueios e integridade |
| Agente de referência | Python | Contratos e comportamento de referência; não é o pacote recomendado para distribuição |
| Painel | React 19, TypeScript, Vite | Administração em `/panel/`; ainda há funções no console legado `/console/` |

**Estado:** F1, F2, F5 e F7 parciais; F3, F4, F6, F8 e F9 não concluídas. Há verificações em Windows Sandbox, mas **não há homologação integral em endpoints físicos/produção**. Consulte [matriz de funcionalidades](docs/product/capabilities.md), [status por fase](docs/status.md) e [evidências](docs/validation/evidence-index.md).

## Início rápido (laboratório)

Requisitos: Docker Compose, PowerShell para geração segura do `.env` e um ambiente **isolado**. Não instale o agente com alterações de DNS, CA ou serviço no computador de trabalho para experimentar.

~~~powershell
powershell -ExecutionPolicy Bypass -File deploy/new-env.ps1
docker compose up --build -d
docker compose ps
~~~

O gerador mostra credenciais iniciais uma única vez e cria `.env` (não versionar). Padrão de desenvolvimento: `http://localhost:8013`; **em rede externa, configurar HTTPS**. A imagem Docker expõe a API apenas no loopback do host. Navegue para `http://localhost:8013/panel/`; operações ainda não migradas estão em `/console/`.

**Não use** exemplos de credenciais padrão publicados em versões antigas deste README. O Compose atual exige segredos explicitamente.

## Documentação

- [Índice completo](docs/index.md) · [Início rápido](docs/getting-started/quickstart.md) · [Instalação Windows](docs/deployment/windows-agent.md)
- [Arquitetura e diagramas](docs/architecture/system-design.md) · [API](docs/reference/api.md) · [Políticas](docs/reference/policy-schema.md)
- [Segurança](docs/security/threat-model.md) · [Operação e recuperação](docs/operations/troubleshooting.md)
- [Testes e evidências](docs/validation/test-matrix.md) · [Contribuição](CONTRIBUTING.md)

## Interoperabilidade e proveniência

O protocolo de comunicação com produtos de terceiros **não está integralmente validado**. [SPEC-INTEROP.md](SPEC-INTEROP.md) contém observações, inferências e elementos pendentes de captura autorizada; não é garantia de compatibilidade. A implementação é independente, não afiliada nem endossada pela Fortinet. Não usar código, binários, ativos visuais ou dados proprietários sem autorização. [Veja os limites e licenças](docs/security/licensing.md).

## Segurança e licença

Leia [SECURITY.md](SECURITY.md) antes de relatar vulnerabilidades e a [política de privacidade e retenção](docs/security/privacy-lgpd.md) antes de coletar telemetria. Código sob [MIT](LICENSE); dados, listas e marcas de terceiros podem ter regras distintas.
