# Ciclo de vida do endpoint

Fonte: `app/service.py`, `app/api.py`, `agent-rs/src/runtime.rs`, `agent-rs/src/service.rs`.

~~~mermaid
sequenceDiagram
  autonumber
  participant Op as Administrador
  participant API as FastAPI
  participant DB as Estado servidor
  participant Ag as Agente Rust
  participant OS as Windows
  Op->>API: Criar convite (grupo, usos, TTL)
  API->>DB: Persistir convite
  Ag->>API: POST register (devid, invitation)
  API->>DB: Consumir convite, criar client_id e credencial
  API-->>Ag: client_id, device_token
  Ag->>API: GET config/assigned (autenticado)
  API-->>Ag: vdom, version, digest, body
  Ag->>Ag: Validar e guardar perfil
  Ag->>OS: Aplicar filtro / processos
  alt Aplicação confirmada
    Ag->>API: POST config/ack success=true
    API->>DB: Gravar estado aplicado
  else Falha na aplicação
    Ag->>API: POST config/ack success=false, error
    API->>DB: Registrar erro de aplicação
  end
  loop Ciclos subsequentes
    Ag->>API: Sync + telemetria agregada
    API-->>Ag: Política vigente
  end
~~~

## Estados e invariantes

1. **Identidade:** `devid` é identificador visível, **não credencial**. `client_id` e `device_token` pertencem ao cadastro e devem permanecer privados.
2. **Cadastro:** um `devid` desconhecido consome convite; recadastro exige prova de posse e revogação impede reaproveitamento.
3. **Convergência:** versão sem identidade de grupo/digest não é suficiente. O ACK confirma aplicação real, não apenas recebimento.
4. **Sem perfil:** a API retorna `unassigned: true` com versão 0 e digest vazio. A liberação explícita de política é diferente de falha de comunicação.
5. **Offline:** manter a última política validada enquanto o servidor não estiver acessível. Não deduzir liberação de bloqueios a partir de timeout.
6. **Revogação/rotação:** operações gerenciais podem exigir reconfiguração ou re-enrollment coordenado do endpoint.

## Serviço Windows

O MSI instala `openems-agent` como serviço de inicialização automática; recuperação e watchdog monitoram falhas e configurações. O agente usa `C:\ProgramData\openems` para configuração e estado. O serviço é sensível a mudanças de DNS, WFP, certificados e permissões; executá-lo como teste apenas em VM.

Relacionados: [enrollment](../getting-started/first-enrollment.md), [políticas](policy-engine.md), [desinstalação](../guides/uninstall-management.md).
