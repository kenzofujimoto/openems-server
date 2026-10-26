# Requisitos e restrições

## Servidor

- Ambiente que execute Docker Compose; imagens utilizadas no repositório: Python 3.14, PostgreSQL 16, Redis 7 e Node 24 no build.
- Segredos obrigatórios via `.env`; **nenhuma credencial padrão**. Criar com `deploy/new-env.ps1` ou mecanismo equivalente.
- TLS gerenciado pelo operador em proxy reverso. `docker-compose.yml` publica `127.0.0.1:8013:8013`; o acesso de outros hosts requer publicação segura e firewall.
- Backups de PostgreSQL, chaves duráveis e configuração. Serviços stateless não substituem persistência.

## Agente Windows

- Testar em VM descartável antes de endpoint real. Privilégios SYSTEM são usados para serviço, NRPT, firewall/WFP, política de navegador e confiança de certificado.
- WiX 5.0.2 para compilar MSI; assinatura de código ainda depende de certificado. Sem assinatura, instalação e reputação podem gerar advertências.
- Funcionalidades `DNSFILTER`, `ANTIBYPASS` e `BLOCKPAGEHTTPS` são **opt-in**. Exigem validar portas locais 53, 80 e 443 e a coexistência com VPN/EDR/DNS corporativo.
- A CA local utilizada pela página HTTPS representa superfície sensível; não funciona como inspeção do tráfego de sites permitidos.

## Condições mínimas antes de produção

1. Autorizar implantação, telemetria, retenção, base legal e comunicação aos usuários; confirmar licenças de categorias e imagens.
2. Validar rede, VPN, DNS, certificados, navegadores, EDR, upgrade e rollback numa amostra representativa.
3. Assinar artefatos, estabelecer distribuição gerenciada, gestão de segredos e recuperação de endpoint fora da rede.
4. Definir SLO, backups testados, monitoramento, procedimento de incidente e plano de remoção.
5. Executar gates CI e evidências funcionais, não apenas testes de unidade.

Não há, nesta revisão, requisitos oficiais documentados de SO/edição mínima, sizing por frota ou capacidade máxima: devem ser determinados por teste de compatibilidade/carga, sem números fabricados.
