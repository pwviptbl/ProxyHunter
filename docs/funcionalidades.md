# Abas da Interface

- Regras
- Intercept
- Histórico
- Repetição
- Attacker (Intruder)
- Decoder
- JWT Editor
- Comparador
- Cookie (Cookie Jar)
- Scanner
- Spider
- WebSocket
- Tecnologias

# Funcionalidades

- **Regras:** Criação e gerenciamento de regras para interceptar/modificar tráfego por host/path e parâmetros.
- **Intercept:** Interceptação manual (Forward/Drop) e edição de requisições/respostas antes do envio.
- **Histórico:** Registro do tráfego, filtros e ações como enviar para Repetição, Attacker, Comparador e JWT Editor.
- **Repetição:** Reenvio de uma requisição individual com edição de parâmetros, headers e corpo.
- **Attacker (Intruder):** Execução automatizada com marcadores de payload `§...§` e envio concorrente (threads).
- **Decoder:** Codificação/decodificação (Base64, URL, HTML, Hex) e hashes.
- **JWT Editor:** Decodificar, modificar e assinar JWT para testes (com envio para Repetição).
- **Comparador:** Comparação lado a lado de duas requisições/respostas, destacando diferenças.
- **Cookie (Cookie Jar):** Captura e gerenciamento de cookies, com sessão forçada para Repetição/Attacker.
- **Scanner:** Scan passivo no tráfego e scan ativo sob demanda com módulos configuráveis.
- **Spider:** Descoberta automática de URLs/endpoints e formulários.
- **WebSocket:** Monitoramento e histórico de conexões e mensagens WebSocket (reenvio não implementado no momento).
- **Tecnologias:** Detecção e exibição de tecnologias usadas pelos alvos.
