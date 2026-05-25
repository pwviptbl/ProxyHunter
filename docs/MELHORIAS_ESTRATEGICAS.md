# Melhorias Estrategicas do ProxyHunter

## Diagnostico

O ProxyHunter nao deve tentar competir diretamente com Burp Suite ou OWASP ZAP como uma ferramenta grafica completa de proxy, interceptacao, repeater, intruder e scanner. Essas ferramentas ja possuem maturidade, ecossistema, plugins, estabilidade e adocao muito maiores.

O melhor caminho para o projeto e assumir uma proposta mais especifica:

> ProxyHunter como uma ferramenta CLI-first para automacao de testes web com IA, navegacao autonoma, scanners ativos/passivos e geracao de evidencias reproduziveis.

Nesse posicionamento, o projeto deixa de ser um clone incompleto de ferramentas consolidadas e passa a resolver um problema mais pratico: automatizar fluxos repetitivos de reconhecimento, navegacao, captura, teste e relatorio.

## Diferencial Real

O diferencial mais forte do projeto e o modo CLI com automacao:

- Navegacao automatica por HTTP ou Playwright.
- Agente com IA para explorar aplicacoes, preencher formularios e mapear rotas.
- Execucao headless em terminal.
- Scans passivos e ativos sobre o historico capturado.
- Exportacao de historico, spider e relatorio em Markdown.
- Possibilidade de uso em pipelines, laboratorios e rotinas internas.

Esse conjunto tem mais valor do que tentar replicar todas as abas de uma ferramenta grafica como Burp/ZAP.

## Decisao Recomendada

Continuar o projeto, mas com mudanca clara de foco.

### Continuar se o objetivo for:

- Criar uma ferramenta de pentest automatizado via terminal.
- Usar IA para navegar, autenticar, mapear e acionar testes.
- Gerar relatorios tecnicos com evidencias.
- Criar perfis de teste para ambientes conhecidos.
- Automatizar verificacoes recorrentes em sistemas internos e legados.

### Reduzir ou parar se o objetivo for:

- Competir como proxy grafico completo.
- Reimplementar todas as funcionalidades do Burp/ZAP.
- Priorizar interface visual acima da automacao.
- Manter muitas abas sem profundidade real.

## Posicionamento Sugerido

Nome conceitual:

> ProxyHunter: AI-assisted CLI web security scanner

Proposta:

> Uma ferramenta de linha de comando para mapear, navegar, testar e gerar evidencias de seguranca em aplicacoes web, usando navegacao automatizada, IA e scanners modulares.

Exemplo de experiencia desejada:

```bash
proxyhunter audit https://alvo.local \
  --login-url /login \
  --username admin \
  --password 'senha' \
  --profile php-legacy \
  --active \
  --report reports/alvo.md
```

Saida esperada:

- Rotas descobertas.
- Formularios identificados.
- Requisicoes autenticadas capturadas.
- Vulnerabilidades passivas.
- Vulnerabilidades ativas.
- Evidencias reproduziveis.
- Comandos `curl` para confirmacao manual.
- Relatorio Markdown.

## Problemas Atuais

### 1. Foco disperso

O projeto possui GUI, CLI, scanner, spider, repeater, attacker, JWT editor, WebSocket, detector de tecnologia, relatorios e agente IA.

Isso demonstra potencial, mas tambem cria risco de virar uma ferramenta grande, dificil de manter e menos madura que Burp/ZAP em quase todas as frentes.

Recomendacao:

- Manter a GUI como recurso secundario.
- Concentrar desenvolvimento novo no CLI, agente, scanner e relatorio.

### 2. Fluxo CLI ainda fragmentado

Hoje o usuario executa etapas separadas:

```bash
proxyhunter agent https://alvo
proxyhunter scan-passive 1
proxyhunter scan-active 1
proxyhunter report-md
```

Recomendacao:

- Criar um comando unico `audit`.
- O comando deve orquestrar navegacao, captura, scanner e relatorio.

### 3. Integracao agente/proxy/scanner precisa amadurecer

O agente autonomo e um dos pontos mais fortes, mas precisa alimentar melhor o mesmo pipeline usado pelo proxy, historico, spider e scanner.

Recomendacao:

- Fazer o agente navegar sempre com proxy configurado quando estiver em modo auditoria.
- Salvar as requisicoes no mesmo formato usado pelo historico.
- Permitir scan por dominio, por rota, por formulario e por parametros descobertos.

### 4. Evidencias precisam ser prioridade

Scanner sem evidencia reproduzivel gera baixa confianca.

Cada achado deve conter:

- Tipo da vulnerabilidade.
- Severidade.
- Confianca: baixa, media ou alta.
- URL.
- Metodo.
- Parametro afetado.
- Payload usado.
- Request original.
- Request modificada.
- Trecho relevante da resposta.
- Diferenca entre resposta original e resposta alterada.
- Comando `curl` para reproduzir.

### 5. Falta uma suite de testes

O projeto possui uma aplicacao vulneravel, mas nao ha uma suite clara de testes automatizados.

Recomendacao:

- Criar testes para scanner passivo.
- Criar testes para scanner ativo.
- Criar testes de regressao usando `vulnerable_app`.
- Validar pelo menos SQLi, XSS, LFI, Open Redirect e Header Injection.

### 6. Configuracoes sensiveis

Configuracoes como OAST nao devem ter defaults reais ou sensiveis.

Recomendacao:

- Remover qualquer chave ou endpoint real hardcoded.
- Usar apenas exemplos inofensivos.
- Exigir configuracao explicita para recursos OAST.
- Documentar modo laboratorio e modo seguro.

## Melhorias Prioritarias

## P0 - Prioridade Maxima

### Criar comando `audit`

Objetivo:

Unificar todo o fluxo de auditoria em um unico comando.

Exemplo:

```bash
proxyhunter audit https://alvo.local --active --report reports/alvo.md
```

Etapas internas:

1. Iniciar proxy local.
2. Executar crawl simples ou Playwright.
3. Executar agente IA se configurado.
4. Salvar historico.
5. Executar scanner passivo.
6. Executar scanner ativo dentro do escopo.
7. Gerar relatorio Markdown.

### Relatorio com evidencias reproduziveis

O relatorio deve priorizar achados confirmaveis.

Estrutura sugerida:

````markdown
# Relatorio ProxyHunter

## Resumo

## Escopo

## Achados por Severidade

## Achados Detalhados

### SQL Injection - High

- URL:
- Metodo:
- Parametro:
- Payload:
- Evidencia:
- Confianca:
- Como reproduzir:

```bash
curl ...
```

## Rotas Descobertas

## Formularios Descobertos

## Recomendacoes
````

### Remover defaults sensiveis

Alterar configuracoes para usar valores vazios por padrao:

```json
{
  "oast": {
    "api_url": "",
    "api_key": "",
    "base_domain": ""
  }
}
```

### Testes automatizados minimos

Criar testes com a aplicacao vulneravel:

- SQL Injection detectado.
- XSS refletido detectado.
- LFI detectado.
- Open Redirect detectado.
- Header Injection detectado.
- Nenhum scan ativo fora de escopo.

## P1 - Alto Valor

### Perfis de teste

Adicionar perfis pre-configurados para contextos reais.

Exemplos:

```bash
proxyhunter audit https://alvo --profile php-legacy
proxyhunter audit https://alvo --profile laravel
proxyhunter audit https://alvo --profile api-json
proxyhunter audit https://alvo --profile municipal-portal
```

Perfis sugeridos:

- `php-legacy`
- `laravel`
- `cakephp`
- `api-json`
- `authenticated-area`
- `municipal-portal`
- `ecidade-like`

Cada perfil pode ajustar:

- Payloads.
- Caminhos comuns.
- Parametros prioritarios.
- Modulos ativos.
- Rate limit.
- Severidade esperada.
- Heuristicas de deteccao.

### Autenticacao e macros

Adicionar suporte a fluxo autenticado:

- Login por formulario.
- Reuso de cookies.
- Renovacao de sessao.
- Macro para reautenticacao.
- Validacao de logout/expiracao.

Exemplo:

```bash
proxyhunter audit https://alvo \
  --login-url /login \
  --username admin \
  --password 'senha' \
  --logged-in-check /dashboard
```

### Teste comparativo de autorizacao

Esse pode ser um diferencial forte.

Objetivo:

Executar a mesma requisicao com duas sessoes diferentes e comparar respostas para detectar IDOR/BOLA.

Exemplo:

```bash
proxyhunter authz-test \
  --user-a admin:senha1 \
  --user-b comum:senha2 \
  --request logs/request_42.json
```

Saida esperada:

- Usuario A recebeu 200.
- Usuario B tambem recebeu 200.
- Conteudo semelhante.
- Possivel falha de autorizacao.

## P2 - Evolucao

### Importador OpenAPI/Postman

Permitir importar especificacoes e gerar automaticamente requests para teste.

```bash
proxyhunter import openapi.json --out logs/collection.json
proxyhunter audit --collection logs/collection.json --active
```

### Param miner

Descobrir parametros ocultos ou esquecidos:

- `debug`
- `admin`
- `id`
- `user_id`
- `file`
- `path`
- `redirect`
- `next`
- `returnUrl`
- `callback`

### GraphQL scanner

Adicionar suporte a:

- Deteccao de endpoint GraphQL.
- Introspection.
- Fuzzing de queries.
- Testes de autorizacao em campos.

### Sequencer

Analisar entropia de:

- Tokens.
- IDs.
- Session IDs.
- Reset tokens.
- CSRF tokens.

## Nao Priorizar Agora

Evitar gastar muito tempo inicialmente com:

- Melhorias visuais grandes na GUI.
- Recriar funcionalidades maduras do Burp/ZAP.
- Editor WebSocket avancado antes do CLI estar forte.
- Muitos formatos de relatorio antes do Markdown estar excelente.
- Plugins complexos antes de estabilizar o core.

## Criterios de Sucesso

O projeto deve continuar se, em 4 a 6 semanas, conseguir entregar:

- Um comando `audit` funcional.
- Navegacao automatizada gerando historico util.
- Scanner ativo/passivo com evidencias reproduziveis.
- Relatorio Markdown bom o suficiente para uso real.
- Testes automatizados contra a aplicacao vulneravel.
- Pelo menos um perfil especializado util, como `php-legacy`.

Se ao final desse ciclo o ProxyHunter ainda parecer apenas uma GUI incompleta parecida com Burp/ZAP, o projeto deve ser reduzido ou reposicionado.

## Roadmap de 6 Semanas

### Semana 1

- Criar comando `audit`.
- Remover defaults sensiveis de OAST.
- Integrar agente, proxy, historico e scanner.
- Gerar relatorio Markdown inicial.

### Semana 2

- Criar suite de testes com `vulnerable_app`.
- Validar deteccoes principais.
- Adicionar campo de confianca nos achados.
- Padronizar estrutura de vulnerabilidade.

### Semana 3

- Melhorar evidencias.
- Gerar `curl` reproduzivel.
- Adicionar comparacao request original vs request alterada.
- Reduzir falsos positivos obvios.

### Semana 4

- Criar perfis `php-legacy`, `api-json` e `laravel`.
- Adicionar caminhos comuns por perfil.
- Ajustar payloads por perfil.

### Semana 5

- Adicionar fluxo autenticado simples.
- Reusar cookies.
- Criar base para macros de login.
- Melhorar agente IA em areas logadas.

### Semana 6

- Rodar comparativo com ZAP baseline.
- Medir achados validos, falsos positivos e tempo de execucao.
- Ajustar documentacao.
- Decidir continuidade com base no valor real entregue.

## Conclusao

O ProxyHunter tem futuro se assumir um foco claro: automacao de pentest web via terminal com IA e evidencias.

O projeto nao precisa vencer Burp ou ZAP no terreno deles. Ele precisa ser melhor em um fluxo especifico:

1. Receber um alvo.
2. Navegar automaticamente.
3. Capturar superficie.
4. Testar com criterio.
5. Produzir evidencias.
6. Gerar relatorio util.

Esse e um caminho mais realista, mais util e mais alinhado com uso profissional recorrente.
