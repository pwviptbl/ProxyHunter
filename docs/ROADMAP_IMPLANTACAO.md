# Roadmap de Implantacao do ProxyHunter

## Objetivo

Implantar o ProxyHunter como uma ferramenta de apoio a analise manual e DAST, com foco em automacao de fluxos repetitivos, cobertura autenticada, evidencias reproduziveis e utilidade pratica em ambientes internos, legados e APIs.

O objetivo nao e disputar diretamente com Burp Suite Professional ou OWASP ZAP como suite grafica completa. O objetivo e entregar um produto mais enxuto e forte nas areas em que o projeto ja demonstra vantagem:

- pipeline CLI-first
- navegacao automatizada
- integracao com agente IA
- scanners modulares
- geracao de evidencias e relatorios

## Resultado Esperado

Ao fim da implantacao inicial, o produto deve permitir um fluxo unico e previsivel:

1. Receber um alvo e um escopo.
2. Navegar e capturar trafego autenticado ou anonimo.
3. Descobrir rotas, formularios e parametros.
4. Executar scanner passivo e ativo dentro do escopo.
5. Registrar achados com evidencia reproduzivel.
6. Gerar relatorio tecnico utilizavel por pentesters e times de correcao.

## Principios de Implantacao

- Priorizar profundidade funcional sobre quantidade de abas.
- Tratar CLI e automacao como caminho principal.
- Manter a GUI como apoio operacional, nao como centro do produto.
- Evitar heuristicas opacas sem evidencia minima.
- Exigir escopo explicito antes de scans ativos.
- Padronizar achados, requests e relatorios antes de ampliar novos modulos.
- Validar cada fase com casos reais e com a `vulnerable_app`.

## Escopo da Implantacao

### Dentro do escopo

- pipeline unificado `audit`
- cobertura de navegacao, captura, scan e relatorio
- autenticacao e reaproveitamento de sessao
- evidencias tecnicas reproduziveis
- baseline de testes automatizados
- endurecimento das configuracoes sensiveis
- modulos de alto valor para analise manual e DAST

### Fora do escopo nesta etapa

- competir com todo o ecossistema de extensoes do Burp
- reimplementar toda a experiencia visual do ZAP
- criar dezenas de modulos sem criterio de confirmacao
- priorizar design de GUI acima do pipeline tecnico

## Fase 0 - Fundacao Tecnica

### Objetivo

Eliminar fragilidades que impedem a ferramenta de ser confiavel em uso recorrente.

### Entregaveis

- padrao unico para o schema de vulnerabilidades
- remocao de defaults sensiveis de OAST
- validacao de configuracao segura vs laboratorio
- consolidacao do formato de historico, spider e requests capturadas
- melhoria do reporter local para aceitar o novo schema

### Criterios de aceite

- todo achado possui pelo menos `type`, `severity`, `confidence`, `url`, `method`, `description` e `evidence`
- OAST nao funciona sem configuracao explicita
- historico do proxy e historico do agente podem ser processados no mesmo pipeline
- relatorio local nao quebra com entradas parciais ou modulos desativados

### Riscos

- manter schemas diferentes entre GUI, CLI e modulos
- seguir produzindo falsos positivos sem contexto suficiente

## Fase 1 - Pipeline Unico de Auditoria

### Objetivo

Transformar o uso fragmentado atual em uma experiencia previsivel e automatizavel.

### Entregaveis

- comando `proxyhunter audit`
- orquestracao de proxy, crawl, agente opcional, scanner passivo, scanner ativo e relatorio
- parametros de escopo, autenticacao, perfil e saida
- exportacao padronizada em `json` e `md`

### Fluxo minimo esperado

```bash
proxyhunter audit https://alvo.local \
  --scope alvo.local \
  --profile api-json \
  --active \
  --report reports/alvo.md
```

### Criterios de aceite

- uma unica execucao gera historico, spider, achados e relatorio
- scans ativos respeitam escopo
- falhas de uma etapa nao corrompem o restante do pipeline
- a saida informa claramente o que foi descoberto, testado e ignorado

### Dependencias

- Fase 0 concluida

## Fase 2 - Autenticacao, Sessao e Cobertura Real

### Objetivo

Tornar o produto util para aplicacoes reais, nao apenas alvos anonimos.

### Entregaveis

- session handler para login e renovacao de sessao
- reaproveitamento automatico de cookies e headers de autenticacao
- estrategia para CSRF token refresh
- macros simples de login
- integracao entre cookie jar, repeater, attacker, scanner e agente

### Criterios de aceite

- uma sessao autenticada pode ser reutilizada pelo scanner sem recaptura manual
- expiracao de token nao interrompe a execucao sem diagnostico claro
- requests autenticadas capturadas pelo agente entram no mesmo historico do proxy

### Ganho esperado

Esta fase e a que mais aproxima o produto de valor pratico de Burp Pro em testes internos, porque aumenta drasticamente a cobertura das rotas realmente sensiveis.

## Fase 3 - Evidencia Forte e Relatorio Tecnico

### Objetivo

Fazer cada achado ser revisavel, reproduzivel e defensavel.

### Entregaveis

- request original e request modificada por teste
- payload associado ao parametro e local de injecao
- trecho relevante de resposta
- diff basico entre resposta base e resposta alterada
- comando `curl` de reproducao
- score de confianca por achado
- relatorio markdown orientado a pentest

### Estrutura minima do achado

- tipo
- severidade
- confianca
- URL
- metodo
- parametro
- payload
- evidencia
- reproducao
- recomendacao tecnica

### Criterios de aceite

- um analista consegue revisar um achado sem abrir o codigo do modulo
- o relatorio final distingue achados confirmados de heuristicas fracas
- os dados suportam validacao manual posterior

## Fase 4 - Modulos de Alto Valor

### Objetivo

Adicionar recursos que realmente complementam Burp Community, ZAP e analise manual.

### Prioridade recomendada

1. teste comparativo de autorizacao e IDOR/BOLA
2. importador OpenAPI, Swagger e Postman
3. Param Miner e descoberta de parametros ocultos
4. WebSocket replay e reenvio de mensagens
5. CORS checker e baseline de headers
6. content discovery para arquivos, backups e paths sensiveis
7. Sequencer para tokens e IDs
8. GraphQL helper

### Criterio de entrada para novo modulo

Um novo modulo so deve entrar se atender aos tres pontos abaixo:

- cobre um caso frequente de analise manual
- consegue gerar evidencia minimamente revisavel
- nao quebra o pipeline comum de historico, scanner e relatorio

## Fase 5 - Validacao Operacional

### Objetivo

Parar de tratar o produto como prototipo e validar uso continuo.

### Entregaveis

- suite de testes automatizados com `vulnerable_app`
- casos de regressao para SQLi, XSS, LFI, Open Redirect, Header Injection e IDOR
- testes de escopo para evitar scan fora do alvo
- ambiente de demonstracao previsivel
- guia de uso para laboratorio e para ambiente controlado

### Criterios de aceite

- toda release relevante roda testes minimos
- regressao em deteccao de modulos criticos e percebida cedo
- o time consegue demonstrar a ferramenta sem ajustes manuais imprevisiveis

## Ordem de Implantacao Recomendada

### Ciclo 1

- Fase 0
- Fase 1

Meta:
entregar um `audit` confiavel, mesmo com cobertura ainda limitada.

### Ciclo 2

- Fase 2
- Fase 3

Meta:
entregar valor real em aplicacoes autenticadas e relatorio revisavel.

### Ciclo 3

- Fase 4
- Fase 5

Meta:
expandir cobertura sem perder consistencia operacional.

## Metricas de Sucesso

- tempo medio para sair de alvo informado para relatorio inicial
- quantidade de rotas e formularios descobertos por execucao
- taxa de achados com evidencia reproduzivel
- taxa de falso positivo por modulo
- percentual de execucoes autenticadas bem-sucedidas
- percentual de modulos cobertos por testes
- tempo para revisar manualmente um achado no relatorio

## Estrutura de Trabalho Recomendada

### Trilha 1 - Core Pipeline

- CLI
- historico
- scanner
- reporter
- schema comum

### Trilha 2 - Cobertura Real

- autenticacao
- sessao
- agente
- cookie jar
- OAST

### Trilha 3 - Modulos de Valor

- autorizacao comparativa
- importadores de API
- Param Miner
- WebSocket replay

## Decisoes de Produto Que Devem Permanecer Claras

- ProxyHunter nao precisa vencer Burp em interface.
- ProxyHunter precisa vencer em automacao, repetibilidade e integracao com fluxos internos.
- Todo investimento novo deve responder a pergunta: isso reduz trabalho manual real ou so aumenta superficie de manutencao.

## Proxima Acao Recomendada

Se a implantacao comecar agora, a melhor primeira entrega e:

1. endurecer configuracoes sensiveis e schema de achados
2. criar o comando `audit`
3. reforcar o relatorio com evidencia reproduzivel

Essa sequencia reduz risco estrutural primeiro e evita crescer em cima de uma base inconsistente.
