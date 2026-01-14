# Melhorias no Gerador de Relatórios

## O que foi corrigido

### 1. Erro AttributeError
- **Problema**: `AttributeError: 'RequestHistory' object has no attribute 'get_all_entries'`
- **Solução**: Corrigido para usar o método correto `get_history()` em vez de `get_all_entries()`
- **Arquivo**: `src/ui/pyside_gui.py`

### 2. Sistema de Logs
Adicionado logging detalhado em todos os componentes:
- `src/ui/pyside_gui.py` - Logs de início, filtros e status
- `src/ui/workers/report_worker.py` - Logs do worker de geração
- `src/core/ai_reporter.py` - Logs da API e geração de PDF

### 3. Validações Melhoradas
- Verifica se há dados no histórico antes de tentar gerar relatório
- Mostra mensagens claras quando não há dados
- Verifica configuração da API antes de iniciar

### 4. Script de Teste
Criado `test_report_generator.py` para testar o gerador de forma independente

## Como usar o Gerador de Relatórios

### 1. Configurar a API Key (primeira vez)
1. Vá em **Relatório** → **Configurar IA**
2. Cole sua API Key do Google Gemini
3. Escolha o modelo (padrão: gemini-2.5-flash-lite)
4. Clique em **Salvar**

### 2. Capturar dados
1. Inicie o proxy
2. Configure seu navegador para usar o proxy
3. Navegue pelos sites que deseja testar
4. As requisições aparecerão na aba **Histórico**

### 3. Gerar o Relatório
1. Vá em **Relatório** → **Gerar com IA**
2. Configure os filtros (opcional):
   - **Domínio**: Ex: `*.example.com` ou `site.com`
   - **Status Code**: Ex: `200`, `4xx`, `500-599`
   - **Métodos HTTP**: Marque os métodos desejados
3. Clique em **Gerar**
4. Aguarde a mensagem de confirmação
5. O PDF será salvo na pasta `reports/`

## Testando o Gerador

Execute o script de teste:

```powershell
python test_report_generator.py
```

O script irá:
- ✓ Verificar a configuração da API
- ✓ Criar dados de teste
- ✓ Gerar um relatório de exemplo
- ✓ Salvar como PDF
- ✓ Confirmar que o arquivo foi criado

## Logs para Debug

Durante a geração, você verá logs detalhados:

```
2025-10-26 11:37:47 - INFO - Iniciando geração de relatório...
2025-10-26 11:37:47 - INFO - Filtros aplicados: {...}
2025-10-26 11:37:47 - INFO - Total de entradas no histórico: 10
2025-10-26 11:37:47 - INFO - Entradas após filtro: 8
2025-10-26 11:37:47 - INFO - Vulnerabilidades coletadas: 3
2025-10-26 11:37:47 - INFO - Tecnologias coletadas: 2
2025-10-26 11:37:47 - INFO - API Key configurada: Sim
2025-10-26 11:37:47 - INFO - Modelo: gemini-2.5-flash-lite
2025-10-26 11:37:47 - INFO - Worker de geração iniciado.
2025-10-26 11:37:47 - INFO - ReportWorker: Iniciando execução...
2025-10-26 11:37:47 - INFO - AIReportGenerator: Formatando prompt...
2025-10-26 11:37:47 - INFO - AIReportGenerator: Enviando requisição para a API...
2025-10-26 11:37:56 - INFO - AIReportGenerator: Resposta recebida da API
2025-10-26 11:37:56 - INFO - AIReportGenerator: Relatório gerado com sucesso
2025-10-26 11:37:56 - INFO - AIReportGenerator: PDF salvo com sucesso
2025-10-26 11:37:56 - INFO - Relatório de IA salvo em: reports\report_20251026_113756.pdf
```

## Estrutura do Relatório Gerado

O relatório inclui:
- **Histórico de Requisições**: Lista das requisições capturadas
- **Vulnerabilidades**: Falhas de segurança identificadas
- **Tecnologias Detectadas**: Frameworks, servidores, bibliotecas
- **Análise da IA**: Padrões identificados e pontos críticos
- **Recomendações**: Próximos passos para o pentester

## Problemas Comuns

### Relatório não é gerado
1. Verifique se há dados no histórico
2. Confirme se a API Key está configurada
3. Verifique os logs para identificar o erro
4. Execute `test_report_generator.py` para validar a configuração

### Erro de API Key inválida
- Verifique se a chave está correta em `config/ai_config.json`
- Teste com o script: `python test_report_generator.py`

### PDF vazio ou com erro
- Verifique os logs para ver se a IA retornou conteúdo
- Confirme se a biblioteca fpdf2 está instalada: `pip install fpdf2`

## Arquivos Modificados

- `src/ui/pyside_gui.py` - Corrigido método e adicionados logs
- `src/ui/workers/report_worker.py` - Adicionados logs detalhados
- `src/core/ai_reporter.py` - Adicionados logs e tratamento de erros
- `test_report_generator.py` - Novo script de teste
