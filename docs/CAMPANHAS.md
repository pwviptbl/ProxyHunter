# Campanhas de Rotas Capturadas

Campanhas permitem navegar manualmente por sistemas legados, salvar apenas as
rotas com superficie util para teste e executar scan em lote depois.

O foco e reduzir ruido de arquivos estaticos e recursos auxiliares, mantendo:

- `GET` com parametros na query string
- `POST`, `PUT`, `PATCH` e `DELETE` com query string ou corpo testavel
- requests deduplicadas por metodo, host, path, parametros e tipo de corpo

Por padrao sao ignorados arquivos como `.js`, `.css`, imagens, fontes, PDF,
ZIP e outros recursos estaticos.

## Capturar Navegacao Manual

### Pela GUI

1. Inicie o proxy.
2. Abra a aba `Campanhas`.
3. Preencha nome e escopo, se necessario.
4. Clique em `Iniciar Captura`.
5. Navegue pelos menus, frames e rotinas do sistema.
6. Clique em `Finalizar Captura`.
7. Revise a lista de rotas testaveis.
8. Use `Exportar`, `Importar`, `Scan Selecionado` ou `Scan Todos`.

Antes do scan/exportacao, use `Excluir Selecionado` ou o menu de contexto da
tabela para remover rotas auxiliares repetidas, como login, frames comuns ou
endpoints de apoio que nao fazem parte do modulo em teste.

Se marcar `Simultaneo`, cada rota testavel nova entra em uma fila e o scanner
vai processando em ordem enquanto a navegacao continua. Use os checkboxes
`Passivo` e `Ativo` para controlar quais testes entram nessa fila.

### Pela CLI

```bash
./.venv/bin/python scripts/cli.py campaign capture https://alvo.local/e-cidade \
  --scope alvo.local \
  --out logs/ecidade-campaign.json
```

Depois configure o navegador para usar o proxy informado pela CLI, navegue nos
menus, frames e rotinas do sistema e pressione `Ctrl+C` para finalizar.

## Criar Campanha de um Historico Existente

```bash
./.venv/bin/python scripts/cli.py campaign build \
  --file logs/cli_history.json \
  --name ecidade-cliente \
  --scope alvo.local \
  --out logs/ecidade-campaign.json
```

## Listar Rotas Testaveis

```bash
./.venv/bin/python scripts/cli.py campaign list \
  --file logs/ecidade-campaign.json
```

## Importar Campanha Salva

```bash
./.venv/bin/python scripts/cli.py campaign import logs/ecidade-campaign.json
```

## Executar Scan em Lote

```bash
./.venv/bin/python scripts/cli.py campaign scan \
  --file logs/ecidade-campaign.json \
  --history-out logs/ecidade-campaign-history.json \
  --report reports/ecidade-campaign.md
```

Para uma primeira validacao sem payloads ativos:

```bash
./.venv/bin/python scripts/cli.py campaign scan \
  --file logs/ecidade-campaign.json \
  --no-active \
  --passive
```

## Observacoes Operacionais

- Confirme o escopo antes de scan ativo em ambiente real.
- Remova rotas destrutivas antes de rodar ativo em producao ou homologacao
  sensivel.
- A campanha salva requests com headers/cookies capturados. Trate o arquivo
  como sensivel.
