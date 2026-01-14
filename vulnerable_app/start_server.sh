#!/bin/bash

VENV_DIR="./venv"

# Verifica se o python3 ou python estao disponiveis
if command -v python3 &>/dev/null; then
    PYTHON_CMD=python3
elif command -v python &>/dev/null; then
    PYTHON_CMD=python
else
    echo "Python nao encontrado. Por favor, instale Python 3."
    exit 1
fi

# Verifica se o diretorio do venv existe
if [ ! -d "$VENV_DIR" ]; then
    echo "Ambiente virtual nao encontrado. Criando..."
    $PYTHON_CMD -m venv $VENV_DIR
fi

echo "Ativando ambiente virtual..."
source "$VENV_DIR/bin/activate"

echo "Instalando dependencias..."
pip install -r requirements.txt

echo "Iniciando o servidor vulneravel..."
$PYTHON_CMD vulnerable_server.py