#!/bin/bash

# ProxyHunter CLI Launcher Script for Linux/Mac
# Este script cria um ambiente virtual, instala dependencias e inicia a CLI

echo "Iniciando ProxyHunter CLI..."

# Verifica suporte a venv (ensurepip)
if ! python3 -c "import ensurepip" >/dev/null 2>&1; then
    echo "O modulo ensurepip nao esta disponivel."
    if command -v apt-get >/dev/null 2>&1; then
        PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        VENV_PKG="python${PY_VER}-venv"
        echo "Instalando dependencia do venv: ${VENV_PKG} (ou python3-venv)..."
        if command -v sudo >/dev/null 2>&1; then
            sudo apt-get install -y "${VENV_PKG}" python3-venv || true
        else
            apt-get install -y "${VENV_PKG}" python3-venv || true
        fi
    else
        echo "Instale o pacote de venv (ex.: python3-venv) e tente novamente."
        exit 1
    fi
fi

# Cria o ambiente virtual se nao existir
if [ ! -d ".venv" ]; then
    echo "Criando ambiente virtual..."
    python3 -m venv .venv
    if [ $? -ne 0 ]; then
        echo "Falha ao criar o ambiente virtual"
        exit 1
    fi
fi

echo "Ambiente virtual encontrado, ativando..."
source .venv/bin/activate
if [ $? -ne 0 ]; then
    echo "Falha ao ativar o ambiente virtual"
    exit 1
fi

echo "Atualizando pip..."
python -m pip install --upgrade pip
if [ $? -ne 0 ]; then
    echo "Falha ao atualizar o pip"
    exit 1
fi

echo "Instalando/atualizando dependencias..."
pip install -r config/requirements.txt
if [ $? -ne 0 ]; then
    echo "Falha ao instalar as dependencias"
    exit 1
fi

echo "Iniciando ProxyHunter CLI..."
python scripts/cli.py "$@"
