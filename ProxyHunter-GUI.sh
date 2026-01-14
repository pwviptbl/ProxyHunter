#!/bin/bash

# ProxyHunter Launcher Script for Linux/Mac
# Este script cria um ambiente virtual, instala dependências e inicia a aplicação

echo "🚀 Iniciando ProxyHunter ..."

# Verifica suporte a venv (ensurepip)
if ! python3 -c "import ensurepip" >/dev/null 2>&1; then
    echo "⚠️  O módulo ensurepip não está disponível."
    if command -v apt-get >/dev/null 2>&1; then
        PY_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
        VENV_PKG="python${PY_VER}-venv"
        echo "📦 Instalando dependência do venv: ${VENV_PKG} (ou python3-venv)..."
        if command -v sudo >/dev/null 2>&1; then
            sudo apt-get install -y "${VENV_PKG}" python3-venv || true
        else
            apt-get install -y "${VENV_PKG}" python3-venv || true
        fi
    else
        echo "❌ Instale o pacote de venv (ex.: python3-venv) e tente novamente."
        exit 1
    fi
fi

# Modo seguro para contornar crashes de drivers/GL
if [ "${PROXYHUNTER_SAFE_MODE}" = "1" ]; then
    echo "🛡️  Modo seguro ativo: forçando renderização por software..."
    export QT_OPENGL=software
    export LIBGL_ALWAYS_SOFTWARE=1
fi

# Cria o ambiente virtual se não existir
if [ ! -d ".venv" ]; then
    echo "📦 Criando ambiente virtual..."
    python3 -m venv .venv
    if [ $? -ne 0 ]; then
        echo "❌ Falha ao criar o ambiente virtual"
        exit 1
    fi
fi

echo "✅ Ambiente virtual encontrado, ativando..."
source .venv/bin/activate
if [ $? -ne 0 ]; then
    echo "❌ Falha ao ativar o ambiente virtual"
    exit 1
fi

echo "📦 Atualizando pip..."
python -m pip install --upgrade pip
if [ $? -ne 0 ]; then
    echo "❌ Falha ao atualizar o pip"
    exit 1
fi

echo "📥 Instalando/atualizando dependências..."
pip install -r config/requirements.txt
if [ $? -ne 0 ]; then
    echo "❌ Falha ao instalar as dependências"
    exit 1
fi

# Verifica o arquivo de configuração da IA
AI_CONFIG="config/ai_config.json"
AI_CONFIG_EXAMPLE="config/ai_config.example.json"

if [ ! -f "$AI_CONFIG" ]; then
    echo "🔧 Arquivo de configuração da IA não encontrado. Copiando do exemplo..."
    cp "$AI_CONFIG_EXAMPLE" "$AI_CONFIG"
fi

# Inicia a aplicação
echo "🎯 Iniciando ProxyHunter..."
python scripts/pyside_proxy.py
