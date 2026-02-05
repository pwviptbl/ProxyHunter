#!/usr/bin/env python3
"""
ProxyHunter - Constantes Globais
Contém constantes de configuração do sistema.
"""

import os
from pathlib import Path

# Diretório base do projeto
BASE_DIR = Path(__file__).parent.parent.parent.absolute()

# ============================================================================
# GITHUB OAUTH CONFIGURATION
# ============================================================================

# OAuth Client ID do VSCode Copilot (OpenClaw/VSCode)
GITHUB_CLIENT_ID = "Iv1.b507a08c87ecfe98"

# URLs de autenticação GitHub
GITHUB_DEVICE_CODE_URL = "https://github.com/login/device/code"
GITHUB_ACCESS_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_COPILOT_TOKEN_URL = "https://api.github.com/copilot_internal/v2/token"

# Arquivos de cache de tokens
OAUTH_TOKEN_FILE = BASE_DIR / ".github_oauth_token.json"
COPILOT_TOKEN_CACHE = BASE_DIR / ".copilot_token_cache.json"

# ============================================================================
# MODELOS DISPONÍVEIS VIA GITHUB COPILOT
# ============================================================================

GITHUB_COPILOT_MODELS = {
    # Stage 1 - Pré-processamento (gratuitos / baratos)
    "gpt-4o": {
        "name": "GPT-4o",
        "cost_multiplier": 0,
        "description": "Rápido, gratuito, bom para contexto básico"
    },
    "gpt-4.1": {
        "name": "GPT-4.1", 
        "cost_multiplier": 0,
        "description": "Gratuito, boa capacidade de organização"
    },
    "gpt-5-mini": {
        "name": "GPT-5 Mini",
        "cost_multiplier": 0,
        "description": "Gratuito, otimizado para tarefas leves"
    },
    "claude-haiku-4.5": {
        "name": "Claude Haiku 4.5",
        "cost_multiplier": 0.33,
        "description": "Rápido, barato, excelente para organizar contexto"
    },
    "gemini-3-flash": {
        "name": "Gemini 3 Flash",
        "cost_multiplier": 0.33,
        "description": "Large context 1M tokens"
    },
    
    # Stage 2 - Modelos principais
    "claude-sonnet-4": {
        "name": "Claude Sonnet 4",
        "cost_multiplier": 1,
        "description": "Raciocínio equilibrado, bom custo-benefício"
    },
    "gemini-2.5-pro": {
        "name": "Gemini 2.5 Pro",
        "cost_multiplier": 1,
        "description": "Multimodal, bom para análise de imagens"
    },
    "gpt-5": {
        "name": "GPT-5",
        "cost_multiplier": 1,
        "description": "Modelo principal da OpenAI"
    },
}
