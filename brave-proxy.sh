#!/bin/bash

# ─────────────────────────────────────────────────────────────
#  brave-proxy.sh — Abre o Brave com o proxy do ProxyHunter
#  Configura o proxy a nível do sistema (gsettings) para que
#  toda navegação, incluindo HTTPS, seja interceptada.
# ─────────────────────────────────────────────────────────────

PROXY_HOST="127.0.0.1"
PROXY_PORT="${1:-9507}"

echo "🔧  Configurando proxy do sistema → ${PROXY_HOST}:${PROXY_PORT} ..."

# ── Salva as configurações atuais de proxy para restaurar depois ──
SAVED_MODE=$(gsettings get org.gnome.system.proxy mode 2>/dev/null)
SAVED_HTTP_HOST=$(gsettings get org.gnome.system.proxy.http host 2>/dev/null)
SAVED_HTTP_PORT=$(gsettings get org.gnome.system.proxy.http port 2>/dev/null)
SAVED_HTTPS_HOST=$(gsettings get org.gnome.system.proxy.https host 2>/dev/null)
SAVED_HTTPS_PORT=$(gsettings get org.gnome.system.proxy.https port 2>/dev/null)

restore_proxy() {
    echo ""
    echo "♻️   Restaurando configurações de proxy originais..."
    gsettings set org.gnome.system.proxy mode "${SAVED_MODE:-'none'}"
    gsettings set org.gnome.system.proxy.http host "${SAVED_HTTP_HOST:-''}"
    gsettings set org.gnome.system.proxy.http port "${SAVED_HTTP_PORT:-8080}"
    gsettings set org.gnome.system.proxy.https host "${SAVED_HTTPS_HOST:-''}"
    gsettings set org.gnome.system.proxy.https port "${SAVED_HTTPS_PORT:-8080}"
    echo "✅  Proxy do sistema restaurado."
}

# Restaura ao pressionar Ctrl+C ou quando o script terminar
trap restore_proxy EXIT INT TERM

# ── Aplica proxy do ProxyHunter no sistema ──
gsettings set org.gnome.system.proxy mode 'manual'
gsettings set org.gnome.system.proxy.http host "${PROXY_HOST}"
gsettings set org.gnome.system.proxy.http port "${PROXY_PORT}"
gsettings set org.gnome.system.proxy.https host "${PROXY_HOST}"
gsettings set org.gnome.system.proxy.https port "${PROXY_PORT}"
gsettings set org.gnome.system.proxy ignore-hosts "['localhost', '127.0.0.0/8', '::1']"

echo "✅  Proxy do sistema configurado!"

# ── Verifica se o Brave está instalado ──
if ! command -v brave-browser &>/dev/null; then
    echo "❌  brave-browser não encontrado."
    exit 1
fi

# ── Fecha instâncias existentes do Brave ──
if pgrep -x "brave" &>/dev/null || pgrep -f "brave-browser" &>/dev/null; then
    echo "⚠️   Fechando instâncias existentes do Brave..."
    pkill -f brave-browser 2>/dev/null
    sleep 1.5
fi

# ── Abre o Brave sem flags de proxy (usa o do sistema) ──
echo "🦁  Abrindo Brave..."
brave-browser --ignore-certificate-errors --no-first-run

# O 'trap restore_proxy EXIT' cuida de restaurar ao fechar o Brave
