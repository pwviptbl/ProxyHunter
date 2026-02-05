#!/usr/bin/env python3
"""
ProxyHunter - GitHub Authentication
Implementa autenticação com GitHub Copilot via OAuth Device Flow.
"""

import json
import subprocess
import time
import webbrowser
import requests
from pathlib import Path
from typing import Optional, Dict
from datetime import datetime
import logging

from ..constants import (
    GITHUB_CLIENT_ID,
    GITHUB_DEVICE_CODE_URL,
    GITHUB_ACCESS_TOKEN_URL,
    GITHUB_COPILOT_TOKEN_URL,
    OAUTH_TOKEN_FILE,
    COPILOT_TOKEN_CACHE,
)

log = logging.getLogger(__name__)


class GitHubAuth:
    """
    Gerenciador de autenticação GitHub.
    Suporta:
    1. OAuth Device Flow (recomendado para Copilot)
    2. Token manual (PAT)
    3. Cache do OpenClaw (se disponível)
    4. GitHub CLI (gh auth token)
    """
    
    def __init__(self):
        self.token_data: Optional[Dict] = None
        self.oauth_token: Optional[str] = None
        
        # Tentar carregar token de várias fontes
        self._load_token()
    
    def _load_token(self):
        """Carrega token de múltiplas fontes (em ordem de prioridade)"""
        
        token = None
        source = None
        
        # 1. Cache de OAuth próprio (maior prioridade)
        if OAUTH_TOKEN_FILE.exists():
            try:
                with open(OAUTH_TOKEN_FILE, 'r') as f:
                    data = json.load(f)
                    token = data.get('access_token')
                    if token:
                        source = "OAuth cache"
                        self.oauth_token = token
                        log.debug("Token GitHub carregado de OAuth cache")
            except Exception:
                pass
        
        # 2. Cache do OpenClaw (credenciais compartilhadas)
        if not token:
            openclaw_creds = Path.home() / ".openclaw" / "credentials" / "github-copilot.json"
            if openclaw_creds.exists():
                try:
                    with open(openclaw_creds, 'r') as f:
                        data = json.load(f)
                        token = data.get('token')
                        if token:
                            source = "OpenClaw credentials"
                            self.oauth_token = token
                            log.debug("Token GitHub carregado do OpenClaw")
                except Exception:
                    pass
        
        # 3. GitHub CLI (gh auth token)
        if not token:
            token = self._get_token_from_gh_cli()
            if token:
                source = "GitHub CLI"
                log.debug("Token GitHub obtido via gh CLI")
        
        if token:
            self.token_data = {
                "token": token,
                "source": source,
            }
            log.info(f"GitHub: Autenticado via {source}")
        else:
            self.token_data = None
            log.warning("GitHub: Nenhum token encontrado - Execute authenticate()")
    
    def _get_token_from_gh_cli(self) -> Optional[str]:
        """Tenta obter token do GitHub CLI"""
        try:
            result = subprocess.run(
                ["gh", "auth", "token"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode == 0:
                return result.stdout.strip()
        except Exception:
            pass
        return None
    
    def authenticate(self, use_rich: bool = True) -> bool:
        """
        Inicia autenticação OAuth Device Flow.
        Abre link no navegador para o usuário autorizar.
        
        Args:
            use_rich: Se True, usa rich para output formatado
            
        Returns:
            True se autenticação bem-sucedida
        """
        if use_rich:
            try:
                from rich.console import Console
                console = Console()
            except ImportError:
                use_rich = False
                console = None
        else:
            console = None
        
        def print_msg(msg: str, style: str = ""):
            if console:
                console.print(msg)
            else:
                # Remove tags de estilo para print normal
                import re
                clean = re.sub(r'\[/?[^\]]+\]', '', msg)
                print(clean)
        
        print_msg("\n[bold cyan]🔐 Autenticação GitHub Copilot (OAuth)[/]\n")
        
        try:
            # 1. Solicitar device code
            response = requests.post(
                GITHUB_DEVICE_CODE_URL,
                data={
                    "client_id": GITHUB_CLIENT_ID,
                    "scope": "read:user user:email copilot",
                },
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                timeout=10
            )
            
            if response.status_code != 200:
                print_msg(f"[red]Erro ao iniciar: {response.text}[/]")
                return False
            
            data = response.json()
            device_code = data["device_code"]
            user_code = data["user_code"]
            verification_uri = data["verification_uri"]
            expires_in = data.get("expires_in", 900)
            interval = data.get("interval", 5)
            
            # 2. Mostrar instruções
            print_msg(f"[yellow]1. Acesse:[/] [bold blue]{verification_uri}[/]")
            print_msg(f"[yellow]2. Digite o código:[/] [bold green]{user_code}[/]")
            print_msg(f"\n[dim]O link será aberto automaticamente...[/]")
            
            try:
                webbrowser.open(verification_uri)
            except Exception:
                pass
            
            # 3. Polling para aguardar autorização
            print_msg(f"\n[cyan]Aguardando autorização... (expira em {expires_in//60} min)[/]")
            
            expires_at = time.time() + expires_in
            
            while time.time() < expires_at:
                time.sleep(interval)
                
                token_response = requests.post(
                    GITHUB_ACCESS_TOKEN_URL,
                    data={
                        "client_id": GITHUB_CLIENT_ID,
                        "device_code": device_code,
                        "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                    },
                    headers={
                        "Accept": "application/json",
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                    timeout=10
                )
                
                if token_response.status_code == 200:
                    token_data = token_response.json()
                    
                    if "access_token" in token_data:
                        access_token = token_data["access_token"]
                        
                        # Salvar token
                        self._save_oauth_token(access_token)
                        
                        # Recarregar
                        self._load_token()
                        
                        # Tentar obter Copilot token
                        copilot_token = self._exchange_for_copilot_token(access_token)
                        if copilot_token:
                            print_msg(f"\n[bold green]✓ Autenticado com sucesso![/]")
                            print_msg(f"[green]  Copilot API token obtido[/]")
                        else:
                            print_msg(f"\n[yellow]✓ GitHub autenticado, mas Copilot token não obtido[/]")
                        
                        return True
                    
                    error = token_data.get("error", "")
                    if error == "authorization_pending":
                        print(".", end="", flush=True)
                        continue
                    elif error == "slow_down":
                        interval += 2
                        continue
                    elif error == "expired_token":
                        print_msg("\n[red]Código expirado. Tente novamente.[/]")
                        return False
                    elif error == "access_denied":
                        print_msg("\n[red]Autorização negada.[/]")
                        return False
                    else:
                        print_msg(f"\n[red]Erro: {error}[/]")
                        return False
            
            print_msg("\n[red]Timeout: Autorização expirou[/]")
            return False
            
        except Exception as e:
            print_msg(f"[red]Erro na autenticação: {e}[/]")
            log.error(f"Erro OAuth GitHub: {e}")
            return False
    
    def _save_oauth_token(self, access_token: str):
        """Salva token OAuth"""
        data = {
            "access_token": access_token,
            "created_at": datetime.now().isoformat(),
        }
        try:
            with open(OAUTH_TOKEN_FILE, 'w') as f:
                json.dump(data, f, indent=2)
            log.info("Token OAuth GitHub salvo")
        except Exception as e:
            log.error(f"Erro ao salvar token: {e}")
    
    def _exchange_for_copilot_token(self, oauth_token: str) -> Optional[str]:
        """Troca token OAuth por token do Copilot API"""
        try:
            response = requests.get(
                GITHUB_COPILOT_TOKEN_URL,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"token {oauth_token}",  # Usar 'token' ao invés de 'Bearer'
                    "User-Agent": "GithubCopilot/1.155.0",
                    "Editor-Version": "vscode/1.85.1",
                    "Editor-Plugin-Version": "copilot/1.155.0"
                },
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                token = data.get("token")
                expires_at = data.get("expires_at", 0)
                
                if expires_at < 10_000_000_000:
                    expires_at = expires_at * 1000
                
                # Salvar em cache
                cache_data = {
                    "token": token,
                    "expiresAt": expires_at,
                    "updatedAt": int(time.time() * 1000)
                }
                with open(COPILOT_TOKEN_CACHE, 'w') as f:
                    json.dump(cache_data, f)
                
                log.info("Copilot API token obtido e salvo")
                return token
            else:
                log.warning(f"Copilot token exchange falhou: {response.status_code}")
                return None
                
        except Exception as e:
            log.error(f"Erro ao obter Copilot token: {e}")
            return None
    
    def get_copilot_token(self) -> Optional[str]:
        """
        Obtém token válido para Copilot API.
        Prioridade:
        1. Cache do OpenClaw (token compartilhado)
        2. Cache próprio
        3. Exchange com OAuth token
        """
        # 1. Verificar cache do OpenClaw primeiro (prioridade máxima)
        openclaw_cache = Path.home() / ".openclaw" / "credentials" / "github-copilot.token.json"
        if openclaw_cache.exists():
            try:
                with open(openclaw_cache, 'r') as f:
                    cache = json.load(f)
                    # Token válido por mais 1 minuto?
                    if cache.get('expiresAt', 0) > time.time() * 1000 + 60000:
                        log.debug("Usando token Copilot do OpenClaw cache")
                        return cache.get('token')
            except Exception:
                pass
        
        # 2. Verificar cache próprio
        if COPILOT_TOKEN_CACHE.exists():
            try:
                with open(COPILOT_TOKEN_CACHE, 'r') as f:
                    cache = json.load(f)
                    # Token válido por mais 1 minuto?
                    if cache.get('expiresAt', 0) > time.time() * 1000 + 60000:
                        return cache.get('token')
            except Exception:
                pass
        
        # 3. Cache expirado ou inválido - fazer exchange
        if self.oauth_token:
            copilot_token = self._exchange_for_copilot_token(self.oauth_token)
            if copilot_token:
                return copilot_token
            # Fallback: retorna OAuth token se exchange falhar (403)
            log.warning("Usando OAuth token como fallback (Copilot exchange falhou)")
            return self.oauth_token
        
        return None


    
    def is_authenticated(self) -> bool:
        """Verifica se há uma sessão válida"""
        return self.token_data is not None and 'token' in self.token_data
    
    def has_copilot_access(self) -> bool:
        """Verifica se tem acesso real ao Copilot"""
        # Verificar cache do OpenClaw
        openclaw_cache = Path.home() / ".openclaw" / "credentials" / "github-copilot.token.json"
        if openclaw_cache.exists():
            try:
                with open(openclaw_cache, 'r') as f:
                    cache = json.load(f)
                    if cache.get('expiresAt', 0) > time.time() * 1000 + 60000:
                        return True
            except Exception:
                pass
        
        # Verificar cache próprio
        if COPILOT_TOKEN_CACHE.exists():
            try:
                with open(COPILOT_TOKEN_CACHE, 'r') as f:
                    cache = json.load(f)
                    if cache.get('expiresAt', 0) > time.time() * 1000 + 60000:
                        return True
            except Exception:
                pass
        
        # Tem OAuth token? Pode fazer exchange
        return self.oauth_token is not None
    
    def get_token(self) -> Optional[str]:
        """Retorna o token de autenticação"""
        if self.token_data:
            return self.token_data.get("token")
        return None
    
    def get_oauth_token(self) -> Optional[str]:
        """Retorna token OAuth (para Copilot API)"""
        return self.oauth_token or self.get_token()
    
    def get_status(self) -> str:
        """Retorna o status da conexão"""
        if self.has_copilot_access():
            return "CONNECTED"
        elif self.is_authenticated():
            return "TOKEN_ONLY"
        return "DISCONNECTED"
    
    def get_plan_info(self) -> str:
        """Retorna informações do plano"""
        if self.has_copilot_access():
            source = self.token_data.get("source", "Unknown") if self.token_data else "cache"
            return f"Copilot Active (via {source})"
        elif self.is_authenticated():
            return "⚠️ Token inválido - Execute authenticate()"
        return "Não autenticado"
    
    def logout(self):
        """Remove credenciais"""
        for f in [OAUTH_TOKEN_FILE, COPILOT_TOKEN_CACHE]:
            if f.exists():
                f.unlink()
        self.token_data = None
        self.oauth_token = None
        log.info("Credenciais GitHub removidas")
