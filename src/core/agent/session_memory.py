"""
SessionMemory - Memória persistente da sessão de navegação.

Este módulo gerencia o armazenamento de:
- Credenciais usadas
- Rotas descobertas
- Histórico de ações
- Estado da sessão para retomar depois
"""

import json
import os
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path


@dataclass
class DiscoveredRoute:
    """Representa uma rota descoberta durante navegação."""
    
    url: str
    method: str = "GET"
    status_code: Optional[int] = None
    title: Optional[str] = None
    discovered_at: str = field(default_factory=lambda: datetime.now().isoformat())
    from_action: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SessionState:
    """Estado completo de uma sessão de navegação."""
    
    session_id: str
    target_url: str
    objective: str
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    last_updated: str = field(default_factory=lambda: datetime.now().isoformat())
    current_url: Optional[str] = None
    
    # Contadores
    actions_count: int = 0
    pages_visited: int = 0
    forms_submitted: int = 0
    
    # Estado
    is_authenticated: bool = False
    status: str = "running"  # running, completed, failed, paused
    
    # Dados coletados
    routes: List[Dict] = field(default_factory=list)
    cookies: List[Dict] = field(default_factory=list)
    action_history: List[Dict] = field(default_factory=list)
    
    # Erros
    last_error: Optional[str] = None


class SessionMemory:
    """
    Gerencia memória persistente da sessão de navegação.
    
    Responsável por:
    - Armazenar credenciais em memória (não persiste senhas)
    - Manter mapa de rotas descobertas
    - Salvar/carregar estado de sessão
    - Evitar loops (tracking de ações)
    """
    
    def __init__(
        self,
        session_id: str,
        target_url: str,
        objective: str,
        storage_dir: Optional[str] = None,
    ):
        """
        Args:
            session_id: Identificador único da sessão
            target_url: URL alvo da navegação
            objective: Objetivo da sessão
            storage_dir: Diretório para persistência (opcional)
        """
        self.session_id = session_id
        self.target_url = target_url
        self.objective = objective
        
        # Diretório de armazenamento
        if storage_dir:
            self.storage_dir = Path(storage_dir)
        else:
            self.storage_dir = Path.home() / ".proxyhunter" / "sessions"
        
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        # Estado da sessão
        self.state = SessionState(
            session_id=session_id,
            target_url=target_url,
            objective=objective,
        )
        
        # Credenciais (apenas em memória, não persistidas)
        self._credentials: Dict[str, Dict[str, str]] = {}
        
        # Set de URLs visitadas para evitar loops
        self._visited_urls: set = set()
        
        # Set de assinaturas de ação para detectar loops
        self._action_signatures: List[str] = []
    
    def store_credentials(self, url: str, username: str, password: str):
        """
        Armazena credenciais para um URL.
        
        As credenciais são mantidas apenas em memória por segurança.
        """
        self._credentials[url] = {
            "username": username,
            "password": password,
        }
    
    def get_credentials(self, url: str) -> Optional[Dict[str, str]]:
        """Recupera credenciais para um URL."""
        return self._credentials.get(url)
    
    def add_route(
        self,
        url: str,
        method: str = "GET",
        status_code: Optional[int] = None,
        title: Optional[str] = None,
        from_action: Optional[str] = None,
    ):
        """Registra uma rota descoberta."""
        route = DiscoveredRoute(
            url=url,
            method=method,
            status_code=status_code,
            title=title,
            from_action=from_action,
        )
        
        # Evita duplicatas
        existing_urls = [r.get("url") for r in self.state.routes]
        if url not in existing_urls:
            self.state.routes.append(asdict(route))
            self._visited_urls.add(url)
    
    def add_action(self, action_result: dict):
        """Registra uma ação executada."""
        self.state.action_history.append(action_result)
        self.state.actions_count += 1
        self.state.last_updated = datetime.now().isoformat()
        
        # Cria assinatura para detecção de loop
        action = action_result.get("action", {})
        signature = f"{action.get('action_type')}:{action.get('selector')}:{action.get('value')}"
        self._action_signatures.append(signature)
    
    def is_url_visited(self, url: str) -> bool:
        """Verifica se URL já foi visitada."""
        return url in self._visited_urls
    
    def detect_loop(self, window_size: int = 5) -> bool:
        """
        Detecta se o agente está em loop.
        
        Verifica se as últimas N ações são repetição das anteriores.
        """
        if len(self._action_signatures) < window_size * 2:
            return False
        
        recent = self._action_signatures[-window_size:]
        previous = self._action_signatures[-window_size * 2:-window_size]
        
        return recent == previous
    
    def get_route_count(self) -> int:
        """Retorna número de rotas descobertas."""
        return len(self.state.routes)
    
    def get_routes(self) -> List[Dict]:
        """Retorna todas as rotas descobertas."""
        return self.state.routes
    
    def set_authenticated(self, authenticated: bool = True):
        """Marca sessão como autenticada."""
        self.state.is_authenticated = authenticated
    
    def update_current_url(self, url: str):
        """Atualiza URL atual."""
        self.state.current_url = url
        self.state.last_updated = datetime.now().isoformat()
    
    def increment_pages(self):
        """Incrementa contador de páginas visitadas."""
        self.state.pages_visited += 1
    
    def increment_forms(self):
        """Incrementa contador de formulários submetidos."""
        self.state.forms_submitted += 1
    
    def set_status(self, status: str):
        """Define status da sessão."""
        self.state.status = status
        self.state.last_updated = datetime.now().isoformat()
    
    def set_error(self, error: str):
        """Registra último erro."""
        self.state.last_error = error
    
    def store_cookies(self, cookies: List[Dict]):
        """Armazena cookies da sessão."""
        self.state.cookies = cookies
    
    def save(self) -> str:
        """
        Persiste estado da sessão em arquivo.
        
        Returns:
            Caminho do arquivo salvo
        """
        file_path = self.storage_dir / f"{self.session_id}.json"
        
        # Não persiste credenciais por segurança
        state_dict = asdict(self.state)
        
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(state_dict, f, indent=2, ensure_ascii=False)
        
        return str(file_path)
    
    @classmethod
    def load(cls, session_id: str, storage_dir: Optional[str] = None) -> "SessionMemory":
        """
        Carrega sessão salva do disco.
        
        Args:
            session_id: ID da sessão a carregar
            storage_dir: Diretório de armazenamento
            
        Returns:
            SessionMemory com estado restaurado
        """
        if storage_dir:
            base_dir = Path(storage_dir)
        else:
            base_dir = Path.home() / ".proxyhunter" / "sessions"
        
        file_path = base_dir / f"{session_id}.json"
        
        if not file_path.exists():
            raise FileNotFoundError(f"Sessão não encontrada: {session_id}")
        
        with open(file_path, "r", encoding="utf-8") as f:
            state_dict = json.load(f)
        
        # Cria instância e restaura estado
        memory = cls(
            session_id=session_id,
            target_url=state_dict.get("target_url", ""),
            objective=state_dict.get("objective", ""),
            storage_dir=storage_dir,
        )
        
        memory.state = SessionState(**state_dict)
        memory._visited_urls = set(r.get("url") for r in memory.state.routes)
        
        return memory
    
    def get_summary(self) -> Dict[str, Any]:
        """Retorna resumo da sessão para relatório."""
        return {
            "session_id": self.session_id,
            "target_url": self.target_url,
            "objective": self.objective,
            "status": self.state.status,
            "is_authenticated": self.state.is_authenticated,
            "actions_count": self.state.actions_count,
            "pages_visited": self.state.pages_visited,
            "forms_submitted": self.state.forms_submitted,
            "routes_discovered": len(self.state.routes),
            "started_at": self.state.started_at,
            "last_updated": self.state.last_updated,
        }
    
    def get_recent_actions(self, count: int = 10) -> List[Dict]:
        """Retorna últimas N ações."""
        return self.state.action_history[-count:]
