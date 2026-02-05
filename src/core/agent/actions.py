"""
Actions - Definição de tipos de ações e estruturas de dados.

Este módulo define os tipos de ação que o agente pode executar
e as estruturas de dados associadas.
"""

from enum import Enum, auto
from dataclasses import dataclass, field, asdict
from typing import Optional, Dict, Any
from datetime import datetime


class ActionType(Enum):
    """Tipos de ação disponíveis para o agente."""
    
    CLICK = auto()
    TYPE = auto()
    NAVIGATE = auto()
    SCROLL = auto()
    WAIT = auto()
    HOVER = auto()
    SELECT = auto()
    PRESS_KEY = auto()
    SCREENSHOT = auto()
    DONE = auto()
    FAILED = auto()


@dataclass
class Action:
    """Representa uma ação a ser executada."""
    
    action_type: ActionType
    selector: Optional[str] = None
    value: Optional[str] = None
    reasoning: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def __str__(self) -> str:
        parts = [self.action_type.name]
        if self.selector:
            parts.append(f"selector={self.selector}")
        if self.value:
            parts.append(f"value={self.value[:30]}...")
        return " ".join(parts)


@dataclass
class ActionResult:
    """Resultado da execução de uma ação."""
    
    success: bool
    action: Action
    error: Optional[str] = None
    new_url: Optional[str] = None
    screenshot_path: Optional[str] = None
    duration_ms: int = 0
    timestamp: Optional[datetime] = None
    
    def __str__(self) -> str:
        status = "✓" if self.success else "✗"
        result = f"{status} {self.action}"
        if self.error:
            result += f" (erro: {self.error[:50]})"
        return result
    
    def to_dict(self) -> Dict[str, Any]:
        """Converte para dicionário serializável."""
        return {
            "success": self.success,
            "action": {
                "action_type": self.action.action_type.name,
                "selector": self.action.selector,
                "value": self.action.value,
                "reasoning": self.action.reasoning,
            },
            "error": self.error,
            "new_url": self.new_url,
            "duration_ms": self.duration_ms,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }


@dataclass
class InteractiveElement:
    """Representa um elemento interativo na página."""
    
    tag: str  # button, a, input, etc.
    element_type: str  # button, link, text, password, etc.
    selector: str  # Seletor CSS único
    text: str = ""  # Texto visível
    name: Optional[str] = None
    id: Optional[str] = None
    placeholder: Optional[str] = None
    value: Optional[str] = None
    is_visible: bool = True
    is_enabled: bool = True
    
    def __str__(self) -> str:
        return f"[{self.element_type}] {self.selector} - {self.text[:30] if self.text else 'N/A'}"
