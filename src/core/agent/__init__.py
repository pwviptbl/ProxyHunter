# Módulo Agent - Navegação Autônoma Inteligente
"""
Este módulo contém os componentes para navegação autônoma
com suporte a LLM para tomada de decisão contextual.
"""

from .actions import Action, ActionType, ActionResult, InteractiveElement
from .browser_vision import BrowserVision, PageState
from .action_executor import ActionExecutor
from .session_memory import SessionMemory
from .decision_agent import DecisionAgent, LLMConfig
from .autonomous_agent import AutonomousAgent

__all__ = [
    "Action",
    "ActionType", 
    "ActionResult",
    "InteractiveElement",
    "BrowserVision",
    "PageState",
    "ActionExecutor",
    "SessionMemory",
    "DecisionAgent",
    "LLMConfig",
    "AutonomousAgent",
]
