"""
DecisionAgent - Cérebro do agente autônomo.

Este módulo contém a lógica de tomada de decisão baseada em LLM.
Recebe o estado da página e decide a próxima ação.
"""

import json
import re
from typing import List, Optional, Tuple
from dataclasses import dataclass

from .actions import Action, ActionType, ActionResult, InteractiveElement
from .browser_vision import PageState
from .prompts import SYSTEM_PROMPT, build_decision_prompt, build_login_context


@dataclass
class LLMConfig:
    """Configuração do cliente LLM."""
    
    provider: str = "gemini"  # gemini, openai, ollama
    api_key: str = ""
    model: str = "gemini-2.0-flash"
    temperature: float = 0.3
    max_tokens: int = 1024
    timeout: int = 30


class DecisionAgent:
    """
    Usa LLM para decidir a próxima ação baseado no contexto.
    
    Responsável por:
    - Construir prompts com estado da página
    - Chamar API do LLM
    - Parsear resposta em ação executável
    - Validar ações decididas
    - Detectar loops e forçar mudança de estratégia
    """
    
    def __init__(
        self,
        objective: str,
        llm_config: LLMConfig,
        credentials: Optional[Tuple[str, str]] = None,
        max_history: int = 10,
    ):
        """
        Args:
            objective: Objetivo da navegação
            llm_config: Configuração do LLM
            credentials: Tupla (username, password) se disponível
            max_history: Máximo de ações no histórico para contexto
        """
        self.objective = objective
        self.llm_config = llm_config
        self.credentials = credentials
        self.max_history = max_history
        
        # Histórico de ações para contexto
        self.action_history: List[ActionResult] = []
        
        # Cliente LLM (lazy initialization)
        self._llm_client = None
        
        # Contador de falhas consecutivas para anti-loop
        self._consecutive_failures = 0
        self._last_failed_selector = None
        self._failed_selectors: set = set()
    
    async def decide_next_action(
        self,
        page_state: PageState,
        retry_count: int = 0,
    ) -> Action:
        """
        Decide a próxima ação baseado no estado da página.
        
        Args:
            page_state: Estado atual da página
            retry_count: Número de tentativas (para fallback)
            
        Returns:
            Action a ser executada
        """
        # Verifica se está em loop de falhas - RECUPERAÇÃO RÁPIDA após 2 falhas
        if self._consecutive_failures >= 2:
            self._consecutive_failures = 0
            return self._get_recovery_action(page_state)
        
        # Constrói contexto adicional
        context = ""
        if self.credentials and self._looks_like_login(page_state):
            context = build_login_context(
                self.credentials[0],
                self.credentials[1],
            )
        
        # Adiciona contexto sobre seletores que falharam
        if self._failed_selectors:
            context += f"\n\nSELETORES QUE NÃO FUNCIONARAM (evite usar):\n"
            for sel in list(self._failed_selectors)[-5:]:
                context += f"- {sel}\n"
        
        # Constrói prompt
        prompt = build_decision_prompt(
            objective=self.objective,
            current_url=page_state.url,
            page_title=page_state.title,
            elements=page_state.elements,
            action_history=self.action_history,
            context=context,
            max_history=self.max_history,
        )
        
        # Chama LLM
        try:
            response = await self._call_llm(prompt)
            action = self._parse_response(response)
            
            # Verifica se selector já falhou antes - força alternativa
            if action.selector and action.selector in self._failed_selectors:
                if retry_count < 2:
                    return await self.decide_next_action(page_state, retry_count + 1)
                return self._get_recovery_action(page_state)
            
            # Valida ação
            if self._is_valid_action(action, page_state):
                return action
            
            # Se inválida e primeira tentativa, tenta novamente
            if retry_count < 2:
                return await self.decide_next_action(page_state, retry_count + 1)
            
            # Fallback: scroll ou wait
            return Action(
                action_type=ActionType.SCROLL,
                value="down",
                reasoning="Fallback: ação anterior inválida",
            )
            
        except Exception as e:
            # Em caso de erro, retorna ação segura
            return Action(
                action_type=ActionType.WAIT,
                value="2",
                reasoning=f"Erro ao decidir: {e}",
            )
    
    def update_history(self, result: ActionResult):
        """Atualiza histórico com resultado da ação."""
        self.action_history.append(result)
        
        # Atualiza contadores de falha para anti-loop
        if not result.success:
            self._consecutive_failures += 1
            if result.action.selector:
                self._last_failed_selector = result.action.selector
                self._failed_selectors.add(result.action.selector)
        else:
            self._consecutive_failures = 0
        
        # Limita tamanho do histórico
        if len(self.action_history) > self.max_history * 2:
            self.action_history = self.action_history[-self.max_history:]
        
        # Limita seletores que falharam para não crescer demais
        if len(self._failed_selectors) > 20:
            self._failed_selectors = set(list(self._failed_selectors)[-10:])
    
    def _get_recovery_action(self, page_state: PageState) -> Action:
        """
        Retorna uma ação de recuperação quando em loop de falhas.
        
        Estratégia: Voltar para a home e explorar outra área.
        """
        from urllib.parse import urlparse
        
        # Extrai URL base (home)
        try:
            parsed = urlparse(page_state.url)
            base_url = f"{parsed.scheme}://{parsed.netloc}/"
            
            # Se não estamos na home, volta para lá
            if page_state.url != base_url and page_state.url != base_url.rstrip('/'):
                return Action(
                    action_type=ActionType.NAVIGATE,
                    value=base_url,
                    reasoning="Recuperação: voltando para home após falhas - explorar outra área",
                )
        except Exception:
            pass
        
        # Se estamos na home, tenta clicar em um botão/link diferente
        buttons = [el for el in page_state.elements 
                   if el.element_type == "button" and el.selector not in self._failed_selectors]
        if buttons:
            return Action(
                action_type=ActionType.CLICK,
                selector=buttons[0].selector,
                reasoning="Recuperação: tentando botão diferente na home",
            )
        
        # Se há links não visitados, clica em um
        links = [el for el in page_state.elements 
                 if el.element_type == "link" and el.selector not in self._failed_selectors]
        if links:
            return Action(
                action_type=ActionType.CLICK,
                selector=links[0].selector,
                reasoning="Recuperação: explorando link diferente",
            )
        
        # Último recurso: scroll
        return Action(
            action_type=ActionType.SCROLL,
            value="down",
            reasoning="Recuperação: scroll para encontrar mais elementos",
        )
    
    async def _call_llm(self, prompt: str) -> str:
        """
        Chama API do LLM.
        
        Suporta múltiplos providers: Gemini, OpenAI, Ollama.
        """
        provider = self.llm_config.provider.lower()
        
        if provider == "gemini":
            return await self._call_gemini(prompt)
        elif provider == "openai":
            return await self._call_openai(prompt)
        elif provider == "ollama":
            return await self._call_ollama(prompt)
        else:
            raise ValueError(f"Provider não suportado: {provider}")
    
    async def _call_gemini(self, prompt: str) -> str:
        """Chama API do Google Gemini usando a nova biblioteca google-genai."""
        try:
            from google import genai
            from google.genai import types
            
            if not self._llm_client:
                self._llm_client = genai.Client(api_key=self.llm_config.api_key)
            
            response = self._llm_client.models.generate_content(
                model=self.llm_config.model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=SYSTEM_PROMPT,
                    temperature=self.llm_config.temperature,
                    max_output_tokens=self.llm_config.max_tokens,
                ),
            )
            
            return response.text
            
        except ImportError:
            # Fallback para biblioteca antiga se nova não estiver instalada
            try:
                import google.generativeai as genai
                
                if not self._llm_client:
                    genai.configure(api_key=self.llm_config.api_key)
                    self._llm_client = genai.GenerativeModel(
                        model_name=self.llm_config.model,
                        system_instruction=SYSTEM_PROMPT,
                    )
                
                response = self._llm_client.generate_content(
                    prompt,
                    generation_config={
                        "temperature": self.llm_config.temperature,
                        "max_output_tokens": self.llm_config.max_tokens,
                    },
                )
                
                return response.text
                
            except ImportError:
                raise ImportError(
                    "Biblioteca Gemini não instalada. Execute:\n"
                    "  pip install google-genai  (recomendado)\n"
                    "ou:\n"
                    "  pip install google-generativeai  (depreciado)"
                )
    
    async def _call_openai(self, prompt: str) -> str:
        """Chama API da OpenAI."""
        try:
            import openai
            
            if not self._llm_client:
                self._llm_client = openai.AsyncOpenAI(api_key=self.llm_config.api_key)
            
            response = await self._llm_client.chat.completions.create(
                model=self.llm_config.model,
                messages=[
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                temperature=self.llm_config.temperature,
                max_tokens=self.llm_config.max_tokens,
            )
            
            return response.choices[0].message.content
            
        except ImportError:
            raise ImportError("openai não instalado. Execute: pip install openai")
    
    async def _call_ollama(self, prompt: str) -> str:
        """Chama Ollama local."""
        try:
            import httpx
            
            async with httpx.AsyncClient(timeout=self.llm_config.timeout) as client:
                response = await client.post(
                    "http://localhost:11434/api/generate",
                    json={
                        "model": self.llm_config.model,
                        "prompt": f"{SYSTEM_PROMPT}\n\n{prompt}",
                        "stream": False,
                        "options": {
                            "temperature": self.llm_config.temperature,
                        },
                    },
                )
                response.raise_for_status()
                data = response.json()
                return data.get("response", "")
                
        except Exception as e:
            raise RuntimeError(f"Erro ao chamar Ollama: {e}")
    
    def _parse_response(self, response: str) -> Action:
        """
        Parseia resposta do LLM em Action.
        
        Espera JSON no formato:
        {
            "reasoning": "...",
            "action": "click|type|...",
            "selector": "...",
            "value": "..."
        }
        """
        # Extrai JSON da resposta (pode ter texto adicional)
        json_match = re.search(r'\{[^{}]*\}', response, re.DOTALL)
        
        if not json_match:
            return Action(
                action_type=ActionType.WAIT,
                value="1",
                reasoning=f"Resposta sem JSON: {response[:100]}",
            )
        
        try:
            data = json.loads(json_match.group())
        except json.JSONDecodeError as e:
            return Action(
                action_type=ActionType.WAIT,
                value="1",
                reasoning=f"JSON inválido: {e}",
            )
        
        # Mapeia action string para ActionType
        action_str = data.get("action", "").lower()
        action_type = self._parse_action_type(action_str)
        
        return Action(
            action_type=action_type,
            selector=data.get("selector"),
            value=data.get("value"),
            reasoning=data.get("reasoning", ""),
        )
    
    def _parse_action_type(self, action_str: str) -> ActionType:
        """Converte string de ação para ActionType."""
        mapping = {
            "click": ActionType.CLICK,
            "type": ActionType.TYPE,
            "navigate": ActionType.NAVIGATE,
            "scroll": ActionType.SCROLL,
            "wait": ActionType.WAIT,
            "hover": ActionType.HOVER,
            "select": ActionType.SELECT,
            "press_key": ActionType.PRESS_KEY,
            "done": ActionType.DONE,
            "failed": ActionType.FAILED,
        }
        return mapping.get(action_str, ActionType.WAIT)
    
    def _is_valid_action(self, action: Action, page_state: PageState) -> bool:
        """Valida se ação é executável."""
        # Ações que sempre são válidas
        if action.action_type in (
            ActionType.WAIT,
            ActionType.SCROLL,
            ActionType.NAVIGATE,
            ActionType.DONE,
            ActionType.FAILED,
        ):
            return True
        
        # Ações que precisam de selector
        if action.action_type in (
            ActionType.CLICK,
            ActionType.TYPE,
            ActionType.HOVER,
            ActionType.SELECT,
        ):
            if not action.selector:
                return False
        
        # TYPE precisa de value
        if action.action_type == ActionType.TYPE:
            if not action.value:
                return False
        
        return True
    
    def _looks_like_login(self, page_state: PageState) -> bool:
        """Detecta se página parece ser de login."""
        indicators = [
            "login", "signin", "sign-in", "entrar", "acesso",
            "password", "senha", "credentials", "auth",
        ]
        
        # Verifica URL
        url_lower = page_state.url.lower()
        if any(ind in url_lower for ind in indicators):
            return True
        
        # Verifica título
        title_lower = (page_state.title or "").lower()
        if any(ind in title_lower for ind in indicators):
            return True
        
        # Verifica elementos (campo de senha presente)
        for el in page_state.elements:
            if el.element_type == "password":
                return True
        
        return False
