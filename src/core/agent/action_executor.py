"""
ActionExecutor - Execução de ações no navegador.

Este módulo é responsável por executar as ações decididas
pelo DecisionAgent no navegador via Playwright.
"""

import asyncio
import time
from typing import Optional
from datetime import datetime

from .actions import Action, ActionType, ActionResult


class ActionExecutor:
    """
    Executa ações no navegador via Playwright.
    
    Responsável por:
    - Traduzir ações em comandos Playwright
    - Lidar com timeouts e erros
    - Reportar resultados de forma estruturada
    """
    
    def __init__(
        self,
        default_timeout: int = 15000,
        navigation_timeout: int = 30000,
    ):
        """
        Args:
            default_timeout: Timeout padrão para ações (ms)
            navigation_timeout: Timeout para navegação (ms)
        """
        self.default_timeout = default_timeout
        self.navigation_timeout = navigation_timeout
    
    async def execute(self, page, action: Action) -> ActionResult:
        """
        Executa uma ação no navegador.
        
        Args:
            page: Objeto Page do Playwright
            action: Ação a ser executada
            
        Returns:
            ActionResult com sucesso/falha e detalhes
        """
        start_time = time.time()
        
        try:
            # Dispatch baseado no tipo de ação
            if action.action_type == ActionType.CLICK:
                result = await self._execute_click(page, action)
            elif action.action_type == ActionType.TYPE:
                result = await self._execute_type(page, action)
            elif action.action_type == ActionType.NAVIGATE:
                result = await self._execute_navigate(page, action)
            elif action.action_type == ActionType.SCROLL:
                result = await self._execute_scroll(page, action)
            elif action.action_type == ActionType.WAIT:
                result = await self._execute_wait(page, action)
            elif action.action_type == ActionType.HOVER:
                result = await self._execute_hover(page, action)
            elif action.action_type == ActionType.SELECT:
                result = await self._execute_select(page, action)
            elif action.action_type == ActionType.PRESS_KEY:
                result = await self._execute_press_key(page, action)
            elif action.action_type == ActionType.SCREENSHOT:
                result = await self._execute_screenshot(page, action)
            elif action.action_type in (ActionType.DONE, ActionType.FAILED):
                result = ActionResult(
                    success=action.action_type == ActionType.DONE,
                    action=action,
                    new_url=page.url,
                )
            else:
                result = ActionResult(
                    success=False,
                    action=action,
                    error=f"Tipo de ação não suportado: {action.action_type}",
                )
            
            # Calcula duração
            duration_ms = int((time.time() - start_time) * 1000)
            result.duration_ms = duration_ms
            result.timestamp = datetime.now()
            
            return result
            
        except Exception as e:
            duration_ms = int((time.time() - start_time) * 1000)
            return ActionResult(
                success=False,
                action=action,
                error=str(e),
                duration_ms=duration_ms,
                timestamp=datetime.now(),
            )
    
    async def _execute_click(self, page, action: Action) -> ActionResult:
        """Executa clique em elemento."""
        if not action.selector:
            return ActionResult(
                success=False,
                action=action,
                error="Selector não fornecido para ação CLICK",
            )
        
        try:
            # Aguarda elemento estar visível e clicável
            await page.wait_for_selector(
                action.selector,
                state="visible",
                timeout=self.default_timeout,
            )
            
            # Clica no elemento
            await page.click(action.selector, timeout=self.default_timeout)
            
            # Aguarda possível navegação
            await self._wait_for_stable(page)
            
            return ActionResult(
                success=True,
                action=action,
                new_url=page.url,
            )
            
        except Exception as e:
            return ActionResult(
                success=False,
                action=action,
                error=f"Falha ao clicar em {action.selector}: {e}",
            )
    
    async def _execute_type(self, page, action: Action) -> ActionResult:
        """Digita texto em campo."""
        if not action.selector:
            return ActionResult(
                success=False,
                action=action,
                error="Selector não fornecido para ação TYPE",
            )
        
        try:
            # Aguarda elemento
            await page.wait_for_selector(
                action.selector,
                state="visible",
                timeout=self.default_timeout,
            )
            
            # Limpa campo antes de digitar
            await page.fill(action.selector, "")
            
            # Digita texto
            await page.fill(action.selector, action.value or "")
            
            return ActionResult(
                success=True,
                action=action,
                new_url=page.url,
            )
            
        except Exception as e:
            return ActionResult(
                success=False,
                action=action,
                error=f"Falha ao digitar em {action.selector}: {e}",
            )
    
    async def _execute_navigate(self, page, action: Action) -> ActionResult:
        """Navega para URL."""
        if not action.value:
            return ActionResult(
                success=False,
                action=action,
                error="URL não fornecida para ação NAVIGATE",
            )
        
        try:
            await page.goto(
                action.value,
                wait_until="domcontentloaded",
                timeout=self.navigation_timeout,
            )
            
            return ActionResult(
                success=True,
                action=action,
                new_url=page.url,
            )
            
        except Exception as e:
            return ActionResult(
                success=False,
                action=action,
                error=f"Falha ao navegar para {action.value}: {e}",
            )
    
    async def _execute_scroll(self, page, action: Action) -> ActionResult:
        """Rola a página."""
        direction = (action.value or "down").lower()
        
        try:
            if direction == "down":
                await page.evaluate("window.scrollBy(0, 500)")
            elif direction == "up":
                await page.evaluate("window.scrollBy(0, -500)")
            elif direction == "top":
                await page.evaluate("window.scrollTo(0, 0)")
            elif direction == "bottom":
                await page.evaluate("window.scrollTo(0, document.body.scrollHeight)")
            else:
                # Tenta interpretar como número de pixels
                try:
                    pixels = int(direction)
                    await page.evaluate(f"window.scrollBy(0, {pixels})")
                except ValueError:
                    return ActionResult(
                        success=False,
                        action=action,
                        error=f"Direção de scroll inválida: {direction}",
                    )
            
            await asyncio.sleep(0.3)  # Pequena pausa para scroll suave
            
            return ActionResult(
                success=True,
                action=action,
                new_url=page.url,
            )
            
        except Exception as e:
            return ActionResult(
                success=False,
                action=action,
                error=f"Falha ao rolar página: {e}",
            )
    
    async def _execute_wait(self, page, action: Action) -> ActionResult:
        """Aguarda tempo especificado."""
        try:
            seconds = float(action.value or "1")
            seconds = min(seconds, 10)  # Máximo 10 segundos
            await asyncio.sleep(seconds)
            
            return ActionResult(
                success=True,
                action=action,
                new_url=page.url,
            )
            
        except Exception as e:
            return ActionResult(
                success=False,
                action=action,
                error=f"Falha ao aguardar: {e}",
            )
    
    async def _execute_hover(self, page, action: Action) -> ActionResult:
        """Move mouse sobre elemento."""
        if not action.selector:
            return ActionResult(
                success=False,
                action=action,
                error="Selector não fornecido para ação HOVER",
            )
        
        try:
            await page.wait_for_selector(
                action.selector,
                state="visible",
                timeout=self.default_timeout,
            )
            await page.hover(action.selector)
            await asyncio.sleep(0.5)  # Pausa para menus aparecerem
            
            return ActionResult(
                success=True,
                action=action,
                new_url=page.url,
            )
            
        except Exception as e:
            return ActionResult(
                success=False,
                action=action,
                error=f"Falha ao hover em {action.selector}: {e}",
            )
    
    async def _execute_select(self, page, action: Action) -> ActionResult:
        """Seleciona opção em dropdown."""
        if not action.selector:
            return ActionResult(
                success=False,
                action=action,
                error="Selector não fornecido para ação SELECT",
            )
        
        try:
            await page.wait_for_selector(
                action.selector,
                state="visible",
                timeout=self.default_timeout,
            )
            await page.select_option(action.selector, action.value or "")
            
            return ActionResult(
                success=True,
                action=action,
                new_url=page.url,
            )
            
        except Exception as e:
            return ActionResult(
                success=False,
                action=action,
                error=f"Falha ao selecionar em {action.selector}: {e}",
            )
    
    async def _execute_press_key(self, page, action: Action) -> ActionResult:
        """Pressiona tecla no teclado."""
        key = action.value or "Enter"
        
        try:
            await page.keyboard.press(key)
            await self._wait_for_stable(page)
            
            return ActionResult(
                success=True,
                action=action,
                new_url=page.url,
            )
            
        except Exception as e:
            return ActionResult(
                success=False,
                action=action,
                error=f"Falha ao pressionar tecla {key}: {e}",
            )
    
    async def _execute_screenshot(self, page, action: Action) -> ActionResult:
        """Captura screenshot."""
        try:
            path = action.value or f"screenshot_{int(time.time())}.png"
            await page.screenshot(path=path, full_page=False)
            
            return ActionResult(
                success=True,
                action=action,
                new_url=page.url,
                screenshot_path=path,
            )
            
        except Exception as e:
            return ActionResult(
                success=False,
                action=action,
                error=f"Falha ao capturar screenshot: {e}",
            )
    
    async def _wait_for_stable(self, page, timeout: int = 2000):
        """
        Aguarda página estabilizar após ação.
        
        Útil após cliques que podem disparar navegação ou AJAX.
        """
        try:
            await page.wait_for_load_state("domcontentloaded", timeout=timeout)
        except Exception:
            pass
        
        try:
            await page.wait_for_load_state("networkidle", timeout=timeout)
        except Exception:
            pass
