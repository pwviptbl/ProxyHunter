"""
AutonomousAgent - Classe principal do agente de navegação autônoma.

Este módulo orquestra todos os componentes do agente:
- BrowserVision para capturar estado
- DecisionAgent para decidir ações
- ActionExecutor para executar ações
- SessionMemory para persistir estado
"""

import asyncio
import uuid
from typing import Optional, List, Dict, Any
from datetime import datetime

from playwright.async_api import async_playwright

from .browser_vision import BrowserVision, PageState
from .decision_agent import DecisionAgent, LLMConfig
from .action_executor import ActionExecutor
from .session_memory import SessionMemory
from .actions import Action, ActionType, ActionResult

from ..logger_config import log


class AutonomousAgent:
    """
    Agente de navegação autônoma inteligente.
    
    Combina visão computacional, LLM e execução para navegar
    em sites como um humano faria.
    
    Exemplo de uso:
        agent = AutonomousAgent(
            target_url="https://example.com",
            objective="fazer login e mapear área logada",
            llm_config=LLMConfig(api_key="..."),
            credentials=("admin", "password123"),
        )
        result = await agent.run()
    """
    
    def __init__(
        self,
        target_url: str,
        objective: str,
        llm_config: LLMConfig,
        credentials: Optional[tuple] = None,
        proxy_port: Optional[int] = None,
        max_steps: int = 50,
        max_depth: int = 3,
        headless: bool = True,
        timeout: int = 30000,
        session_id: Optional[str] = None,
        storage_dir: Optional[str] = None,
    ):
        """
        Args:
            target_url: URL inicial para navegação
            objective: Objetivo a ser alcançado
            llm_config: Configuração do LLM
            credentials: Tupla (username, password) se disponível
            proxy_port: Porta do proxy (opcional, para integrar com mitmproxy)
            max_steps: Número máximo de ações
            max_depth: Profundidade máxima de navegação
            headless: Se True, executa sem interface visual
            timeout: Timeout padrão em ms
            session_id: ID da sessão (gerado automaticamente se não fornecido)
            storage_dir: Diretório para persistir sessão
        """
        self.target_url = target_url
        self.objective = objective
        self.credentials = credentials
        self.proxy_port = proxy_port
        self.max_steps = max_steps
        self.max_depth = max_depth
        self.headless = headless
        self.timeout = timeout
        
        # ID da sessão
        self.session_id = session_id or str(uuid.uuid4())[:8]
        
        # Componentes
        self.vision = BrowserVision(max_elements=50)
        self.executor = ActionExecutor(
            default_timeout=timeout // 2,
            navigation_timeout=timeout,
        )
        self.decision = DecisionAgent(
            objective=objective,
            llm_config=llm_config,
            credentials=credentials,
        )
        self.memory = SessionMemory(
            session_id=self.session_id,
            target_url=target_url,
            objective=objective,
            storage_dir=storage_dir,
        )
        
        # Estado interno
        self._browser = None
        self._context = None
        self._page = None
        self._step_count = 0
        self._is_running = False
    
    async def run(self) -> Dict[str, Any]:
        """
        Executa o agente de navegação.
        
        Returns:
            Dicionário com resumo da execução
        """
        log.info(f"Iniciando AutonomousAgent [{self.session_id}]")
        log.info(f"Alvo: {self.target_url}")
        log.info(f"Objetivo: {self.objective}")
        
        self._is_running = True
        start_time = datetime.now()
        
        try:
            # Inicia navegador
            await self._start_browser()
            
            # Navega para URL inicial
            await self._page.goto(
                self.target_url,
                wait_until="domcontentloaded",
                timeout=self.timeout,
            )
            
            self.memory.add_route(
                url=self.target_url,
                title=await self._page.title(),
                from_action="initial_navigation",
            )
            
            # Loop principal
            while self._is_running and self._step_count < self.max_steps:
                result = await self._execute_step()
                
                if result.action.action_type == ActionType.DONE:
                    log.info(f"Objetivo alcançado: {result.action.reasoning}")
                    self.memory.set_status("completed")
                    break
                
                if result.action.action_type == ActionType.FAILED:
                    log.warning(f"Agente falhou: {result.action.reasoning}")
                    self.memory.set_status("failed")
                    break
                
                # Detecta loop
                if self.memory.detect_loop():
                    log.warning("Loop detectado, interrompendo")
                    self.memory.set_status("loop_detected")
                    break
            
            else:
                if self._step_count >= self.max_steps:
                    log.info(f"Limite de passos atingido ({self.max_steps})")
                    self.memory.set_status("max_steps_reached")
            
        except Exception as e:
            log.error(f"Erro durante execução: {e}")
            self.memory.set_error(str(e))
            self.memory.set_status("error")
            
        finally:
            await self._stop_browser()
            self.memory.save()
        
        # Calcula duração
        duration = (datetime.now() - start_time).total_seconds()
        
        return self._build_report(duration)
    
    async def _execute_step(self) -> ActionResult:
        """Executa um passo do agente."""
        self._step_count += 1
        log.debug(f"Passo {self._step_count}/{self.max_steps}")
        
        # Captura estado da página
        page_state = await self.vision.capture_page_state(self._page)
        self.memory.update_current_url(page_state.url)
        
        log.debug(f"URL: {page_state.url}")
        log.debug(f"Elementos: {len(page_state.elements)}")
        
        # Decide próxima ação
        action = await self.decision.decide_next_action(page_state)
        log.info(f"Ação: {action}")
        
        # Executa ação
        result = await self.executor.execute(self._page, action)
        
        if result.success:
            log.debug(f"Sucesso: {result}")
            
            # Registra rota se URL mudou
            if result.new_url and result.new_url != page_state.url:
                self.memory.add_route(
                    url=result.new_url,
                    title=await self._page.title(),
                    from_action=str(action),
                )
                self.memory.increment_pages()
        else:
            log.warning(f"Falha: {result.error}")
        
        # Atualiza memória e histórico
        self.memory.add_action(result.to_dict())
        self.decision.update_history(result)
        
        # Pequena pausa entre ações
        await asyncio.sleep(0.5)
        
        return result
    
    async def _start_browser(self):
        """Inicia navegador Playwright."""
        playwright = await async_playwright().start()
        
        # Configura proxy se especificado
        browser_args = ["--ignore-certificate-errors"]
        proxy_config = None
        if self.proxy_port:
            proxy_config = {"server": f"http://127.0.0.1:{self.proxy_port}"}
        
        self._browser = await playwright.chromium.launch(
            headless=self.headless,
            args=browser_args,
        )
        
        context_options = {
            "ignore_https_errors": True,
            "user_agent": "ProxyHunter-AutonomousAgent/1.0",
        }
        if proxy_config:
            context_options["proxy"] = proxy_config
        
        self._context = await self._browser.new_context(**context_options)
        self._page = await self._context.new_page()
        
        # Configura timeouts
        self._page.set_default_timeout(self.timeout)
        
        # Captura requisições via hooks do Playwright
        self._captured_requests = []
        self._request_id_counter = 0
        
        async def on_request(request):
            self._request_id_counter += 1
            req_data = {
                "id": self._request_id_counter,
                "method": request.method,
                "url": request.url,
                "headers": dict(request.headers) if request.headers else {},
                "post_data": request.post_data if request.method in ["POST", "PUT", "PATCH"] else None,
                "timestamp": datetime.now().isoformat(),
                "response": None,  # Será atualizado no on_response
            }
            # Armazena temporariamente para associar com response
            setattr(request, "_ph_id", self._request_id_counter)
            setattr(request, "_ph_idx", len(self._captured_requests))
            self._captured_requests.append(req_data)
        
        async def on_response(response):
            # Encontra a requisição correspondente e adiciona dados da response
            req = response.request
            if hasattr(req, "_ph_idx"):
                idx = req._ph_idx
                if idx < len(self._captured_requests):
                    try:
                        body = ""
                        content_type = response.headers.get("content-type", "")
                        # Só captura body para text/html e json
                        if "text/html" in content_type or "application/json" in content_type:
                            try:
                                body = await response.text()
                                # Limita tamanho do body
                                if len(body) > 10000:
                                    body = body[:10000] + "... [truncado]"
                            except Exception:
                                pass
                        
                        self._captured_requests[idx]["response"] = {
                            "status": response.status,
                            "status_text": response.status_text,
                            "headers": dict(response.headers) if response.headers else {},
                            "body": body,
                        }
                    except Exception:
                        pass
        
        self._page.on("request", on_request)
        self._page.on("response", on_response)
        
        log.debug("Navegador iniciado com captura de requisições")
    
    async def _stop_browser(self):
        """Fecha navegador."""
        try:
            # Salva cookies antes de fechar
            if self._context:
                cookies = await self._context.cookies()
                self.memory.store_cookies(cookies)
            
            if self._browser:
                await self._browser.close()
                
            log.debug("Navegador fechado")
            
        except Exception as e:
            log.warning(f"Erro ao fechar navegador: {e}")
    
    def stop(self):
        """Para execução do agente."""
        self._is_running = False
    
    def _build_report(self, duration: float) -> Dict[str, Any]:
        """Constrói relatório final."""
        summary = self.memory.get_summary()
        summary["duration_seconds"] = round(duration, 2)
        summary["routes"] = self.memory.get_routes()
        summary["last_actions"] = self.memory.get_recent_actions(5)
        
        # Inclui requisições capturadas via Playwright
        summary["captured_requests"] = getattr(self, "_captured_requests", [])
        
        return summary
    
    @classmethod
    async def resume(
        cls,
        session_id: str,
        llm_config: LLMConfig,
        storage_dir: Optional[str] = None,
        **kwargs,
    ) -> "AutonomousAgent":
        """
        Retoma uma sessão salva.
        
        Args:
            session_id: ID da sessão a retomar
            llm_config: Configuração do LLM
            storage_dir: Diretório de armazenamento
            **kwargs: Argumentos adicionais para o agente
            
        Returns:
            AutonomousAgent com estado restaurado
        """
        memory = SessionMemory.load(session_id, storage_dir)
        
        agent = cls(
            target_url=memory.target_url,
            objective=memory.objective,
            llm_config=llm_config,
            session_id=session_id,
            storage_dir=storage_dir,
            **kwargs,
        )
        
        agent.memory = memory
        memory.set_status("resumed")
        
        return agent
