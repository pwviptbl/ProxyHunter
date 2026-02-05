"""
BrowserVision - Extração de estado visual e estrutural da página.

Este módulo captura o estado atual do navegador e extrai informações
que serão usadas pelo LLM para decidir a próxima ação.
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from urllib.parse import urlparse

from .actions import InteractiveElement


@dataclass
class PageState:
    """
    Representa o estado completo de uma página web.
    
    Usado para comunicar o contexto ao LLM.
    """
    
    url: str
    title: str
    html: str = ""
    elements: List[InteractiveElement] = field(default_factory=list)
    forms_count: int = 0
    links_count: int = 0
    screenshot_path: Optional[str] = None
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def get_domain(self) -> str:
        """Retorna o domínio da URL atual."""
        try:
            return urlparse(self.url).netloc
        except Exception:
            return ""
    
    def summarize(self) -> str:
        """Gera resumo do estado para logs."""
        return (
            f"URL: {self.url}\n"
            f"Título: {self.title}\n"
            f"Elementos: {len(self.elements)} | Forms: {self.forms_count} | Links: {self.links_count}"
        )


class BrowserVision:
    """
    Extrai informações visuais e estruturais de uma página.
    
    Responsável por:
    - Capturar estado da página (DOM, título, URL)
    - Identificar elementos interativos
    - Gerar descrições para o LLM
    """
    
    # Seletores para elementos interativos
    INTERACTIVE_SELECTORS = [
        "button",
        "a[href]",
        "input:not([type='hidden'])",
        "select",
        "textarea",
        "[role='button']",
        "[role='link']",
        "[onclick]",
        "[tabindex]:not([tabindex='-1'])",
    ]
    
    # Tipos de input que devemos considerar
    INPUT_TYPES_TO_INCLUDE = [
        "text", "email", "password", "search", "tel", "url",
        "number", "date", "datetime-local", "time", "week", "month",
        "checkbox", "radio", "file", "submit", "button",
    ]
    
    def __init__(self, max_elements: int = 80):
        """
        Args:
            max_elements: Número máximo de elementos a extrair
        """
        self.max_elements = max_elements
    
    async def capture_page_state(self, page) -> PageState:
        """
        Captura o estado atual da página.
        
        Args:
            page: Objeto Page do Playwright
            
        Returns:
            PageState com informações da página
        """
        try:
            url = page.url
            title = await page.title()
            html = await page.content()
            
            # Extrai elementos interativos
            elements = await self._extract_interactive_elements(page)
            
            # Conta forms e links
            forms_count = await page.locator("form").count()
            links_count = await page.locator("a[href]").count()
            
            return PageState(
                url=url,
                title=title,
                html=html,
                elements=elements,
                forms_count=forms_count,
                links_count=links_count,
            )
            
        except Exception as e:
            return PageState(
                url=page.url if page else "",
                title="",
                error=str(e),
            )
    
    async def _extract_interactive_elements(self, page) -> List[InteractiveElement]:
        """
        Extrai todos os elementos interativos da página.
        
        Args:
            page: Objeto Page do Playwright
            
        Returns:
            Lista de InteractiveElement
        """
        elements = []
        
        # Monta seletor combinado
        combined_selector = ", ".join(self.INTERACTIVE_SELECTORS)
        
        try:
            locators = page.locator(combined_selector)
            count = await locators.count()
            
            for i in range(min(count, self.max_elements)):
                try:
                    loc = locators.nth(i)
                    element = await self._parse_element(loc, i)
                    if element:
                        elements.append(element)
                except Exception:
                    continue
                    
        except Exception:
            pass
        
        return elements
    
    async def _parse_element(self, locator, index: int) -> Optional[InteractiveElement]:
        """
        Converte um locator do Playwright em InteractiveElement.
        
        Args:
            locator: Locator do Playwright
            index: Índice do elemento para fallback de seletor
            
        Returns:
            InteractiveElement ou None se inválido
        """
        try:
            # Verifica visibilidade
            is_visible = await locator.is_visible()
            if not is_visible:
                return None
            
            # Obtém propriedades básicas
            tag = await locator.evaluate("el => el.tagName.toLowerCase()")
            
            # Obtém atributos - incluindo className para melhores seletores
            attrs = await locator.evaluate("""el => ({
                id: el.id || null,
                name: el.name || null,
                type: el.type || null,
                placeholder: el.placeholder || null,
                value: el.value || null,
                href: el.href || null,
                role: el.getAttribute('role'),
                ariaLabel: el.getAttribute('aria-label'),
                disabled: el.disabled || false,
                className: el.className || null,
                textContent: el.textContent ? el.textContent.trim().substring(0, 50) : null,
            })""")
            
            # Obtém texto visível
            text = await locator.inner_text() if tag not in ["input", "select", "textarea"] else ""
            text = self._clean_text(text)
            
            # Determina tipo do elemento
            element_type = self._determine_element_type(tag, attrs)
            
            # Gera seletor único - MELHORADO para incluir texto e classes
            selector = self._build_selector(tag, attrs, index, text)
            
            # Verifica se está habilitado
            is_enabled = not attrs.get("disabled", False)
            
            return InteractiveElement(
                tag=tag,
                element_type=element_type,
                selector=selector,
                text=text,
                name=attrs.get("name"),
                id=attrs.get("id"),
                placeholder=attrs.get("placeholder"),
                value=attrs.get("value"),
                is_visible=is_visible,
                is_enabled=is_enabled,
            )
            
        except Exception:
            return None
    
    def _determine_element_type(self, tag: str, attrs: dict) -> str:
        """Determina o tipo lógico do elemento."""
        if tag == "a":
            return "link"
        elif tag == "button":
            return "button"
        elif tag == "select":
            return "dropdown"
        elif tag == "textarea":
            return "textarea"
        elif tag == "input":
            input_type = (attrs.get("type") or "text").lower()
            return input_type
        elif attrs.get("role") == "button":
            return "button"
        elif attrs.get("role") == "link":
            return "link"
        else:
            return "clickable"
    
    def _build_selector(self, tag: str, attrs: dict, index: int, text: str = "") -> str:
        """
        Constrói um seletor CSS único para o elemento.
        
        Ordem de prioridade:
        1. ID
        2. aria-label (muito confiável)
        3. name
        4. href para links
        5. Texto do elemento (via :has-text para Playwright)
        6. Classes CSS específicas
        7. Fallback posicional
        """
        # Prioridade 1: ID
        if attrs.get("id"):
            return f"#{attrs['id']}"
        
        # Prioridade 2: aria-label (muito confiável para botões)
        if attrs.get("ariaLabel"):
            label = attrs["ariaLabel"]
            # Escapa aspas simples
            label = label.replace("'", "\\'")
            return f"{tag}[aria-label='{label}']"
        
        # Prioridade 3: name único
        if attrs.get("name"):
            name = attrs["name"].replace("'", "\\'")
            return f"{tag}[name='{name}']"
        
        # Prioridade 4: href para links
        if tag == "a" and attrs.get("href"):
            href = attrs["href"]
            # Usa apenas parte do href para evitar seletores muito longos
            if len(href) < 80:
                href = href.replace("'", "\\'")
                return f"a[href='{href}']"
        
        # Prioridade 5: Texto do elemento (muito útil para botões)
        # Usa :text() que é suportado pelo Playwright
        if text and len(text) > 0 and len(text) < 30:
            # Limpa o texto para usar como seletor
            clean = text.strip()
            if clean:
                # Usar :text() para matching por texto
                return f"{tag}:has-text('{clean}')"
        
        # Prioridade 6: textContent do atributo (fallback)
        text_content = attrs.get("textContent", "")
        if text_content and len(text_content) > 0 and len(text_content) < 30:
            clean = text_content.strip()
            if clean:
                return f"{tag}:has-text('{clean}')"
        
        # Prioridade 7: Classes CSS específicas (para botões estilizados)
        class_name = attrs.get("className", "")
        if class_name and tag == "button":
            # Extrai primeira classe significativa
            classes = [c.strip() for c in str(class_name).split() if c.strip()]
            # Filtra classes muito genéricas
            significant_classes = [c for c in classes if c not in [
                "btn", "button", "w-full", "h-full", "p-2", "p-3", "m-2", "flex"
            ] and len(c) > 3]
            if significant_classes:
                # Usa a primeira classe significativa
                return f"button.{significant_classes[0]}"
        
        # Prioridade 8: type + placeholder para inputs
        if tag == "input" and attrs.get("type"):
            input_type = attrs["type"]
            if attrs.get("placeholder"):
                placeholder = attrs["placeholder"].replace("'", "\\'")
                return f"input[type='{input_type}'][placeholder='{placeholder}']"
            return f"input[type='{input_type}']:nth-of-type({index + 1})"
        
        # Fallback: posição (menos confiável)
        return f"{tag}:nth-of-type({index + 1})"
    
    def _clean_text(self, text: str) -> str:
        """Limpa e normaliza texto extraído."""
        if not text:
            return ""
        # Remove quebras de linha excessivas e espaços
        text = re.sub(r'\s+', ' ', text)
        return text.strip()[:100]  # Limita tamanho
    
    async def take_screenshot(self, page, path: str) -> Optional[str]:
        """
        Captura screenshot da página.
        
        Args:
            page: Objeto Page do Playwright
            path: Caminho para salvar o screenshot
            
        Returns:
            Caminho do arquivo ou None se falhou
        """
        try:
            await page.screenshot(path=path, full_page=False)
            return path
        except Exception:
            return None
    
    def filter_relevant_elements(
        self,
        elements: List[InteractiveElement],
        context: str = "",
    ) -> List[InteractiveElement]:
        """
        Filtra elementos mais relevantes baseado no contexto.
        
        Por exemplo, em página de login, prioriza campos de usuário/senha.
        """
        if not context:
            return elements
        
        context_lower = context.lower()
        scored = []
        
        for el in elements:
            score = 0
            text_lower = (el.text or "").lower() + (el.name or "").lower()
            
            # Boost para elementos relacionados ao contexto
            if "login" in context_lower:
                if any(x in text_lower for x in ["user", "email", "login", "senha", "password", "entrar", "sign"]):
                    score += 10
            
            if "registro" in context_lower or "register" in context_lower:
                if any(x in text_lower for x in ["register", "cadastro", "criar", "novo"]):
                    score += 10
            
            # Campos de formulário sempre relevantes
            if el.element_type in ["text", "email", "password", "submit", "button"]:
                score += 5
            
            scored.append((score, el))
        
        # Ordena por score e retorna
        scored.sort(key=lambda x: x[0], reverse=True)
        return [el for _, el in scored]
