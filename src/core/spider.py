"""
Módulo Spider/Crawler para descoberta automática de URLs e endpoints
"""
from typing import Dict, List, Set, Any
from urllib.parse import urljoin, urlparse
from html.parser import HTMLParser
from .logger_config import log
import queue
import threading


class LinkParser(HTMLParser):
    """Parser HTML para extrair links"""
    
    def __init__(self):
        super().__init__()
        self.links = []
        
    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        
        # Extrai links de tags <a>, <link>
        if tag in ('a', 'link') and 'href' in attrs_dict:
            self.links.append(attrs_dict['href'])
        
        # Extrai links de <script>, <img>, <iframe>
        elif tag in ('script', 'img', 'iframe') and 'src' in attrs_dict:
            self.links.append(attrs_dict['src'])


class FormParser(HTMLParser):
    """Parser HTML para extrair formulários e seus campos"""
    
    def __init__(self):
        super().__init__()
        self.forms = []
        self._current_form = None
    
    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)
        if tag == 'form':
            self._current_form = {
                'method': (attrs_dict.get('method') or 'GET').upper(),
                'action': attrs_dict.get('action') or '',
                'inputs': []
            }
        elif self._current_form and tag in ('input', 'select', 'textarea'):
            input_name = attrs_dict.get('name') or ''
            input_type = attrs_dict.get('type') or tag
            if input_name:
                self._current_form['inputs'].append({'name': input_name, 'type': input_type})
    
    def handle_endtag(self, tag):
        if tag == 'form' and self._current_form:
            self.forms.append(self._current_form)
            self._current_form = None


class Spider:
    """Spider/Crawler para descoberta automática de URLs"""
    
    def __init__(self):
        self.discovered_urls: Set[str] = set()
        self.queue: List[str] = []
        self.visited: Set[str] = set()
        self.running = False
        self.scope_urls: List[str] = []  # URLs no escopo
        self.max_depth = 3
        self.max_urls = 1000
        self.ui_queue = None
        self._lock = threading.RLock()
        # Armazena formulários descobertos (mínimo viável)
        # Estrutura esperada pela UI: {
        #   'method': str,
        #   'url': str,
        #   'inputs': List[{'name': str, 'type': str}]
        # }
        self.forms: List[Dict[str, Any]] = []

    def set_ui_queue(self, ui_queue: queue.Queue):
        """Define a fila para notificações da UI."""
        with self._lock:
            self.ui_queue = ui_queue
        
    def is_running(self) -> bool:
        """Retorna se o spider está ativo"""
        with self._lock:
            return self.running
    
    def start(self, target_urls: List[str] = None, max_depth: int = 3, max_urls: int = 1000):
        """
        Inicia o spider
        
        Args:
            target_urls: Lista de URLs iniciais para crawl
            max_depth: Profundidade máxima de navegação
            max_urls: Número máximo de URLs para descobrir
        """
        with self._lock:
            self.running = True
            self.max_depth = max_depth
            self.max_urls = max_urls
        
        if target_urls:
            # Normaliza URLs iniciais: garante presença de esquema
            normalized: List[str] = []
            for u in target_urls:
                try:
                    parsed = urlparse(u)
                    normalized.append(u if parsed.scheme else f"http://{u}")
                except Exception:
                    normalized.append(u)

            with self._lock:
                self.scope_urls = normalized
            for url in normalized:
                self.add_to_queue(url)
        
        log.info(f"Spider iniciado - Escopo: {len(target_urls) if target_urls else 0} URLs")
    
    def stop(self):
        """Para o spider"""
        with self._lock:
            self.running = False
        log.info("Spider parado")
    
    def clear(self):
        """Limpa todos os dados do spider"""
        with self._lock:
            self.discovered_urls.clear()
            self.queue.clear()
            self.visited.clear()
            self.forms.clear()
            self.running = False
        log.info("Spider resetado")
    
    def add_to_queue(self, url: str):
        """Adiciona URL à fila de descoberta"""
        with self._lock:
            if url and url not in self.visited and url not in self.queue:
                if self._is_in_scope(url):
                    self.queue.append(url)
                    log.debug(f"URL adicionada à fila: {url}")
    
    def _is_in_scope(self, url: str) -> bool:
        """Verifica se a URL está no escopo configurado"""
        with self._lock:
            if not self.scope_urls:
                return True
        
        parsed = urlparse(url)
        url_base = f"{parsed.scheme}://{parsed.netloc}"
        
        with self._lock:
            scope_urls = list(self.scope_urls)

        for scope_url in scope_urls:
            scope_parsed = urlparse(scope_url)
            scope_base = f"{scope_parsed.scheme}://{scope_parsed.netloc}"
            
            if url_base == scope_base:
                return True
            
            # Verifica subdomínios
            if parsed.netloc.endswith(f".{scope_parsed.netloc}"):
                return True
        
        return False
    
    def _should_ignore_url(self, url: str) -> bool:
        """Verifica se a URL deve ser ignorada (arquivos estáticos, etc)"""
        ignored_extensions = [
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.ico',
            '.css', '.js', '.woff', '.woff2', '.ttf', '.eot',
            '.pdf', '.zip', '.tar', '.gz', '.rar',
            '.mp4', '.avi', '.mov', '.mp3', '.wav',
            '.xml', '.json'
        ]
        
        url_lower = url.lower()
        return any(url_lower.endswith(ext) for ext in ignored_extensions)
    
    def get_stats(self) -> Dict[str, Any]:
        """Retorna estatísticas do spider"""
        with self._lock:
            return {
                'running': self.running,
                'discovered_urls': len(self.discovered_urls),
                'queue_size': len(self.queue),
                'visited': len(self.visited),
                'forms': len(getattr(self, 'forms', [])),
            }
    
    def get_discovered_urls(self) -> List[str]:
        """Retorna lista de URLs descobertas"""
        with self._lock:
            return sorted(list(self.discovered_urls))

    # ---- Métodos esperados pela UI (aba Spider) ----
    def get_forms(self) -> List[Dict[str, Any]]:
        """Retorna a lista de formulários descobertos.

        Implementação mínima para evitar erros na UI. Pode ser
        posteriormente povoada por um extrator de formulários.
        """
        with self._lock:
            return list(self.forms)

    def export_sitemap_text(self) -> str:
        """Gera um sitemap em texto agrupando URLs por host.

        Usa as URLs em `discovered_urls`. Formato simples:
        host
          /path
          /outro/path
        """
        with self._lock:
            discovered_urls = set(self.discovered_urls)

        if not discovered_urls:
            return "(vazio)"

        host_to_paths: Dict[str, Set[str]] = {}
        for url in discovered_urls:
            try:
                parsed = urlparse(url)
                host = parsed.netloc or ""
                path = parsed.path or "/"
                if host:
                    host_to_paths.setdefault(host, set()).add(path)
            except Exception:
                # Ignora URLs malformadas
                continue

        lines: List[str] = []
        for host in sorted(host_to_paths.keys()):
            lines.append(host)
            for path in sorted(host_to_paths[host]):
                lines.append(f"  {path}")

        return "\n".join(lines) if lines else "(vazio)"
