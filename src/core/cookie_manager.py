import collections
from http.cookies import SimpleCookie
from typing import Dict, List, Callable

class CookieManager:
    """
    Gerencia a extração, armazenamento e uso de cookies.
    """

    def __init__(self):
        # Armazena todos os cookies capturados, organizados por domínio
        self.cookies_by_domain: Dict[str, Dict[str, str]] = collections.defaultdict(dict)
        # Armazena os cookies que o usuário quer forçar
        self.cookie_jar: Dict[str, str] = {}
        # Callback para notificar a UI sobre atualizações
        self.ui_callback: Callable[[], None] | None = None

    def set_ui_callback(self, callback: Callable[[], None]):
        """Define um callback para notificar a UI sobre atualizações."""
        self.ui_callback = callback

    def _notify_ui(self):
        """Chama o callback da UI se ele estiver definido."""
        if self.ui_callback:
            self.ui_callback()

    def parse_and_store_cookies(self, host: str, request_headers: Dict, response_headers: Dict):
        """
        Analisa os cabeçalhos de uma transação e armazena os cookies encontrados.
        """
        updated = False
        domain = host.lower()

        # 1. Analisa o cabeçalho 'Cookie' da requisição
        cookie_header = next((v for k, v in request_headers.items() if k.lower() == 'cookie'), None)
        if cookie_header:
            try:
                cookies = [c.strip().split('=', 1) for c in cookie_header.split(';') if '=' in c]
                for name, value in cookies:
                    if self.cookies_by_domain[domain].get(name) != value:
                        self.cookies_by_domain[domain][name] = value
                        updated = True
            except Exception:
                pass  # Ignora cabeçalhos de cookie malformados

        # 2. Analisa o cabeçalho 'Set-Cookie' da resposta
        set_cookie_header = next((v for k, v in response_headers.items() if k.lower() == 'set-cookie'), None)
        if set_cookie_header:
            try:
                cookie = SimpleCookie()
                cookie.load(set_cookie_header)
                for name, morsel in cookie.items():
                    # Garante que não sobrescrevemos com um valor vazio se já tivermos um
                    if self.cookies_by_domain[domain].get(name) != morsel.value:
                         self.cookies_by_domain[domain][name] = morsel.value
                         updated = True
            except Exception:
                pass  # Ignora cabeçalhos Set-Cookie malformados

        if updated:
            self._notify_ui()

    def get_all_cookies(self) -> Dict[str, Dict[str, str]]:
        """Retorna todos os cookies capturados."""
        return self.cookies_by_domain

    def add_to_jar(self, name: str, value: str):
        """Adiciona ou atualiza um cookie no Jar."""
        self.cookie_jar[name] = value

    def remove_from_jar(self, name: str):
        """Remove um cookie do Jar."""
        if name in self.cookie_jar:
            del self.cookie_jar[name]

    def clear_jar(self):
        """Limpa todos os cookies do Jar."""
        self.cookie_jar.clear()

    def get_jar_cookies_header(self) -> str:
        """Retorna a string do cabeçalho Cookie a partir do Jar."""
        if not self.cookie_jar:
            return ""
        return "; ".join([f"{name}={value}" for name, value in self.cookie_jar.items()])

    def get_jar_cookies_list(self) -> List[Dict]:
        """Retorna a lista de cookies no Jar para a UI."""
        return [{'name': k, 'value': v} for k, v in sorted(self.cookie_jar.items())]
