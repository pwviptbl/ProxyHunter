"""
TOR Manager - Gerencia conexões e configurações do TOR
"""
import socket
import socks
import stem
from stem import Signal
from stem.control import Controller
from contextlib import contextmanager
from .logger_config import log

class TorManager:
    """Gerencia conexões TOR para anonimato nas requisições"""

    def __init__(self, tor_port=9050, control_port=9051):
        self.tor_port = tor_port
        self.control_port = control_port
        self.controller = None
        self._original_socket = socket.socket
        self._patched = False

    @contextmanager
    def tor_context(self):
        """Context manager para usar TOR temporariamente"""
        original_socket = None
        try:
            # Salva o socket original
            original_socket = socket.socket

            # Aplica monkey patching apenas para este contexto
            socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", self.tor_port)
            socket.socket = socks.socksocket
            self._patched = True

            log.debug("TOR context ativado")
            yield
        finally:
            # Sempre restaura o socket original
            if original_socket:
                socket.socket = original_socket
                self._patched = False
                log.debug("TOR context desativado")

    def connect(self):
        """Estabelece conexão com o TOR (método legado)"""
        try:
            # Configura SOCKS5 proxy
            socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", self.tor_port)
            socket.socket = socks.socksocket
            self._patched = True
            log.info(f"TOR configurado na porta {self.tor_port}")
            return True
        except Exception as e:
            log.error(f"Erro ao conectar com TOR: {e}")
            return False

    def disconnect(self):
        """Remove a configuração TOR e volta ao socket normal"""
        try:
            socket.socket = self._original_socket
            self._patched = False
            log.info("TOR desconectado")
            return True
        except Exception as e:
            log.error(f"Erro ao desconectar TOR: {e}")
            return False

    def new_identity(self):
        """Renova a identidade TOR (novo circuito)"""
        try:
            if not self.controller:
                self.controller = Controller.from_port(port=self.control_port)
                self.controller.authenticate()

            self.controller.signal(Signal.NEWNYM)
            log.info("Nova identidade TOR solicitada")
            return True
        except Exception as e:
            log.error(f"Erro ao renovar identidade TOR: {e}")
            return False

    def is_tor_running(self):
        """Verifica se o TOR está rodando"""
        try:
            sock = socks.socksocket()
            sock.set_proxy(socks.SOCKS5, "127.0.0.1", self.tor_port)
            sock.connect(("check.torproject.org", 80))
            sock.close()
            return True
        except:
            return False

    def get_current_ip(self):
        """Obtém o IP atual através do TOR"""
        try:
            import requests
            # Temporariamente desabilita proxy para checar IP
            original_proxies = requests.utils.get_environ_proxies("")
            response = requests.get("https://httpbin.org/ip", timeout=10)
            return response.json().get("origin", "Unknown")
        except Exception as e:
            log.error(f"Erro ao obter IP atual: {e}")
            return "Unknown"