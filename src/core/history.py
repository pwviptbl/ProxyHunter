from datetime import datetime
import copy
import os
import threading
from mitmproxy import http


DEFAULT_MAX_REQUEST_BODY_BYTES = 256 * 1024
DEFAULT_MAX_RESPONSE_BODY_BYTES = 512 * 1024

BINARY_CONTENT_TYPES = (
    "application/octet-stream",
    "application/pdf",
    "application/zip",
    "application/x-",
    "audio/",
    "font/",
    "image/",
    "video/",
)


def _env_int(name: str, default: int) -> int:
    try:
        value = int(os.getenv(name, str(default)))
        return max(0, value)
    except (TypeError, ValueError):
        return default


MAX_REQUEST_BODY_BYTES = _env_int("PROXYHUNTER_MAX_REQUEST_BODY_BYTES", DEFAULT_MAX_REQUEST_BODY_BYTES)
MAX_RESPONSE_BODY_BYTES = _env_int("PROXYHUNTER_MAX_RESPONSE_BODY_BYTES", DEFAULT_MAX_RESPONSE_BODY_BYTES)


def _content_type(headers) -> str:
    try:
        return (headers.get("content-type", "") or "").split(";", 1)[0].strip().lower()
    except Exception:
        return ""


def _is_binary_content_type(content_type: str) -> bool:
    return any(content_type == item.rstrip("/") or content_type.startswith(item) for item in BINARY_CONTENT_TYPES)


def _decode_body_for_history(content, headers, max_bytes: int):
    """Decode bounded textual content for GUI/history without retaining huge payloads."""
    if not content:
        return "", {
            "truncated": False,
            "stored_bytes": 0,
            "original_bytes": 0,
            "content_type": _content_type(headers),
            "binary_omitted": False,
        }

    original_bytes = len(content)
    content_type = _content_type(headers)

    if _is_binary_content_type(content_type):
        return (
            f"[conteudo binario omitido: {original_bytes} bytes, content-type: {content_type or 'desconhecido'}]",
            {
                "truncated": False,
                "stored_bytes": 0,
                "original_bytes": original_bytes,
                "content_type": content_type,
                "binary_omitted": True,
            },
        )

    limited = content[:max_bytes] if max_bytes else b""
    truncated = original_bytes > len(limited)
    text = limited.decode("utf-8", errors="replace")
    if truncated:
        text += f"\n\n[truncado pelo ProxyHunter: exibindo {len(limited)} de {original_bytes} bytes]"

    return text, {
        "truncated": truncated,
        "stored_bytes": len(limited),
        "original_bytes": original_bytes,
        "content_type": content_type,
        "binary_omitted": False,
    }


class RequestHistory:
    """Gerencia o histórico de requisições"""

    def __init__(self):
        self.history = []
        self.max_items = 1000
        self.current_id = 0
        self._lock = threading.Lock()
        self.ui_queue = None

    def set_ui_queue(self, queue):
        """Define a fila de UI para notificações."""
        self.ui_queue = queue

    def get_ui_queue(self):
        """Retorna a fila de UI."""
        return self.ui_queue

    def add_request(self, flow: http.HTTPFlow, vulnerabilities=None):
        """Adiciona uma requisição ao histórico"""
        request = flow.request
        response = flow.response

        with self._lock:
            # Incrementa o ID para cada nova requisição
            self.current_id += 1

            # Calcula elapsed_ms usando timestamps do mitmproxy
            try:
                if response and response.timestamp_end and request.timestamp_start:
                    elapsed_ms = round((response.timestamp_end - request.timestamp_start) * 1000)
                else:
                    elapsed_ms = None
            except Exception:
                elapsed_ms = None

            request_body, request_body_meta = _decode_body_for_history(
                request.content,
                request.headers,
                MAX_REQUEST_BODY_BYTES,
            )
            response_body, response_body_meta = _decode_body_for_history(
                response.content if response else b"",
                response.headers if response else {},
                MAX_RESPONSE_BODY_BYTES,
            )

            # Extrai informações da requisição
            entry = {
                'id': self.current_id,
                'timestamp': datetime.now(),
                'host': request.pretty_host,
                'method': request.method,
                'url': request.pretty_url,
                'path': request.path,
                'status': response.status_code if response else 0,
                'elapsed_ms': elapsed_ms,
                'request_headers': dict(request.headers),
                'request_body': request_body,
                'request_body_meta': request_body_meta,
                'response_headers': dict(response.headers) if response else {},
                'response_body': response_body,
                'response_body_meta': response_body_meta,
                'vulnerabilities': vulnerabilities or [],  # Adiciona lista de vulnerabilidades
            }

            self.history.append(entry)

            # Limita o tamanho do histórico
            if len(self.history) > self.max_items:
                self.history.pop(0)

    def add_raw_request(self, method: str, url: str, host: str, path: str, status: int,
                       request_headers: dict, request_body: str, response_headers: dict,
                       response_body: str, vulnerabilities=None, elapsed_ms=None):
        """Adiciona uma requisição ao histórico usando dados brutos (para attacker)"""
        with self._lock:
            # Incrementa o ID para cada nova requisição
            self.current_id += 1

            # Cria entrada do histórico
            entry = {
                'id': self.current_id,
                'timestamp': datetime.now(),
                'host': host,
                'method': method,
                'url': url,
                'path': path,
                'status': status,
                'elapsed_ms': elapsed_ms,
                'request_headers': request_headers,
                'request_body': request_body,
                'response_headers': response_headers,
                'response_body': response_body,
                'vulnerabilities': vulnerabilities or [],
            }

            self.history.append(entry)

            # Limita o tamanho do histórico
            if len(self.history) > self.max_items:
                self.history.pop(0)

    def get_history(self):
        """Retorna todo o histórico"""
        with self._lock:
            return copy.deepcopy(self.history)

    def get_latest_entry(self):
        """Retorna a entrada mais recente do histórico."""
        with self._lock:
            if not self.history:
                return None
            return copy.deepcopy(self.history[-1])

    def clear_history(self):
        """Limpa o histórico"""
        with self._lock:
            self.history = []
            self.current_id = 0

    def get_new_entries(self, last_id=0):
        """Retorna apenas as entradas mais novas que o último ID conhecido."""
        with self._lock:
            if not last_id or not self.history:
                return copy.deepcopy(self.history)

            # Encontra o índice da primeira nova entrada
            first_new_index = -1
            for i, entry in enumerate(reversed(self.history)):
                if entry['id'] <= last_id:
                    break
                first_new_index = len(self.history) - 1 - i

            if first_new_index != -1:
                return copy.deepcopy(self.history[first_new_index:])
            else:
                return []

    def get_entry_by_id(self, entry_id: int):
        """Retorna uma entrada do histórico pelo seu ID."""
        with self._lock:
            for entry in reversed(self.history):
                if entry['id'] == entry_id:
                    return copy.deepcopy(entry)
            return None

    def add_vulnerabilities_to_entry(self, entry_id: int, new_vulnerabilities: list):
        """Adiciona uma lista de vulnerabilidades a uma entrada existente no histórico."""
        with self._lock:
            entry = None
            for existing in reversed(self.history):
                if existing['id'] == entry_id:
                    entry = existing
                    break
            if entry:
                # Garante que a lista de vulnerabilidades exista
                if 'vulnerabilities' not in entry or not isinstance(entry['vulnerabilities'], list):
                    entry['vulnerabilities'] = []

                # Adiciona apenas vulnerabilidades que ainda não foram reportadas
                existing_vulns_str = {str(v) for v in entry['vulnerabilities']}
                for vuln in new_vulnerabilities:
                    if str(vuln) not in existing_vulns_str:
                        entry['vulnerabilities'].append(vuln)
                return True
            return False
