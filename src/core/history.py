from datetime import datetime
from mitmproxy import http


class RequestHistory:
    """Gerencia o histórico de requisições"""

    def __init__(self):
        self.history = []
        self.max_items = 1000
        self.current_id = 0

    def add_request(self, flow: http.HTTPFlow, vulnerabilities=None):
        """Adiciona uma requisição ao histórico"""
        request = flow.request
        response = flow.response

        # Incrementa o ID para cada nova requisição
        self.current_id += 1

        # Extrai informações da requisição
        entry = {
            'id': self.current_id,
            'timestamp': datetime.now(),
            'host': request.pretty_host,
            'method': request.method,
            'url': request.pretty_url,
            'path': request.path,
            'status': response.status_code if response else 0,
            'request_headers': dict(request.headers),
            'request_body': request.content.decode('utf-8', errors='ignore') if request.content else '',
            'response_headers': dict(response.headers) if response else {},
            'response_body': response.content.decode('utf-8', errors='ignore') if response and response.content else '',
            'vulnerabilities': vulnerabilities or [],  # Adiciona lista de vulnerabilidades
        }

        self.history.append(entry)

        # Limita o tamanho do histórico
        if len(self.history) > self.max_items:
            self.history.pop(0)

    def add_raw_request(self, method: str, url: str, host: str, path: str, status: int,
                       request_headers: dict, request_body: str, response_headers: dict,
                       response_body: str, vulnerabilities=None):
        """Adiciona uma requisição ao histórico usando dados brutos (para attacker)"""
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
        return self.history

    def clear_history(self):
        """Limpa o histórico"""
        self.history = []
        self.current_id = 0

    def get_new_entries(self, last_id=0):
        """Retorna apenas as entradas mais novas que o último ID conhecido."""
        if not last_id or not self.history:
            return self.history

        # Encontra o índice da primeira nova entrada
        first_new_index = -1
        for i, entry in enumerate(reversed(self.history)):
            if entry['id'] <= last_id:
                break
            first_new_index = len(self.history) - 1 - i

        if first_new_index != -1:
            return self.history[first_new_index:]
        else:
            return []

    def get_entry_by_id(self, entry_id: int):
        """Retorna uma entrada do histórico pelo seu ID."""
        for entry in reversed(self.history):
            if entry['id'] == entry_id:
                return entry
        return None

    def add_vulnerabilities_to_entry(self, entry_id: int, new_vulnerabilities: list):
        """Adiciona uma lista de vulnerabilidades a uma entrada existente no histórico."""
        entry = self.get_entry_by_id(entry_id)
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
