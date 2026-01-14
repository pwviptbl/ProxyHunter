import re
import queue
import threading
import concurrent.futures
from datetime import datetime
from .advanced_sender import send_from_raw # Reutilizando a função de envio
from .logger_config import log

class Attacker:
    def _add_to_history(self, request_text: str, response=None):
        try:
            lines = request_text.strip().split('\n')
            if not lines:
                return

            first_line = lines[0]
            parts = first_line.split()
            if len(parts) < 2:
                return

            method = parts[0]
            path = parts[1]

            headers = {}
            body_start = -1
            for i, line in enumerate(lines[1:], 1):
                if line.strip() == '':
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()

            host = headers.get('Host', 'unknown')
            body = '\n'.join(lines[body_start:]) if body_start > 0 else ''
            url = f"https://{host}{path}" if host != 'unknown' else path

            status = 0
            response_headers = {}
            response_body = ''
            if response is not None:
                try:
                    status = getattr(response, 'status_code', 0)
                    response_headers = dict(getattr(response, 'headers', {}))
                    response_body = getattr(response, 'text', '')
                except Exception:
                    status = 0
                    response_headers = {}
                    response_body = ''

            entry = {
                'method': method,
                'url': url,
                'host': host,
                'path': path,
                'status': status,
                'request_headers': headers,
                'request_body': body,
                'response_headers': response_headers,
                'response_body': response_body,
            }
            self.history.append(entry)
        except Exception as e:
            log.error(f"Erro ao adicionar ao histórico do Attacker: {e}", exc_info=True)
    """
    Lógica principal para as operações de ataque automatizado.
    """
    def __init__(self, raw_request: str, attack_type: str, payloads: list, num_threads: int, result_queue: queue.Queue, proxy_port: int, use_tor: bool = False, tor_port: int = 9050, history=None):
        self.raw_request = raw_request
        self.attack_type = attack_type
        self.payloads = payloads
        self.num_threads = num_threads
        self.result_queue = result_queue
        self.proxy_port = proxy_port
        self.use_tor = use_tor
        self.tor_port = tor_port
        self.history = []

    def _add_to_history(self, request_text: str, response=None):
        try:
            lines = request_text.strip().split('\n')
            if not lines:
                return

            first_line = lines[0]
            parts = first_line.split()
            if len(parts) < 2:
                return

            method = parts[0]
            path = parts[1]

            headers = {}
            body_start = -1
            for i, line in enumerate(lines[1:], 1):
                if line.strip() == '':
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()

            host = headers.get('Host', 'unknown')
            body = '\n'.join(lines[body_start:]) if body_start > 0 else ''
            url = f"https://{host}{path}" if host != 'unknown' else path

            status = 0
            response_headers = {}
            response_body = ''
            if response is not None:
                try:
                    status = getattr(response, 'status_code', 0)
                    response_headers = dict(getattr(response, 'headers', {}))
                    response_body = getattr(response, 'text', '')
                except Exception:
                    status = 0
                    response_headers = {}
                    response_body = ''

            entry = {
                'method': method,
                'url': url,
                'host': host,
                'path': path,
                'status': status,
                'request_headers': headers,
                'request_body': body,
                'response_headers': response_headers,
                'response_body': response_body,
            }
            self.history.append(entry)
        except Exception as e:
            log.error(f"Erro ao adicionar ao histórico do Attacker: {e}", exc_info=True)

    def run(self):
        """
        Inicia o ataque com base no tipo configurado.
        Por enquanto, apenas o "Sniper" está implementado.
        """
        log.info(f"Iniciando ataque do tipo: {self.attack_type} com {len(self.payloads)} payloads.")

        # O ataque Sniper usa uma lista de payloads em uma posição de cada vez.
        # Simplificação: vamos usar apenas a primeira posição encontrada.
        if "§" not in self.raw_request:
            log.error("Nenhum marcador de payload (§...§) encontrado na requisição.")
            self.result_queue.put({'type': 'progress_done'})
            return

        total_requests = len(self.payloads)
        completed_requests = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            # Cria uma future para cada payload
            futures = {executor.submit(self._send_request_with_payload, p): p for p in self.payloads}

            for future in concurrent.futures.as_completed(futures):
                response = future.result()
                payload = futures[future]
                completed_requests += 1

                if self.result_queue:
                    progress = (completed_requests / total_requests) * 100
                    self.result_queue.put({'type': 'progress_update', 'value': progress})

                    if response:
                        # Monta o request bruto enviado
                        raw_request = re.sub(r'§.*?§', str(payload), self.raw_request, count=1)
                        # Extrai headers e corpo do request
                        req_headers = dict(getattr(response.request, 'headers', {})) if hasattr(response, 'request') else {}
                        req_body = getattr(response.request, 'body', b'') if hasattr(response, 'request') else b''
                        if isinstance(req_body, bytes):
                            req_body = req_body.decode(errors='ignore')
                        result_data = {
                            'url': response.request.url if hasattr(response, 'request') else '',
                            'status': response.status_code,
                            'length': len(response.content),
                            'payload': payload,
                            'raw_request': raw_request,
                            'method': getattr(response.request, 'method', ''),
                            'path': getattr(response.request, 'path_url', ''),
                            'host': req_headers.get('Host', ''),
                            'request_headers': req_headers,
                            'request_body': req_body,
                            'response_headers': dict(getattr(response, 'headers', {})),
                            'response_body': getattr(response, 'text', ''),
                        }
                    else:
                        result_data = {
                            'url': 'N/A',
                            'status': 'Error',
                            'length': 0,
                            'payload': payload,
                            'raw_request': re.sub(r'§.*?§', str(payload), self.raw_request, count=1),
                            'method': '',
                            'path': '',
                            'host': '',
                            'request_headers': {},
                            'request_body': '',
                            'response_headers': {},
                            'response_body': '',
                        }

                    self.result_queue.put({'type': 'result', 'data': result_data})

        log.info("Ataque concluído.")
        if self.result_queue:
            self.result_queue.put({'type': 'progress_done'})

    def _send_request_with_payload(self, payload: str):
        """
        Prepara e envia uma única requisição HTTP com o payload injetado.
        """
        try:
            # Substitui a primeira ocorrência do marcador com o payload.
            # re.sub(pattern, repl, string, count=1)
            modified_request = re.sub(r'§.*?§', str(payload), self.raw_request, count=1)

            # Reutiliza a função de envio do sender.py
            response = send_from_raw(
                raw_request=modified_request,
                proxy_port=self.proxy_port,
                use_tor=self.use_tor,
                tor_port=self.tor_port
            )

            # Adiciona ao histórico
            self._add_to_history(modified_request, response)

            return response

        except Exception as e:
            log.error(f"Erro ao enviar requisição no Attacker: {e}", exc_info=True)
            return None

def run_attacker(raw_request: str, attack_type: str, payloads: list, num_threads: int, result_queue: queue.Queue, proxy_port: int, use_tor: bool = False, tor_port: int = 9050, history=None):
    """
    Ponto de entrada para executar uma tarefa do Attacker.
    """
    attacker = Attacker(raw_request, attack_type, payloads, num_threads, result_queue, proxy_port, use_tor, tor_port, history)
    attacker.run()
