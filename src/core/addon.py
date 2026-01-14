from mitmproxy import http, websocket
from urllib.parse import parse_qs, urlencode, urlparse
from email.message import EmailMessage
from email.parser import BytesParser
from email.message import Message
from io import BytesIO

from .config import InterceptConfig
from .cookie_manager import CookieManager
from .history import RequestHistory
from .logger_config import log
from .scanner import VulnerabilityScanner
from .spider import Spider
from .websocket_history import WebSocketHistory
from .active_scanner import ActiveScanner
from .technology_manager import TechnologyManager
from .technology_detector import TechnologyDetector
from . import target_processor


class InterceptAddon:
    """Addon do mitmproxy para interceptar e modificar requisições"""

    def __init__(self, config: InterceptConfig, history: RequestHistory = None, cookie_manager: CookieManager = None, spider: Spider = None, websocket_history: WebSocketHistory = None, technology_manager: TechnologyManager = None):
        self.config = config
        self.history = history
        self.cookie_manager = cookie_manager

        # Componentes de detecção de tecnologia
        self.technology_manager = technology_manager if technology_manager is not None else TechnologyManager()
        self.technology_detector = TechnologyDetector()

        self.vulnerability_scanner = VulnerabilityScanner(
            technology_detector=self.technology_detector,
            technology_manager=self.technology_manager
        )  # Scanner passivo
        self.active_scanner = ActiveScanner()  # Scanner ativo
        self.spider = spider
        self.websocket_history = websocket_history

    def run_active_scan_on_request(self, request_id: int):
        """
        Executa o scanner ativo em uma requisição específica do histórico.
        """
        if not self.history:
            log.error("Histórico não está disponível para a varredura ativa.")
            return

        entry = self.history.get_entry_by_id(request_id)
        if not entry:
            log.error(f"Requisição com ID {request_id} não encontrada no histórico.")
            return

        # Prepara a requisição base para o scanner
        base_request = {
            'method': entry['method'],
            'url': entry['url'],
            'headers': entry['request_headers'],
            'body': entry['request_body'],
        }

        # Executa o scan
        vulnerabilities = self.active_scanner.scan_request(base_request)

        # Adiciona as vulnerabilidades encontradas ao histórico
        if vulnerabilities:
            self.history.add_vulnerabilities_to_entry(request_id, vulnerabilities)
            log.info(f"{len(vulnerabilities)} novas vulnerabilidades ativas adicionadas ao histórico para o ID {request_id}.")

    @staticmethod
    def _split_host_and_path(raw_host: str):
        """Normaliza host configurado, aceitando entradas com esquema ou URL completa."""
        if not raw_host:
            return "", ""
        parsed = urlparse(raw_host) if "://" in raw_host else urlparse(f"//{raw_host}")
        host = (parsed.hostname or parsed.netloc or "").lower()
        extra_path = parsed.path if (parsed.scheme or parsed.netloc) else ""
        if not host:
            host = raw_host.lower()
        return host, extra_path

    @staticmethod
    def _host_matches(request_host: str, rule_host: str) -> bool:
        """Verifica se o host da requisição corresponde ao host da regra."""
        if not rule_host:
            return True
        request_host = request_host.lower()
        rule_host = rule_host.lower()
        # Remove porta se presente
        request_host_no_port = request_host.split(':')[0]
        rule_host_no_port = rule_host.split(':')[0]
        if request_host_no_port == rule_host_no_port:
            return True
        return request_host_no_port.endswith(f".{rule_host_no_port}")

    def request(self, flow: http.HTTPFlow) -> None:
        """Intercepta requisições HTTP"""
        # Força upstream HTTP para servidores locais que não suportam TLS
        if flow.request.pretty_host in ['192.168.1.208:8081', '192.168.1.208']:
            flow.server_conn.scheme = 'http'
            log.info(f"Forçando upstream HTTP para {flow.request.pretty_host}")

        # Se o proxy estiver pausado, ignora todas as regras e o histórico
        if self.config.is_paused():
            return

        # Se a interceptação manual está ativada, pausa a requisição
        if self.config.is_intercept_enabled():
            # Prepara os dados da requisição para a fila
            flow_data = {
                'flow': flow,
                'method': flow.request.method,
                'url': flow.request.pretty_url,
                'headers': dict(flow.request.headers),
                'body': flow.request.content.decode('utf-8', errors='ignore') if flow.request.content else '',
                'host': flow.request.pretty_host,
                'path': flow.request.path,
            }
            
            # Adiciona à fila de interceptação
            self.config.add_to_intercept_queue(flow_data)
            log.info(f"Requisição interceptada: {flow.request.method} {flow.request.pretty_url}")
            
            # Aguarda decisão do usuário (Forward ou Drop)
            response = self.config.get_intercept_response(timeout=300)  # 5 minutos de timeout
            
            if response is None:
                # Timeout - cancela a requisição
                log.warning(f"Timeout na interceptação: {flow.request.pretty_url}")
                flow.kill()
                return
            
            if response['action'] == 'drop':
                # Usuário escolheu cancelar a requisição
                log.info(f"Requisição cancelada pelo usuário: {flow.request.pretty_url}")
                flow.kill()
                return
            
            if response['action'] == 'forward':
                # Usuário escolheu enviar a requisição (possivelmente modificada)
                if 'modified_body' in response:
                    flow.request.content = response['modified_body'].encode('utf-8')
                if 'modified_headers' in response:
                    flow.request.headers.clear()
                    for key, value in response['modified_headers'].items():
                        flow.request.headers[key] = value
                log.info(f"Requisição enviada pelo usuário: {flow.request.pretty_url}")
                # Continua o processamento normal

        request = flow.request

        for rule in self.config.get_rules():
            if not rule.get('enabled', True):
                continue

            # Verifica se a URL corresponde ao host e caminho configurados
            rule_host, host_path = self._split_host_and_path(rule.get('host', ''))
            normalized_rule_path = rule.get('path', '') or host_path or ""
            if normalized_rule_path and not normalized_rule_path.startswith('/'):
                normalized_rule_path = f"/{normalized_rule_path}"
            host_match = self._host_matches(request.pretty_host, rule_host)
            path_match = True if not normalized_rule_path else request.path.startswith(normalized_rule_path)

            if host_match and path_match:
                # Modifica parâmetros na query string (GET)
                if request.query:
                    query_dict = dict(request.query)
                    if rule['param_name'] in query_dict:
                        query_dict[rule['param_name']] = rule['param_value']
                        request.query.clear()
                        for key, value in query_dict.items():
                            request.query[key] = value
                        log.info(f"Regra GET aplicada: '{rule['param_name']}' -> '{rule['param_value']}' em {request.pretty_url}")

                # Modifica parâmetros no corpo (POST)
                if request.method == "POST" and request.content:
                    content_type = request.headers.get("content-type", "")

                    if "application/x-www-form-urlencoded" in content_type:
                        # Parse form data
                        body = request.content.decode('utf-8', errors='ignore')
                        params = parse_qs(body, keep_blank_values=True)

                        # Modifica o parâmetro se existir
                        if rule['param_name'] in params:
                            params[rule['param_name']] = [rule['param_value']]
                            # Reconstrói o corpo
                            new_body = urlencode(params, doseq=True)
                            request.content = new_body.encode('utf-8')
                            log.info(f"Regra POST aplicada: '{rule['param_name']}' -> '{rule['param_value']}' em {request.pretty_url}")

                    elif "multipart/form-data" in content_type:
                        # Para dados multipart/form-data
                        boundary = content_type.split("boundary=")[-1]
                        if not boundary:
                            log.warning(f"Boundary não encontrado para multipart/form-data em {request.pretty_url}")
                        else:
                            log.info(f"Processando multipart com boundary: {boundary}")
                            # Método alternativo: usar regex para substituir diretamente
                            try:
                                body_str = request.content.decode('utf-8', errors='ignore')
                                import re
                                # Padrão para encontrar o campo username
                                pattern = rf'(--{re.escape(boundary)}\r?\nContent-Disposition: form-data; name="username"\r?\n\r?\n)([^\r\n]*)(\r?\n)'
                                match = re.search(pattern, body_str)
                                if match:
                                    prefix = match.group(1)
                                    old_value = match.group(2)
                                    suffix = match.group(3)
                                    new_body = body_str.replace(f"{prefix}{old_value}{suffix}", f"{prefix}{rule['param_value']}{suffix}")
                                    request.content = new_body.encode('utf-8')
                                    log.info(f"Regra POST aplicada (multipart regex): '{rule['param_name']}' '{old_value}' -> '{rule['param_value']}' em {request.pretty_url}")
                                else:
                                    log.warning(f"Parâmetro '{rule['param_name']}' não encontrado via regex no multipart")
                            except Exception as e:
                                log.error(f"Erro ao processar multipart/form-data com regex em {request.pretty_url}: {e}")
                                import traceback
                                log.error(traceback.format_exc())

                    elif "application/json" in content_type:
                        # Para dados JSON
                        try:
                            import json
                            body = json.loads(request.content.decode('utf-8', errors='ignore'))
                            if isinstance(body, dict):
                                # Suporta caminhos aninhados com dot notation (ex: "data.username")
                                def set_nested_value(obj, key_path, value):
                                    keys = key_path.split('.')
                                    for key in keys[:-1]:
                                        obj = obj.setdefault(key, {})
                                    obj[keys[-1]] = value
                                
                                set_nested_value(body, rule['param_name'], rule['param_value'])
                                new_body = json.dumps(body)
                                request.content = new_body.encode('utf-8')
                                log.info(f"Regra POST aplicada (JSON): '{rule['param_name']}' -> '{rule['param_value']}' em {request.pretty_url}")
                        except Exception as e:
                            log.error(f"Erro ao processar application/json em {request.pretty_url}: {e}")

    def response(self, flow: http.HTTPFlow) -> None:
        """Intercepta respostas HTTP e armazena no histórico"""
        
        # Aplica regras de response
        if flow.response and flow.response.content:
            for rule in self.config.get_rules():
                if not rule.get('enabled', True) or rule.get('type', 'request') != 'response':
                    continue

                # Verifica se a URL corresponde ao host e caminho configurados
                rule_host, host_path = self._split_host_and_path(rule.get('host', ''))
                normalized_rule_path = rule.get('path', '') or host_path or ""
                if normalized_rule_path and not normalized_rule_path.startswith('/'):
                    normalized_rule_path = f"/{normalized_rule_path}"
                host_match = self._host_matches(flow.request.pretty_host, rule_host)
                path_match = True if not normalized_rule_path else flow.request.path.startswith(normalized_rule_path)

                if host_match and path_match:
                    content_type = flow.response.headers.get("content-type", "")

                    if "application/json" in content_type:
                        # Para dados JSON
                        try:
                            import json
                            body = json.loads(flow.response.content.decode('utf-8', errors='ignore'))
                            if isinstance(body, dict):
                                # Suporta caminhos aninhados com dot notation (ex: "data.primeiro_acesso")
                                def set_nested_value(obj, key_path, value):
                                    keys = key_path.split('.')
                                    for key in keys[:-1]:
                                        obj = obj.setdefault(key, {})
                                    obj[keys[-1]] = value
                                
                                set_nested_value(body, rule['param_name'], rule['param_value'])
                                new_body = json.dumps(body)
                                flow.response.content = new_body.encode('utf-8')
                                log.info(f"Regra RESPONSE aplicada (JSON): '{rule['param_name']}' -> '{rule['param_value']}' em {flow.request.pretty_url}")
                        except Exception as e:
                            log.error(f"Erro ao processar response JSON em {flow.request.pretty_url}: {e}")
        
        # Escaneia a resposta em busca de vulnerabilidades e tecnologias
        vulnerabilities = []
        if self.vulnerability_scanner and flow.response and self.config.is_in_scope(flow.request.pretty_url):
            vulnerabilities = self.vulnerability_scanner.scan_response(flow)
            
            # Preenche URL e método nas vulnerabilidades
            for vuln in vulnerabilities:
                if not vuln.get('url'):
                    vuln['url'] = flow.request.pretty_url
                if not vuln.get('method'):
                    vuln['method'] = flow.request.method
            
            # Log se vulnerabilidades foram encontradas
            if vulnerabilities:
                log.warning(f"Vulnerabilidades encontradas em {flow.request.pretty_url}: {len(vulnerabilities)}")
        
        # Armazena a requisição no histórico com vulnerabilidades
        if self.history is not None:
            self.history.add_request(flow, vulnerabilities=vulnerabilities)
            # Notifica UI se existir fila configurada
            try:
                ui_q = getattr(self.config, 'ui_queue', None)
                if ui_q:
                    # Envia a cópia dos dados básicos para a UI
                    entry = self.history.get_history()[-1]
                    ui_q.put({"type": "new_history_entry", "data": entry})
            except Exception:
                # Não falha o addon se a notificação da UI não funcionar
                pass

        # Processa e armazena os cookies
        if self.cookie_manager is not None and flow.response:
            self.cookie_manager.parse_and_store_cookies(
                host=flow.request.pretty_host,
                request_headers=dict(flow.request.headers),
                response_headers=dict(flow.response.headers)
            )
        
        # Processa a requisição para mapeamento do alvo e crawling
        target_processor.process_flow(flow, self.spider)

    def websocket_start(self, flow: http.HTTPFlow) -> None:
        """Chamado quando uma conexão WebSocket é estabelecida"""
        if self.websocket_history is not None and flow.websocket:
            flow_id = str(id(flow))
            url = flow.request.pretty_url
            host = flow.request.pretty_host
            self.websocket_history.add_connection(flow_id, url, host)
            log.info(f"WebSocket conectado: {url}")

    def websocket_message(self, flow: http.HTTPFlow) -> None:
        """Chamado quando uma mensagem WebSocket é recebida"""
        if self.websocket_history is not None and flow.websocket:
            flow_id = str(id(flow))
            # Processa a última mensagem
            message = flow.websocket.messages[-1]
            from_client = message.from_client
            content = message.content
            
            # Armazena a mensagem no histórico
            self.websocket_history.add_message(flow_id, content, from_client)
            
            direction = "Cliente → Servidor" if from_client else "Servidor → Cliente"
            log.info(f"WebSocket mensagem ({direction}): {len(content)} bytes em {flow.request.pretty_url}")

    def websocket_end(self, flow: http.HTTPFlow) -> None:
        """Chamado quando uma conexão WebSocket é fechada"""
        if self.websocket_history is not None and flow.websocket:
            flow_id = str(id(flow))
            self.websocket_history.close_connection(flow_id)
            log.info(f"WebSocket desconectado: {flow.request.pretty_url}")

