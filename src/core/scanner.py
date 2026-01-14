"""
Módulo de Scanner de Vulnerabilidades
Detecta vulnerabilidades comuns em requisições e respostas HTTP
"""
import re
from typing import Dict, List, Any
from .logger_config import log


from .technology_detector import TechnologyDetector
from .technology_manager import TechnologyManager
from mitmproxy import http
from .secret_patterns import SECRET_PATTERNS


class VulnerabilityScanner:
    """Scanner de vulnerabilidades para detecção automática de problemas de segurança"""
    
    def __init__(self, technology_detector: TechnologyDetector = None, technology_manager: TechnologyManager = None):
        self.technology_detector = technology_detector
        self.technology_manager = technology_manager
        self.sql_injection_patterns = [
            # MySQL errors
            r"(?i)sql\s+syntax",
            r"(?i)mysql_fetch",
            r"(?i)mysql_num_rows",
            r"(?i)mysql_query",
            r"(?i)mysql_error",
            r"(?i)warning.*mysql",
            r"(?i)you\s+have\s+an\s+error\s+in\s+your\s+sql\s+syntax",
            r"(?i)supplied\s+argument\s+is\s+not\s+a\s+valid\s+mysql",
            
            # PostgreSQL errors
            r"(?i)postgresql.*error",
            r"(?i)pg_query\(\)",
            r"(?i)pg_exec\(\)",
            r"(?i)unterminated\s+quoted\s+string",
            r"(?i)pg::syntaxerror",
            
            # MSSQL errors
            r"(?i)microsoft\s+sql\s+server",
            r"(?i)odbc\s+(microsoft|sql\s+server|driver)",
            r"(?i)unclosed\s+quotation\s+mark",
            r"(?i)quoted\s+string\s+not\s+properly\s+terminated",
            r"(?i)incorrect\s+syntax\s+near",
            r"(?i)\[sql\s+server\]",
            r"(?i)mssql_query",
            
            # Oracle errors
            r"(?i)ora-\d{5}",
            r"(?i)oracle.*error",
            r"(?i)oracle.*driver",
            r"(?i)warning.*oci_",
            r"(?i)warning.*ora_",
            
            # SQLite errors
            r"(?i)sqlite.*error",
            r"(?i)sqlite3::SQLException",
            r"(?i)warning.*sqlite",
            r"(?i)SQLITE_ERROR",
            
            # DB2 errors
            r"(?i)db2.*error",
            r"(?i)ibm.*driver",
            r"(?i)SQL\d{4}N",
            
            # Informix errors
            r"(?i)informix",
            r"(?i)ISAM\s+error",
            
            # Sybase errors
            r"(?i)sybase",
            r"(?i)warning.*sybase",
            
            # Generic SQL errors
            r"(?i)jdbc.*exception",
            r"(?i)sql\s+error",
            r"(?i)database\s+error",
            r"(?i)warning.*mysql_",
            r"(?i)valid\s+mysql\s+result",
            r"(?i)sqlstate\[\d+\]",
            r"(?i)syntax\s+error.*near",
            r"(?i)unexpected\s+end\s+of\s+sql\s+command",
            r"(?i)division\s+by\s+zero",
            r"(?i)invalid\s+query",
            r"(?i)sql\s+command\s+not\s+properly\s+ended",
            r"(?i)query\s+failed",
            r"(?i)error\s+in\s+your\s+sql",
        ]
        self.xss_reflection_patterns = [
            # Script tags
            r'<script[^>]*>.*?</script>',
            r'<script[^>]*>',
            r'</script>',
            
            # JavaScript protocols
            r'javascript:',
            r'jAvAsCrIpT:',
            r'javas\s*cript:',
            
            # Event handlers
            r'onerror\s*=',
            r'onload\s*=',
            r'onclick\s*=',
            r'onmouseover\s*=',
            r'onmouseout\s*=',
            r'onfocus\s*=',
            r'onblur\s*=',
            r'onchange\s*=',
            r'onsubmit\s*=',
            r'onkeydown\s*=',
            r'onkeyup\s*=',
            r'onkeypress\s*=',
            r'ondblclick\s*=',
            r'oncontextmenu\s*=',
            r'oninput\s*=',
            r'onbegin\s*=',
            r'onstart\s*=',
            r'ontoggle\s*=',
            
            # HTML tags
            r'<iframe[^>]*>',
            r'<object[^>]*>',
            r'<embed[^>]*>',
            r'<img[^>]*>',
            r'<svg[^>]*>',
            r'<body[^>]*>',
            r'<input[^>]*>',
            r'<form[^>]*>',
            r'<video[^>]*>',
            r'<audio[^>]*>',
            r'<link[^>]*>',
            r'<meta[^>]*>',
            r'<style[^>]*>',
            
            # Data URIs
            r'data:text/html',
            r'data:text/javascript',
            r'data:application/javascript',
            
            # AngularJS
            r'\{\{.*constructor.*\}\}',
            r'\{\{.*alert.*\}\}',
            r'\{\{.*eval.*\}\}',
            
            # VBScript (IE)
            r'vbscript:',
            r'<script[^>]*language\s*=\s*["\']?vbscript',
            
            # Expression (IE)
            r'expression\s*\(',
            r'style\s*=\s*["\'][^"\']*expression',
            
            # Import
            r'@import',
            
            # Special identifiers for testing
            r'<xss>',
            r'activescanner',
        ]
        self.path_traversal_patterns = [
            # Basic path traversal patterns
            r'\.\./.*\.\./.*\.\.',  # Multiple ../
            r'\.\.[\\/]',
            
            # Linux/Unix specific
            r'[\\/]etc[\\/]passwd',
            r'[\\/]etc[\\/]shadow',
            r'[\\/]etc[\\/]hosts',
            r'[\\/]proc[\\/]self[\\/]environ',
            r'[\\/]proc[\\/]version',
            r'[\\/]proc[\\/]cmdline',
            r'[\\/]home[\\/]',
            r'[\\/]root[\\/]',
            r'[\\/]var[\\/]log',
            r'[\\/]var[\\/]www',
            
            # Windows specific
            r'[\\/]windows[\\/]win\.ini',
            r'[\\/]winnt[\\/]win\.ini',
            r'[\\/]boot\.ini',
            r'[\\/]windows[\\/]system32',
            r'[\\/]windows[\\/]system\.ini',
            r'C:\\\\windows',
            r'C:\\\\winnt',
            r'C:\\\\boot\.ini',
            
            # URL encoded variants - Single encoding
            r'%2e%2e%2f',  # ../
            r'%2e%2e[\\/]',
            r'%2e%2e%5c',  # ..\
            r'\.\.%2f',
            r'\.\.%5c',
            
            # URL encoded variants - Double encoding
            r'%252e%252e%252f',
            r'%252e%252e%255c',
            
            # UTF-8 encoding
            r'%c0%ae%c0%ae%c0%af',
            r'%e0%80%ae%e0%80%ae%e0%80%af',
            
            # Dot variations
            r'\.\.\.[\\/]',
            r'\.\.\.\.[\\/]',
            r'\.\.\.\.\.[\\/]',
            
            # Filter bypass
            r'\.\.;[\\/]',
            r'\.\.\x00[\\/]',
            r'\.\.[\\/]\.\.[\\/]\.\.[\\/]',
            
            # Backslash variations
            r'\.\.\\\\',
            r'\\\\\.\.\\\\',
            
            # Multiple encodings mixed
            r'\.\.%5c',
            r'%2e%2e\\\\',
            
            # Specific file access patterns
            r'file:///',
            r'file:\\\\\\\\',
            
            # Null byte injection
            r'\.\.%00',
            r'%00\.\.[\\/]',
        ]
        self.sensitive_info_patterns = [
            # Passwords and keys
            (r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?([^"\'\s]{3,})', 'Senha em texto claro'),
            (r'(?i)api[_-]?key\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{10,})', 'API Key exposta'),
            (r'(?i)secret[_-]?key\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{10,})', 'Secret Key exposta'),
            (r'(?i)access[_-]?key\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{10,})', 'Access Key exposta'),
            (r'(?i)client[_-]?secret\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{10,})', 'Client Secret exposto'),
            
            # Tokens
            (r'(?i)token\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]{20,})', 'Token exposto'),
            (r'(?i)auth[_-]?token\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]{20,})', 'Auth Token exposto'),
            (r'(?i)session[_-]?token\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]{20,})', 'Session Token exposto'),
            (r'(?i)csrf[_-]?token\s*[:=]\s*["\']?([a-zA-Z0-9_\-\.]{20,})', 'CSRF Token exposto'),
            (r'(?i)jwt\s*[:=]\s*["\']?(eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+)', 'JWT Token exposto'),
            
            # Authorization headers
            (r'(?i)authorization:\s*bearer\s+([a-zA-Z0-9_\-\.]{20,})', 'Bearer Token exposto'),
            (r'(?i)authorization:\s*basic\s+([a-zA-Z0-9+/=]{20,})', 'Basic Auth exposto'),
            
            # AWS credentials
            (r'(?i)aws[_-]?access[_-]?key[_-]?id\s*[:=]\s*["\']?(AKIA[A-Z0-9]{16})', 'AWS Access Key'),
            (r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{40})', 'AWS Secret Key'),
            (r'(?i)aws[_-]?session[_-]?token\s*[:=]\s*["\']?([a-zA-Z0-9/+=]{100,})', 'AWS Session Token'),
            
            # Google Cloud
            (r'(?i)google[_-]?api[_-]?key\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{39})', 'Google API Key'),
            (r'(?i)gcp[_-]?key\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{39})', 'GCP Key'),
            
            # Azure
            (r'(?i)azure[_-]?key\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{32,})', 'Azure Key'),
            
            # GitHub
            (r'(?i)github[_-]?token\s*[:=]\s*["\']?(ghp_[a-zA-Z0-9]{36})', 'GitHub Personal Access Token'),
            (r'(?i)github[_-]?app[_-]?token\s*[:=]\s*["\']?(ghs_[a-zA-Z0-9]{36})', 'GitHub App Token'),
            (r'(?i)github[_-]?oauth\s*[:=]\s*["\']?(gho_[a-zA-Z0-9]{36})', 'GitHub OAuth Token'),
            
            # GitLab
            (r'(?i)gitlab[_-]?token\s*[:=]\s*["\']?([a-zA-Z0-9_\-]{20,})', 'GitLab Token'),
            
            # Slack
            (r'(?i)slack[_-]?token\s*[:=]\s*["\']?(xox[a-zA-Z]-[a-zA-Z0-9-]{10,})', 'Slack Token'),
            (r'(?i)slack[_-]?webhook\s*[:=]\s*["\']?(https://hooks\.slack\.com/services/[A-Z0-9/]+)', 'Slack Webhook'),
            
            # Stripe
            (r'(?i)stripe[_-]?key\s*[:=]\s*["\']?(sk_live_[a-zA-Z0-9]{24,})', 'Stripe Live Key'),
            (r'(?i)stripe[_-]?test\s*[:=]\s*["\']?(sk_test_[a-zA-Z0-9]{24,})', 'Stripe Test Key'),
            
            # Private keys
            (r'(?i)private[_-]?key', 'Chave Privada mencionada'),
            (r'-----BEGIN\s+(RSA|OPENSSH|EC|PGP|DSA)?\s*PRIVATE\s+KEY-----', 'Chave Privada'),
            (r'-----BEGIN\s+PRIVATE\s+KEY-----', 'Chave Privada'),
            
            # Connection strings
            (r'(?i)connection[_-]?string\s*[:=]', 'Connection String'),
            (r'(?i)database[_-]?url\s*[:=]', 'Database URL'),
            (r'(?i)mongodb://[^"\'\s]+', 'MongoDB Connection String'),
            (r'(?i)mysql://[^"\'\s]+', 'MySQL Connection String'),
            (r'(?i)postgresql://[^"\'\s]+', 'PostgreSQL Connection String'),
            (r'(?i)postgres://[^"\'\s]+', 'PostgreSQL Connection String'),
            (r'(?i)redis://[^"\'\s]+', 'Redis Connection String'),
            
            # Email addresses
            (r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', 'Endereço de e-mail'),
            
            # IP addresses
            (r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', 'Endereço IP'),
            
            # Credit cards
            (r'(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9][0-9])[0-9]{12}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|(?:2131|1800|35\d{3})\d{11})', 'Número de Cartão de Crédito'),
            
            # Social Security Numbers (US)
            (r'\b\d{3}-\d{2}-\d{4}\b', 'Possível SSN (US)'),
            
            # Encryption keys patterns
            (r'(?i)encryption[_-]?key\s*[:=]\s*["\']?([a-zA-Z0-9+/=]{16,})', 'Encryption Key'),
            (r'(?i)cipher[_-]?key\s*[:=]\s*["\']?([a-zA-Z0-9+/=]{16,})', 'Cipher Key'),
            
            # Twilio
            (r'(?i)twilio[_-]?auth\s*[:=]\s*["\']?([a-z0-9]{32})', 'Twilio Auth Token'),
            
            # SendGrid
            (r'(?i)sendgrid[_-]?key\s*[:=]\s*["\']?(SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43})', 'SendGrid API Key'),
            
            # Heroku
            (r'(?i)heroku[_-]?key\s*[:=]\s*["\']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})', 'Heroku API Key'),
            
            # MailChimp
            (r'(?i)mailchimp[_-]?key\s*[:=]\s*["\']?([a-f0-9]{32}-us[0-9]{1,2})', 'MailChimp API Key'),
            
            # PayPal
            (r'(?i)paypal[_-]?token\s*[:=]\s*["\']?(access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32})', 'PayPal Token'),
            
            # Firebase
            (r'(?i)firebase[_-]?api\s*[:=]\s*["\']?(AIza[a-zA-Z0-9_-]{35})', 'Firebase API Key'),
            
            # NPM token
            (r'(?i)npm[_-]?token\s*[:=]\s*["\']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})', 'NPM Token'),
        ]
        self.cve_patterns = [
            # Apache vulnerabilities
            (r'Apache/2\.4\.49', 'CVE-2021-41773 - Path Traversal Apache 2.4.49'),
            (r'Apache/2\.4\.50', 'CVE-2021-42013 - Path Traversal Apache 2.4.50'),
            (r'Apache/2\.4\.[0-4][0-9]', 'Apache 2.4.x - Verificar CVEs conhecidas'),
            (r'Apache/2\.2\.', 'Apache 2.2.x (EOL) - Verificar CVEs conhecidas'),
            (r'Apache/1\.', 'Apache 1.x (EOL) - Múltiplas vulnerabilidades'),
            
            # Log4j vulnerabilities
            (r'(?i)log4j.*2\.(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16)', 'Possível Log4Shell (CVE-2021-44228)'),
            (r'(?i)log4j-core.*2\.(0|1|2|3|4|5|6|7|8|9|10|11|12|13|14|15|16)', 'Possível Log4Shell (CVE-2021-44228)'),
            
            # Struts vulnerabilities
            (r'(?i)struts.*2\.[0-5]\.', 'Apache Struts 2.x - Verificar CVEs (incluindo S2-045, S2-046)'),
            (r'(?i)struts', 'Apache Struts - Verificar CVEs conhecidas'),
            
            # Spring vulnerabilities
            (r'(?i)spring.*framework.*[45]\.', 'Spring Framework - Verificar Spring4Shell (CVE-2022-22965)'),
            (r'(?i)spring.*framework.*3\.', 'Spring Framework 3.x - Verificar CVEs conhecidas'),
            (r'(?i)spring.*boot.*[12]\.', 'Spring Boot - Verificar CVEs conhecidas'),
            
            # PHP vulnerabilities
            (r'(?i)php/[45]\.', 'PHP 4.x/5.x - Verificar CVEs conhecidas'),
            (r'(?i)php/7\.[0-2]\.', 'PHP 7.0-7.2 - Verificar CVEs conhecidas'),
            (r'(?i)phpMyAdmin/[234]\.', 'phpMyAdmin - Verificar CVEs conhecidas'),
            
            # WordPress vulnerabilities
            (r'(?i)WordPress/[345]\.', 'WordPress - Verificar vulnerabilidades conhecidas'),
            (r'(?i)wp-content', 'WordPress detectado - Verificar plugins vulneráveis'),
            
            # Drupal vulnerabilities
            (r'(?i)Drupal\s+[78]\.', 'Drupal - Verificar Drupalgeddon'),
            (r'(?i)Drupal\s+[6]\.', 'Drupal 6.x (EOL) - Múltiplas vulnerabilidades'),
            
            # Joomla vulnerabilities
            (r'(?i)Joomla\s+[123]\.', 'Joomla - Verificar CVEs conhecidas'),
            
            # jQuery vulnerabilities
            (r'(?i)jQuery\s+(1\.|2\.|3\.[0-4])', 'jQuery versão antiga - XSS vulnerabilities'),
            (r'(?i)jquery-1\.[0-8]', 'jQuery 1.x antiga - Múltiplas vulnerabilidades'),
            
            # Node.js vulnerabilities
            (r'(?i)Node\.js/[0-9]\.[0-9]\.', 'Node.js - Verificar versão para CVEs'),
            (r'(?i)Express/[34]\.', 'Express.js - Verificar CVEs conhecidas'),
            
            # Tomcat vulnerabilities
            (r'(?i)Apache-Coyote/1\.1', 'Apache Tomcat - Verificar CVEs'),
            (r'(?i)Tomcat/[6789]\.', 'Apache Tomcat - Verificar CVEs conhecidas'),
            
            # Nginx vulnerabilities
            (r'(?i)nginx/1\.[0-9]\.', 'Nginx - Verificar CVEs conhecidas'),
            (r'(?i)nginx/0\.', 'Nginx versão antiga - Múltiplas vulnerabilidades'),
            
            # IIS vulnerabilities
            (r'(?i)Microsoft-IIS/[6789]\.', 'IIS - Verificar CVEs conhecidas'),
            (r'(?i)Microsoft-IIS/10\.', 'IIS 10 - Verificar CVEs conhecidas'),
            
            # ASP.NET vulnerabilities
            (r'(?i)ASP\.NET', 'ASP.NET - Verificar CVEs conhecidas'),
            (r'(?i)X-AspNet-Version:\s*[1-3]\.', 'ASP.NET versão antiga - Verificar CVEs'),
            
            # Jenkins vulnerabilities
            (r'(?i)Jenkins/[12]\.', 'Jenkins - Verificar CVEs conhecidas'),
            
            # ElasticSearch vulnerabilities
            (r'(?i)elasticsearch/[1-6]\.', 'ElasticSearch - Verificar CVEs conhecidas'),
            
            # MongoDB vulnerabilities
            (r'(?i)MongoDB/[23]\.', 'MongoDB - Verificar CVEs conhecidas'),
            
            # Redis vulnerabilities
            (r'(?i)Redis/[2-5]\.', 'Redis - Verificar CVEs conhecidas'),
            
            # OpenSSL vulnerabilities
            (r'(?i)OpenSSL/1\.0\.', 'OpenSSL 1.0.x - Heartbleed e outras vulnerabilidades'),
            (r'(?i)OpenSSL/0\.', 'OpenSSL 0.x - Múltiplas vulnerabilidades críticas'),
            
            # Django vulnerabilities
            (r'(?i)Django/[12]\.', 'Django - Verificar CVEs conhecidas'),
            
            # Rails vulnerabilities
            (r'(?i)Ruby on Rails/[34]\.', 'Ruby on Rails - Verificar CVEs conhecidas'),
            (r'(?i)Rails/[34]\.', 'Ruby on Rails - Verificar CVEs conhecidas'),
            
            # Flask vulnerabilities
            (r'(?i)Flask/0\.', 'Flask versão antiga - Verificar CVEs'),
            
            # Laravel vulnerabilities
            (r'(?i)Laravel/[45]\.', 'Laravel - Verificar CVEs conhecidas'),
            
            # Angular vulnerabilities
            (r'(?i)Angular/[1-9]\.', 'Angular - Verificar CVEs conhecidas'),
            
            # React vulnerabilities
            (r'(?i)React/1[0-5]\.', 'React versão antiga - Verificar CVEs'),
            
            # Vue.js vulnerabilities
            (r'(?i)Vue\.js/[12]\.', 'Vue.js - Verificar CVEs conhecidas'),
            
            # Microsoft Exchange vulnerabilities
            (r'(?i)Microsoft.*Exchange', 'Microsoft Exchange - Verificar ProxyShell, ProxyLogon'),
            
            # Confluence vulnerabilities
            (r'(?i)Confluence/[67]\.', 'Atlassian Confluence - Verificar CVEs conhecidas'),
            
            # JIRA vulnerabilities
            (r'(?i)JIRA/[67]\.', 'Atlassian JIRA - Verificar CVEs conhecidas'),
            
            # vBulletin vulnerabilities
            (r'(?i)vBulletin\s+[345]\.', 'vBulletin - Verificar CVEs conhecidas'),
            
            # Magento vulnerabilities
            (r'(?i)Magento/[12]\.', 'Magento - Verificar CVEs conhecidas'),
            
            # WebLogic vulnerabilities
            (r'(?i)WebLogic', 'Oracle WebLogic - Verificar CVEs de desserialização'),
        ]
        self.csrf_indicators = [
            'csrf',
            'xsrf',
            '_token',
            'authenticity_token',
            'anti-forgery',
        ]

    def _detect_technologies(self, flow: http.HTTPFlow):
        if not self.technology_detector or not self.technology_manager:
            return
        try:
            detected_techs = self.technology_detector.detect(flow)
            if detected_techs:
                hostname = flow.request.host
                for tech in detected_techs:
                    self.technology_manager.add_technology(hostname, tech)
                log.info(f"Tecnologias detectadas para {hostname}: {', '.join(detected_techs)}")
        except Exception as e:
            log.error(f"Erro ao detectar tecnologias para {flow.request.pretty_url}: {e}")

    def scan_response(self, flow: http.HTTPFlow) -> List[Dict[str, Any]]:
        request_data = {
            'method': flow.request.method,
            'url': flow.request.pretty_url,
            'headers': dict(flow.request.headers),
            'body': flow.request.get_text(strict=False) or "",
        }
        response_data = {
            'status': flow.response.status_code,
            'headers': dict(flow.response.headers),
            'body': flow.response.get_text(strict=False) or "",
        }
        vulnerabilities = []
        vulnerabilities.extend(self._scan_for_secrets(request_data, response_data))
        vulnerabilities.extend(self._detect_sql_injection(request_data, response_data))
        vulnerabilities.extend(self._detect_xss(request_data, response_data))
        vulnerabilities.extend(self._detect_path_traversal(request_data, response_data))
        vulnerabilities.extend(self._detect_sensitive_info(request_data, response_data))
        vulnerabilities.extend(self._detect_cve(request_data, response_data))
        vulnerabilities.extend(self._detect_csrf(request_data, response_data))
        vulnerabilities.extend(self._detect_missing_security_headers(request_data, response_data))
        vulnerabilities.extend(self._detect_insecure_cookies(request_data, response_data))
        vulnerabilities.extend(self._detect_information_leakage(request_data, response_data))
        vulnerabilities.extend(self._scan_javascript_content(request_data, response_data))
        return vulnerabilities

    def _scan_for_secrets(self, request_data: Dict, response_data: Dict) -> List[Dict]:
        """Analisa o corpo e os cabeçalhos da resposta em busca de segredos hardcoded."""
        vulnerabilities = []
        # Combina headers e body em um único texto para a busca
        content_to_scan = str(response_data.get('headers', {})) + response_data.get('body', '')

        for secret in SECRET_PATTERNS:
            pattern = secret['Pattern']
            name = secret['Name']
            
            matches = pattern.finditer(content_to_scan)
            for match in matches:
                evidence = match.group(0)
                # Limita o tamanho da evidência para não poluir a UI
                if len(evidence) > 150:
                    evidence = evidence[:147] + '...'

                vulnerabilities.append({
                    'type': 'Exposição de Dados Sensíveis',
                    'severity': 'High',
                    'source': 'Passive',
                    'description': f'Detectado um possível segredo do tipo: {name}',
                    'evidence': evidence,
                    'url': request_data.get('url', ''),
                    'method': request_data.get('method', ''),
                })
                log.critical(f"Segredo '{name}' detectado em {request_data.get('url', '')}")
        return vulnerabilities
    
    def _scan_javascript_content(self, request_data: Dict, response_data: Dict) -> List[Dict]:
        vulnerabilities = []
        content_type = response_data.get('headers', {}).get('Content-Type', '')
        url = request_data.get('url', '')
        if 'javascript' not in content_type and not url.endswith('.js'):
            return vulnerabilities
        response_body = response_data.get('body', '')
        if not response_body:
            return vulnerabilities
        log.info(f"Analisando conteúdo JavaScript de: {url}")
        js_patterns = [
            (r'(?i)("|")((?:[a-zA-Z0-9-_.]*(?:api_key|secret|token))|(?:AKIA[A-Z0-9]{16})|(?:bearer\s+[a-zA-Z0-9-_\.]{20,}))("|")\s*[:=]\s*("|")([a-zA-Z0-9-_\.]{16,})("|")', 'Possível Chave de API ou Segredo Hard-coded'),
            (r'("|")((https?://|/)[a-zA-Z0-9-_./]*(?:api|v[1-9]|private|admin|prod|dev)[a-zA-Z0-9-_./]*)("|")', 'Endpoint de API ou URL Interno Encontrado'),
            (r'//.*(password|secret|key|token|debug|admin|todo)', 'Comentário Sensível Encontrado'),
        ]
        for pattern, description in js_patterns:
            matches = re.finditer(pattern, response_body, re.IGNORECASE)
            for match in matches:
                evidence = match.group(0).strip()
                if len(evidence) > 250: continue
                vulnerabilities.append({
                    'type': 'Análise de JavaScript',
                    'severity': 'Low',
                    'source': 'Passive',
                    'description': description,
                    'evidence': evidence,
                    'url': url,
                    'method': request_data.get('method', ''),
                })
                log.warning(f"Descoberta em JavaScript ({description}) em {url}: {evidence}")
        return vulnerabilities

    def _detect_sql_injection(self, request_data: Dict, response_data: Dict) -> List[Dict]:
        vulnerabilities = []
        response_body = response_data.get('body', '')
        for pattern in self.sql_injection_patterns:
            if re.search(pattern, response_body, re.IGNORECASE):
                vulnerabilities.append({
                    'type': 'SQL Injection',
                    'severity': 'High',
                    'source': 'Passive',
                    'description': 'Possível SQL Injection detectado - Mensagem de erro de banco de dados na resposta',
                    'evidence': re.search(pattern, response_body, re.IGNORECASE).group(0),
                    'url': request_data.get('url', ''),
                    'method': request_data.get('method', ''),
                })
                log.warning(f"SQL Injection detectado em {request_data.get('url', '')}")
                break
        return vulnerabilities
    
    def _detect_xss(self, request_data: Dict, response_data: Dict) -> List[Dict]:
        vulnerabilities = []
        response_body = response_data.get('body', '')
        request_params = request_data.get('body', '') + request_data.get('url', '')
        for pattern in self.xss_reflection_patterns:
            matches_in_request = re.findall(pattern, request_params, re.IGNORECASE)
            for match in matches_in_request:
                if match in response_body:
                    vulnerabilities.append({
                        'type': 'XSS (Cross-Site Scripting)',
                        'severity': 'High',
                        'source': 'Passive',
                        'description': 'Possível XSS refletido - Payload encontrado na resposta',
                        'evidence': match[:100],
                        'url': request_data.get('url', ''),
                        'method': request_data.get('method', ''),
                    })
                    log.warning(f"XSS refletido detectado em {request_data.get('url', '')}")
                    return vulnerabilities
        return vulnerabilities
    
    def _detect_path_traversal(self, request_data: Dict, response_data: Dict) -> List[Dict]:
        vulnerabilities = []
        request_url = request_data.get('url', '')
        request_body = request_data.get('body', '')
        response_body = response_data.get('body', '')
        for pattern in self.path_traversal_patterns:
            if re.search(pattern, request_url) or re.search(pattern, request_body):
                if re.search(r'root:.*:0:0:|daemon:|bin:|sys:', response_body):
                    vulnerabilities.append({
                        'type': 'Path Traversal',
                        'severity': 'Critical',
                        'source': 'Passive',
                        'description': 'Path Traversal confirmado - Arquivo do sistema detectado na resposta',
                        'evidence': 'Conteúdo de arquivo do sistema encontrado',
                        'url': request_data.get('url', ''),
                        'method': request_data.get('method', ''),
                    })
                    log.critical(f"Path Traversal crítico detectado em {request_data.get('url', '')}")
                    break
                elif response_data.get('status', 0) == 200:
                    vulnerabilities.append({
                        'type': 'Path Traversal',
                        'severity': 'Medium',
                        'source': 'Passive',
                        'description': 'Possível Path Traversal - Tentativa detectada com resposta 200',
                        'evidence': re.search(pattern, request_url or request_body).group(0),
                        'url': request_data.get('url', ''),
                        'method': request_data.get('method', ''),
                    })
                    log.warning(f"Possível Path Traversal detectado em {request_data.get('url', '')}")
                    break
        return vulnerabilities
    
    def _detect_sensitive_info(self, request_data: Dict, response_data: Dict) -> List[Dict]:
        vulnerabilities = []
        response_body = response_data.get('body', '')
        response_headers = response_data.get('headers', {})
        for pattern, description in self.sensitive_info_patterns:
            matches = re.finditer(pattern, response_body, re.IGNORECASE)
            for match in matches:
                vulnerabilities.append({
                    'type': 'Informação Sensível Exposta',
                    'severity': 'Medium',
                    'source': 'Passive',
                    'description': description,
                    'evidence': match.group(0)[:100],
                    'url': request_data.get('url', ''),
                    'method': request_data.get('method', ''),
                })
                log.warning(f"Informação sensível detectada: {description}")
                break
        sensitive_headers = ['X-Api-Key', 'X-Auth-Token', 'Authorization']
        for header in sensitive_headers:
            if header.lower() in [h.lower() for h in response_headers.keys()]:
                vulnerabilities.append({
                    'type': 'Informação Sensível Exposta',
                    'severity': 'Low',
                    'source': 'Passive',
                    'description': f'Header sensível exposto: {header}',
                    'evidence': header,
                    'url': request_data.get('url', ''),
                    'method': request_data.get('method', ''),
                })
        return vulnerabilities
    
    def _detect_cve(self, request_data: Dict, response_data: Dict) -> List[Dict]:
        vulnerabilities = []
        response_headers = response_data.get('headers', {})
        response_body = response_data.get('body', '')
        server_header = response_headers.get('Server', '') or response_headers.get('server', '')
        for pattern, description in self.cve_patterns:
            if re.search(pattern, server_header, re.IGNORECASE):
                vulnerabilities.append({
                    'type': 'CVE / Vulnerabilidade Conhecida',
                    'severity': 'High',
                    'source': 'Passive',
                    'description': description,
                    'evidence': server_header,
                    'url': request_data.get('url', ''),
                    'method': request_data.get('method', ''),
                })
                log.warning(f"CVE detectada: {description}")
            if re.search(pattern, response_body, re.IGNORECASE):
                match = re.search(pattern, response_body, re.IGNORECASE)
                vulnerabilities.append({
                    'type': 'CVE / Vulnerabilidade Conhecida',
                    'severity': 'Medium',
                    'source': 'Passive',
                    'description': description,
                    'evidence': match.group(0),
                    'url': request_data.get('url', ''),
                    'method': request_data.get('method', ''),
                })
                log.warning(f"CVE detectada no body: {description}")
                break
        return vulnerabilities
    
    def _detect_csrf(self, request_data: Dict, response_data: Dict) -> List[Dict]:
        vulnerabilities = []
        method = request_data.get('method', '').upper()
        if method not in ['POST', 'PUT', 'DELETE', 'PATCH']:
            return vulnerabilities
        request_body = request_data.get('body', '')
        request_headers = request_data.get('headers', {})
        has_csrf_token = False
        for indicator in self.csrf_indicators:
            if indicator in request_body.lower():
                has_csrf_token = True
                break
            for header_name in request_headers.keys():
                if indicator in header_name.lower():
                    has_csrf_token = True
                    break
        if not has_csrf_token:
            vulnerabilities.append({
                'type': 'CSRF (Cross-Site Request Forgery)',
                'severity': 'Medium',
                'source': 'Passive',
                'description': 'Possível falta de proteção CSRF - Token não detectado em requisição que modifica estado',
                'evidence': f'Método {method} sem token CSRF aparente',
                'url': request_data.get('url', ''),
                'method': method,
            })
            log.info(f"Possível falta de proteção CSRF em {request_data.get('url', '')}")
        return vulnerabilities
    
    def format_vulnerabilities_report(self, vulnerabilities: List[Dict]) -> str:
        if not vulnerabilities:
            return "Nenhuma vulnerabilidade detectada."
        report = f"\n={'='*80}\n"
        report += f"RELATÓRIO DE VULNERABILIDADES ({len(vulnerabilities)} encontrada(s))\n"
        report += f"{ '='*80}\n\n"
        for i, vuln in enumerate(vulnerabilities, 1):
            report += f"{i}. {vuln['type']}\n"
            report += f"   Severidade: {vuln['severity']}\n"
            report += f"   URL: {vuln.get('url', 'N/A')}\n"
            report += f"   Método: {vuln.get('method', 'N/A')}\n"
            report += f"   Descrição: {vuln['description']}\n"
            report += f"   Evidência: {vuln.get('evidence', 'N/A')}\n"
            report += f"   {'-'*78}\n"
        return report

    def _detect_missing_security_headers(self, request_data: Dict, response_data: Dict) -> List[Dict]:
        vulnerabilities = []
        headers = {k.lower(): v for k, v in response_data.get('headers', {}).items()}
        security_headers = {
            'strict-transport-security': {
                'severity': 'Medium',
                'description': 'Ausência do cabeçalho Strict-Transport-Security (HSTS)',
            },
            'x-frame-options': {
                'severity': 'Medium',
                'description': 'Ausência do cabeçalho X-Frame-Options (proteção contra Clickjacking)',
            },
            'x-content-type-options': {
                'severity': 'Low',
                'description': 'Ausência do cabeçalho X-Content-Type-Options (proteção contra MIME sniffing)',
            },
            'content-security-policy': {
                'severity': 'High',
                'description': 'Ausência do cabeçalho Content-Security-Policy (CSP)',
            }
        }
        for header, details in security_headers.items():
            if header not in headers:
                vulnerabilities.append({
                    'type': 'Missing Security Header',
                    'severity': details['severity'],
                    'source': 'Passive',
                    'description': details['description'],
                    'evidence': f"O cabeçalho '{header}' não foi encontrado na resposta.",
                    'url': request_data.get('url', ''),
                    'method': request_data.get('method', ''),
                })
                log.info(f"Cabeçalho de segurança ausente detectado em {request_data.get('url', '')}: {header}")
        return vulnerabilities

    def _detect_insecure_cookies(self, request_data: Dict, response_data: Dict) -> List[Dict]:
        vulnerabilities = []
        headers = response_data.get('headers', {})
        set_cookie_headers = [v for k, v in headers.items() if k.lower() == 'set-cookie']
        for cookie_str in set_cookie_headers:
            cookie_name = cookie_str.split(';')[0].split('=')[0]
            if 'secure' not in cookie_str.lower():
                vulnerabilities.append({
                    'type': 'Insecure Cookie',
                    'severity': 'Medium',
                    'source': 'Passive',
                    'description': f"O cookie '{cookie_name}' não possui o atributo 'Secure'.",
                    'evidence': cookie_str,
                    'url': request_data.get('url', ''),
                    'method': request_data.get('method', ''),
                })
            if 'httponly' not in cookie_str.lower():
                vulnerabilities.append({
                    'type': 'Insecure Cookie',
                    'severity': 'Medium',
                    'source': 'Passive',
                    'description': f"O cookie '{cookie_name}' não possui o atributo 'HttpOnly'.",
                    'evidence': cookie_str,
                    'url': request_data.get('url', ''),
                    'method': request_data.get('method', ''),
                })
            if 'samesite' not in cookie_str.lower():
                vulnerabilities.append({
                    'type': 'Insecure Cookie',
                    'severity': 'Low',
                    'source': 'Passive',
                    'description': f"O cookie '{cookie_name}' não possui o atributo 'SameSite', o que pode permitir ataques CSRF.",
                    'evidence': cookie_str,
                    'url': request_data.get('url', ''),
                    'method': request_data.get('method', ''),
                })
        return vulnerabilities

    def _detect_information_leakage(self, request_data: Dict, response_data: Dict) -> List[Dict]:
        vulnerabilities = []
        headers = {k.lower(): v for k, v in response_data.get('headers', {}).items()}
        leaking_headers = ['server', 'x-powered-by', 'x-aspnet-version']
        for header in leaking_headers:
            if header in headers:
                vulnerabilities.append({
                    'type': 'Information Leakage',
                    'severity': 'Low',
                    'source': 'Passive',
                    'description': f"O cabeçalho '{header}' pode vazar informações sobre a tecnologia do servidor.",
                    'evidence': f"{header}: {headers[header]}",
                    'url': request_data.get('url', ''),
                    'method': request_data.get('method', ''),
                })
                log.info(f"Vazamento de informação detectado em {request_data.get('url', '')}: {header}")
        return vulnerabilities
