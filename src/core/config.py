import json
import os
import queue
import threading
from urllib.parse import urlparse
import fnmatch

# --- AI Config ---
AI_CONFIG_FILE = os.path.join("config", "ai_config.json")

def get_default_ai_config():
    """Retorna a configuração padrão da IA."""
    return {
        "api_key": "",
        "model": "gemini-2.5-flash-lite",
        "prompt": "Você é um especialista em segurança da informação e está gerando um relatório técnico detalhado com base em dados coletados durante um teste de penetração. Os dados incluem tráfego HTTP (requisições e respostas), vulnerabilidades identificadas pelos scanners e tecnologias detectadas.\\n\\nPor favor, organize o relatório nas seguintes seções:\\n\\n# 1. **Resumo Executivo**\\n   - Forneça um parágrafo conciso descrevendo o estado geral de segurança da aplicação com base nos dados fornecidos.\\n\\n# 2. **Vulnerabilidades Identificadas**\\n   - Liste todas as vulnerabilidades encontradas, classificadas por severidade (Crítica, Alta, Média, Baixa).\\n   - Para cada vulnerabilidade, inclua:\\n     - Tipo de vulnerabilidade\\n     - Severidade\\n     - Endpoints afetados\\n     - Descrição técnica\\n     - Evidências encontradas (ex: mensagens de erro específicas)\\n     - Impacto potencial\\n\\n# 3. **Análise de Tráfego**\\n   - Identifique endpoints sensíveis detectados (ex: /login, /admin, /api, /debug)\\n   - Destaque padrões de requisições que indicam possíveis falhas de segurança\\n   - Analise parâmetros que parecem vulneráveis e fluxos de autenticação\\n   - Correlacione requisições específicas com as vulnerabilidades identificadas\\n\\n# 4. **Tecnologias Detectadas**\\n   - Liste as tecnologias identificadas com suas versões e possíveis CVEs conhecidas\\n   - Avalie o risco associado a cada tecnologia baseado na versão instalada\\n\\n# 5. **Recomendações de Remediação**\\n   - Forneça recomendações técnicas específicas para cada vulnerabilidade identificada\\n   - Priorize as correções com base no risco\\n   - Inclua exemplos de código ou configurações seguras quando apropriado\\n\\n# 6. **Próximos Passos (Foco Pentester)**\\n   - Com base na análise, forneça uma lista de sugestões de testes manuais que um pentester deveria realizar\\n   - As sugestões devem ser práticas e focadas em explorar as fraquezas encontradas\\n   - Refira-se a IDs de requisições específicas para facilitar a reprodução\\n\\nFormato de exemplo para sugestões: \\\"Teste de manipulação de ID na requisição ID 45: O endpoint 'GET /api/users/{id}' não parece validar corretamente o parâmetro ID. Tente acessar IDs de outros usuários para verificar se há falha de controle de acesso.\\\"\\n\\nSeja claro, objetivo e foque em fornecer valor para profissionais de segurança.\\n\\n--- DADOS COLETADOS ---\\n{data}"
    }

def load_ai_config():
    """Carrega a configuração da IA do arquivo JSON."""
    if not os.path.exists(AI_CONFIG_FILE):
        return get_default_ai_config()
    try:
        with open(AI_CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = json.load(f)
            # Garante que todas as chaves padrão estão presentes
            default_config = get_default_ai_config()
            for key, value in default_config.items():
                if key not in config:
                    config[key] = value
            return config
    except (json.JSONDecodeError, IOError) as e:
        print(f"Erro ao carregar {AI_CONFIG_FILE}: {e}. Usando configuração padrão.")
        return get_default_ai_config()

def save_ai_config(config: dict):
    """Salva a configuração da IA no arquivo JSON."""
    try:
        os.makedirs(os.path.dirname(AI_CONFIG_FILE), exist_ok=True)
        with open(AI_CONFIG_FILE, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=4, ensure_ascii=False)
        return True
    except IOError as e:
        print(f"Erro ao salvar {AI_CONFIG_FILE}: {e}")
        return False

# --- Intercept Config ---
INTERCEPT_CONFIG_FILE = os.path.join("config", "intercept_config.json")

class InterceptConfig:
    """Gerencia a configuração do interceptador"""
    
    def __init__(self, config_file=None):
        if config_file is None:
            config_file = INTERCEPT_CONFIG_FILE
        self.config_file = config_file
        self.rules = []
        self.scope = []
        self.port = 9507  # Porta padrão
        self.paused = False
        self.intercept_enabled = False
        self.intercept_queue = queue.Queue()
        self.intercept_response_queue = queue.Queue()
        self.intercept_lock = threading.Lock()
        self.ui_queue = None  # Fila para notificar a UI
        
        # Configurações TOR
        self.tor_enabled = False
        self.tor_port = 9050
        self.tor_control_port = 9051
        self.tor_auto_start = False

        # Configurações OAST
        self.oast_api_url = "http://144.126.216.70/api.php"
        self.oast_api_key = "abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"
        self.oast_base_domain = "callback.localhost"

        # Modulos do scanner ativo
        self.active_scan_modules = self._get_default_active_scan_modules()
        
        self.load_config()

    @staticmethod
    def _get_default_active_scan_modules():
        return {
            'SqlInjectionModule': True,
            'RceOastModule': True,
            'SstiModule': True,
            'SsrfOastModule': True,
            'OpenRedirectModule': True,
            'HeaderInjectionModule': True,
            'LfiModule': True,
            'XssModule': True,
            'IdorModule': True,
        }

    def set_ui_queue(self, ui_queue: queue.Queue):
        """Define a fila para notificações da UI."""
        self.ui_queue = ui_queue

    def load_config(self):
        """Carrega configuração do arquivo"""
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.rules = data.get('rules', [])
                    self.scope = data.get('scope', [])
                    self.port = data.get('port', 9507)
                    
                    # Carrega configurações TOR
                    tor_config = data.get('tor', {})
                    self.tor_enabled = tor_config.get('enabled', False)
                    self.tor_port = tor_config.get('port', 9050)
                    self.tor_control_port = tor_config.get('control_port', 9051)
                    self.tor_auto_start = tor_config.get('auto_start', False)

                    # Carrega configurações OAST
                    oast_config = data.get('oast', {})
                    self.oast_api_url = oast_config.get('api_url', self.oast_api_url)
                    self.oast_api_key = oast_config.get('api_key', self.oast_api_key)
                    self.oast_base_domain = oast_config.get('base_domain', self.oast_base_domain)

                    # Carrega modulos do scanner ativo
                    modules_config = data.get('active_scan_modules')
                    default_modules = self._get_default_active_scan_modules()
                    if isinstance(modules_config, dict):
                        merged = dict(default_modules)
                        merged.update({k: bool(v) for k, v in modules_config.items()})
                        self.active_scan_modules = merged
                    elif isinstance(modules_config, list):
                        self.active_scan_modules = {name: (name in modules_config) for name in default_modules.keys()}
                    else:
                        self.active_scan_modules = dict(default_modules)
            except Exception as e:
                print(f"Erro ao carregar config: {e}")
                # Mantém os padrões em caso de erro
        else:
            # Se o arquivo não existe, os valores padrão definidos no __init__ serão usados.
            pass

    def save_config(self):
        """Salva configuração no arquivo"""
        try:
            config_data = {
                'rules': self.rules,
                'scope': self.scope,
                'port': self.port,
                'tor': {
                    'enabled': self.tor_enabled,
                    'port': self.tor_port,
                    'control_port': self.tor_control_port,
                    'auto_start': self.tor_auto_start
                },
                'oast': {
                    'api_url': self.oast_api_url,
                    'api_key': self.oast_api_key,
                    'base_domain': self.oast_base_domain
                },
                'active_scan_modules': self.active_scan_modules
            }
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Erro ao salvar config: {e}")
            return False

    def add_rule(self, host, path, param_name, param_value, rule_type='request'):
        """Adiciona uma regra de interceptação com validação."""
        # Validação
        if not all(str(val).strip() for val in [host, path, param_name, param_value]):
            return False, "Todos os campos devem ser preenchidos."

        rule = {
            'type': rule_type,
            'host': str(host).strip(),
            'path': str(path).strip(),
            'param_name': str(param_name).strip(),
            'param_value': str(param_value).strip(),
            'enabled': True
        }
        self.rules.append(rule)

        if self.save_config():
            return True, "Regra adicionada com sucesso!"
        else:
            # Em caso de falha ao salvar, remove a regra que foi adicionada
            self.rules.pop()
            return False, "Erro ao salvar a configuração."

    def remove_rule(self, index):
        """Remove uma regra de interceptação"""
        if 0 <= index < len(self.rules):
            self.rules.pop(index)
            return self.save_config()
        return False

    def get_rules(self):
        """Retorna todas as regras"""
        return self.rules

    def toggle_rule(self, index):
        """Ativa/desativa uma regra"""
        if 0 <= index < len(self.rules):
            self.rules[index]['enabled'] = not self.rules[index]['enabled']
            return self.save_config()
        return False

    def toggle_pause(self):
        """Alterna o estado de pausa do proxy."""
        self.paused = not self.paused
        return self.paused

    def is_paused(self):
        """Verifica se o proxy está pausado."""
        return self.paused

    def toggle_intercept(self):
        """Alterna o estado de interceptação manual."""
        self.intercept_enabled = not self.intercept_enabled
        return self.intercept_enabled

    def is_intercept_enabled(self):
        """Verifica se a interceptação manual está ativada."""
        return self.intercept_enabled

    def add_to_intercept_queue(self, flow_data):
        """Adiciona uma requisição à fila de interceptação e notifica a UI."""
        self.intercept_queue.put(flow_data)
        if self.ui_queue:
            # Envia uma cópia dos dados necessários para a UI, sem o objeto 'flow'
            ui_data = {k: v for k, v in flow_data.items() if k != 'flow'}
            self.ui_queue.put({"type": "intercepted_request", "data": ui_data})

    def get_from_intercept_queue(self, timeout=0.1):
        """Obtém uma requisição da fila de interceptação."""
        try:
            # Este método não precisa mais ser usado pela GUI
            return self.intercept_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def add_intercept_response(self, response_data):
        """Adiciona uma resposta à fila de respostas."""
        self.intercept_response_queue.put(response_data)

    def get_intercept_response(self, timeout=10):
        """Obtém uma resposta da fila de respostas."""
        try:
            return self.intercept_response_queue.get(timeout=timeout)
        except queue.Empty:
            return None

    def clear_intercept_queues(self):
        """Limpa todas as filas de interceptação."""
        while not self.intercept_queue.empty():
            try:
                self.intercept_queue.get_nowait()
            except queue.Empty:
                break
        while not self.intercept_response_queue.empty():
            try:
                self.intercept_response_queue.get_nowait()
            except queue.Empty:
                break

    def add_to_scope(self, host):
        """Adiciona um host ao escopo."""
        host = str(host).strip()
        if host and host not in self.scope:
            self.scope.append(host)
            return self.save_config()
        return False

    def remove_from_scope(self, host):
        """Remove um host do escopo."""
        host = str(host).strip()
        if host in self.scope:
            self.scope.remove(host)
            return self.save_config()
        return False

    def get_scope(self):
        """Retorna a lista de escopo."""
        return self.scope

    def is_in_scope(self, url):
        """Verifica se uma URL está no escopo."""
        if not self.scope:
            return True  # Se o escopo estiver vazio, tudo é permitido

        hostname = urlparse(url).hostname
        if not hostname:
            return False

        for pattern in self.scope:
            if fnmatch.fnmatch(hostname, pattern):
                return True
        return False

    def get_port(self):
        """Retorna a porta configurada."""
        return self.port

    def set_port(self, port):
        """Define a porta e salva a configuração."""
        if not isinstance(port, int):
            try:
                port = int(port)
            except (ValueError, TypeError):
                return False, "Porta deve ser um número inteiro."

        if port < 1 or port > 65535:
            return False, "Porta deve estar entre 1 e 65535."

        self.port = port
        if self.save_config():
            return True, f"Porta configurada para {port}"
        else:
            return False, "Erro ao salvar a configuração."

    # --- Métodos TOR ---
    def set_tor_enabled(self, enabled: bool):
        """Habilita/desabilita o uso do TOR."""
        self.tor_enabled = enabled
        return self.save_config()

    def get_tor_enabled(self):
        """Retorna se o TOR está habilitado."""
        return self.tor_enabled

    def set_tor_port(self, port: int):
        """Define a porta SOCKS5 do TOR."""
        if not isinstance(port, int) or port < 1 or port > 65535:
            return False, "Porta TOR deve ser um número entre 1 e 65535."
        self.tor_port = port
        return self.save_config()

    def get_tor_port(self):
        """Retorna a porta SOCKS5 do TOR."""
        return self.tor_port

    def set_tor_control_port(self, port: int):
        """Define a porta de controle do TOR."""
        if not isinstance(port, int) or port < 1 or port > 65535:
            return False, "Porta de controle TOR deve ser um número entre 1 e 65535."
        self.tor_control_port = port
        return self.save_config()

    def get_tor_control_port(self):
        """Retorna a porta de controle do TOR."""
        return self.tor_control_port

    def set_tor_auto_start(self, auto_start: bool):
        """Define se o TOR deve ser iniciado automaticamente."""
        self.tor_auto_start = auto_start
        return self.save_config()

    def get_tor_auto_start(self):
        """Retorna se o TOR deve ser iniciado automaticamente."""
        return self.tor_auto_start

    def get_tor_config(self):
        """Retorna todas as configurações do TOR."""
        return {
            'enabled': self.tor_enabled,
            'port': self.tor_port,
            'control_port': self.tor_control_port,
            'auto_start': self.tor_auto_start
        }

    def get_active_scan_modules(self):
        """Retorna configuracao de modulos do scanner ativo."""
        return dict(self.active_scan_modules)

    def set_active_scan_modules(self, modules: dict):
        """Define modulos habilitados do scanner ativo."""
        if not isinstance(modules, dict):
            return False, "Formato invalido para modulos do scanner ativo."
        self.active_scan_modules = modules
        if self.save_config():
            return True, "Configuracao de modulos atualizada."
        return False, "Erro ao salvar configuracao."
