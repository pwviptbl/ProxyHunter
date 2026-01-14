"""
Advanced Intruder/Sender module with support for:
- Multiple payload positions
- Attack types (Sniper, Battering Ram, Pitchfork, Cluster Bomb)
- Payload processing (encode, hash, prefix, suffix)
- Grep extraction from responses
"""
import concurrent.futures
import requests
import re
import hashlib
import base64
import urllib.parse
import html
import warnings
from typing import List, Dict, Tuple, Optional, Callable, Any
from .logger_config import log
from .tor_manager import TorManager

# Suppress urllib3 warnings for unverified HTTPS requests
requests.packages.urllib3.disable_warnings()


class PayloadProcessor:
    """Handles payload transformations (encoding, hashing, etc.)"""
    
    @staticmethod
    def url_encode(payload: str) -> str:
        """URL encode the payload"""
        return urllib.parse.quote(payload)
    
    @staticmethod
    def base64_encode(payload: str) -> str:
        """Base64 encode the payload"""
        return base64.b64encode(payload.encode('utf-8')).decode('utf-8')
    
    @staticmethod
    def html_encode(payload: str) -> str:
        """HTML encode the payload"""
        return html.escape(payload)
    
    @staticmethod
    def md5_hash(payload: str) -> str:
        """MD5 hash the payload"""
        return hashlib.md5(payload.encode('utf-8')).hexdigest()
    
    @staticmethod
    def sha1_hash(payload: str) -> str:
        """SHA1 hash the payload"""
        return hashlib.sha1(payload.encode('utf-8')).hexdigest()
    
    @staticmethod
    def sha256_hash(payload: str) -> str:
        """SHA256 hash the payload"""
        return hashlib.sha256(payload.encode('utf-8')).hexdigest()
    
    @staticmethod
    def add_prefix(payload: str, prefix: str) -> str:
        """Add prefix to payload"""
        return f"{prefix}{payload}"
    
    @staticmethod
    def add_suffix(payload: str, suffix: str) -> str:
        """Add suffix to payload"""
        return f"{payload}{suffix}"
    
    @staticmethod
    def hex_encode(payload: str) -> str:
        """Hex encode the payload"""
        return payload.encode('utf-8').hex()
    
    @staticmethod
    def apply_processors(payload: str, processors: List[Dict[str, Any]]) -> str:
        """
        Apply a chain of processors to a payload.
        
        Args:
            payload: The original payload
            processors: List of processor configurations
                       [{'type': 'url_encode'}, {'type': 'prefix', 'value': 'test_'}, ...]
        
        Returns:
            The transformed payload
        """
        result = payload
        processor_obj = PayloadProcessor()
        
        for proc in processors:
            proc_type = proc.get('type', '')
            
            if proc_type == 'url_encode':
                result = processor_obj.url_encode(result)
            elif proc_type == 'base64':
                result = processor_obj.base64_encode(result)
            elif proc_type == 'html_encode':
                result = processor_obj.html_encode(result)
            elif proc_type == 'md5':
                result = processor_obj.md5_hash(result)
            elif proc_type == 'sha1':
                result = processor_obj.sha1_hash(result)
            elif proc_type == 'sha256':
                result = processor_obj.sha256_hash(result)
            elif proc_type == 'hex':
                result = processor_obj.hex_encode(result)
            elif proc_type == 'prefix':
                result = processor_obj.add_prefix(result, proc.get('value', ''))
            elif proc_type == 'suffix':
                result = processor_obj.add_suffix(result, proc.get('value', ''))
        
        return result


class PayloadPositionParser:
    """Parses and manages payload positions in requests"""
    
    MARKER_PATTERN = r'§(.+?)§'
    
    @staticmethod
    def find_positions(raw_request: str) -> List[Tuple[int, int, str]]:
        """
        Find all payload position markers (§...§) in the request.
        
        Returns:
            List of tuples (start_pos, end_pos, original_value)
        """
        positions = []
        for match in re.finditer(PayloadPositionParser.MARKER_PATTERN, raw_request):
            positions.append((match.start(), match.end(), match.group(1)))
        return positions
    
    @staticmethod
    def replace_positions(raw_request: str, payloads: List[str]) -> str:
        """
        Replace all payload positions with actual payloads.
        
        Args:
            raw_request: Request with §markers§
            payloads: List of payload values (one per position)
        
        Returns:
            Request with markers replaced
        """
        result = raw_request
        positions = PayloadPositionParser.find_positions(raw_request)
        
        # Replace from end to start to maintain positions
        for i in range(len(positions) - 1, -1, -1):
            start, end, _ = positions[i]
            if i < len(payloads):
                result = result[:start] + payloads[i] + result[end:]
        
        return result
    
    @staticmethod
    def count_positions(raw_request: str) -> int:
        """Count the number of payload positions in the request"""
        return len(PayloadPositionParser.find_positions(raw_request))


class AttackTypeGenerator:
    """Generates payload combinations for different attack types"""
    
    @staticmethod
    def sniper(payload_sets: List[List[str]], num_positions: int) -> List[List[str]]:
        """
        Sniper: Uses one payload set, iterates through each position one at a time.
        Other positions use original values.
        
        Example with 2 positions and payloads [a, b]:
            - [a, original2]
            - [b, original2]
            - [original1, a]
            - [original1, b]
        """
        if not payload_sets or not payload_sets[0]:
            return []
        
        payloads = payload_sets[0]  # Use first set
        positions = PayloadPositionParser.find_positions
        combinations = []
        
        # For each position
        for pos_idx in range(num_positions):
            # For each payload
            for payload in payloads:
                combo = ['§ORIGINAL§'] * num_positions
                combo[pos_idx] = payload
                combinations.append(combo)
        
        return combinations
    
    @staticmethod
    def battering_ram(payload_sets: List[List[str]], num_positions: int) -> List[List[str]]:
        """
        Battering Ram: Uses same payload in all positions simultaneously.
        
        Example with 2 positions and payloads [a, b]:
            - [a, a]
            - [b, b]
        """
        if not payload_sets or not payload_sets[0]:
            return []
        
        payloads = payload_sets[0]
        combinations = []
        
        for payload in payloads:
            combo = [payload] * num_positions
            combinations.append(combo)
        
        return combinations
    
    @staticmethod
    def pitchfork(payload_sets: List[List[str]], num_positions: int) -> List[List[str]]:
        """
        Pitchfork: Uses multiple payload sets, iterates through them in parallel.
        Stops when shortest set is exhausted.
        
        Example with 2 positions, set1=[a,b,c], set2=[x,y]:
            - [a, x]
            - [b, y]
        """
        if not payload_sets:
            return []
        
        # Ensure we have enough sets
        while len(payload_sets) < num_positions:
            payload_sets.append(payload_sets[0] if payload_sets else [])
        
        combinations = []
        min_length = min(len(pset) for pset in payload_sets[:num_positions])
        
        for i in range(min_length):
            combo = [payload_sets[j][i] for j in range(num_positions)]
            combinations.append(combo)
        
        return combinations
    
    @staticmethod
    def cluster_bomb(payload_sets: List[List[str]], num_positions: int) -> List[List[str]]:
        """
        Cluster Bomb: Uses multiple payload sets, tries all combinations.
        
        Example with 2 positions, set1=[a,b], set2=[x,y]:
            - [a, x]
            - [a, y]
            - [b, x]
            - [b, y]
        """
        if not payload_sets:
            return []
        
        # Ensure we have enough sets
        while len(payload_sets) < num_positions:
            payload_sets.append(payload_sets[0] if payload_sets else [])
        
        # Generate all combinations recursively
        def generate_combinations(sets: List[List[str]], current: List[str] = []) -> List[List[str]]:
            if not sets:
                return [current]
            
            results = []
            for payload in sets[0]:
                results.extend(generate_combinations(sets[1:], current + [payload]))
            return results
        
        return generate_combinations(payload_sets[:num_positions])


class GrepExtractor:
    """Extracts data from responses using regex patterns"""
    
    def __init__(self, patterns: List[str]):
        """
        Args:
            patterns: List of regex patterns to match in responses
        """
        self.patterns = [re.compile(p) for p in patterns]
    
    def extract(self, response_text: str) -> List[str]:
        """
        Extract matches from response text.
        
        Returns:
            List of all matches found
        """
        matches = []
        for pattern in self.patterns:
            found = pattern.findall(response_text)
            matches.extend(found)
        return matches


class AdvancedSender:
    """Advanced sender with intruder capabilities"""
    
    def __init__(self, 
                 raw_request: str,
                 attack_type: str = 'sniper',
                 payload_sets: List[List[str]] = None,
                 processors: List[List[Dict[str, Any]]] = None,
                 grep_patterns: List[str] = None,
                 num_threads: int = 10,
                 proxy_port: int = 9507,
                 use_tor: bool = False,
                 tor_port: int = 9050):
        """
        Args:
            raw_request: Base request with §markers§ for payload positions
            attack_type: 'sniper', 'battering_ram', 'pitchfork', or 'cluster_bomb'
            payload_sets: List of payload lists (one per position for some attacks)
            processors: List of processor chains (one per payload set)
            grep_patterns: Regex patterns to extract from responses
            num_threads: Number of concurrent threads
            proxy_port: Port for the proxy server
            use_tor: Whether to route requests through TOR
            tor_port: TOR SOCKS5 port
        """
        self.raw_request = raw_request
        self.attack_type = attack_type
        self.payload_sets = payload_sets or [[]]
        self.processors = processors or [[]]
        self.grep_extractor = GrepExtractor(grep_patterns or [])
        self.num_threads = num_threads
        self.proxy_port = proxy_port
        self.use_tor = use_tor
        self.tor_port = tor_port
        self.num_positions = PayloadPositionParser.count_positions(raw_request)
        
        # Store original values for Sniper attack
        self.original_values = [val for _, _, val in PayloadPositionParser.find_positions(raw_request)]
    
    def generate_requests(self) -> List[Tuple[str, List[str]]]:
        """
        Generate all requests based on attack type.
        
        Returns:
            List of (request_string, payloads_used) tuples
        """
        # Apply processors to payloads
        processed_sets = []
        for i, pset in enumerate(self.payload_sets):
            proc_chain = self.processors[i] if i < len(self.processors) else []
            processed = [PayloadProcessor.apply_processors(p, proc_chain) for p in pset]
            processed_sets.append(processed)
        
        # Generate payload combinations based on attack type
        if self.attack_type == 'sniper':
            combinations = AttackTypeGenerator.sniper(processed_sets, self.num_positions)
        elif self.attack_type == 'battering_ram':
            combinations = AttackTypeGenerator.battering_ram(processed_sets, self.num_positions)
        elif self.attack_type == 'pitchfork':
            combinations = AttackTypeGenerator.pitchfork(processed_sets, self.num_positions)
        elif self.attack_type == 'cluster_bomb':
            combinations = AttackTypeGenerator.cluster_bomb(processed_sets, self.num_positions)
        else:
            log.error(f"Unknown attack type: {self.attack_type}")
            return []
        
        # Replace §ORIGINAL§ markers with actual original values for Sniper
        if self.attack_type == 'sniper':
            for combo in combinations:
                for i in range(len(combo)):
                    if combo[i] == '§ORIGINAL§' and i < len(self.original_values):
                        combo[i] = self.original_values[i]
        
        # Generate requests
        requests = []
        for combo in combinations:
            request = PayloadPositionParser.replace_positions(self.raw_request, combo)
            requests.append((request, combo))
        
        return requests
    
    def send_request(self, raw_request: str) -> Optional[requests.Response]:
        """
        Send a single HTTP request.
        
        Args:
            raw_request: Raw HTTP request string
            
        Returns:
            Response object or None on error
        """
        tor_manager = None
        try:
            # Parse request (simplified version from sender.py)
            head, body = raw_request.strip().split('\n\n', 1) if '\n\n' in raw_request else (raw_request.strip(), "")
            request_lines = head.split('\n')
            
            method, path, _ = request_lines[0].split(' ')
            
            headers = {}
            for line in request_lines[1:]:
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip()] = value.strip()
            
            host = headers.get("Host")
            if not host:
                raise ValueError("Header 'Host' not found")
            
            # Use HTTP for local hosts, HTTPS for others
            if host.startswith(('127.0.0.1', 'localhost', '192.168.', '10.', '172.')):
                scheme = "http"
            else:
                scheme = "https"
            full_url = f"{scheme}://{host}{path}"
            
            headers_to_send = {k: v for k, v in headers.items() if k.lower() not in ['host', 'content-length']}
            
            # Configure proxies based on TOR setting
            if self.use_tor:
                tor_manager = TorManager(tor_port=self.tor_port)
                # Use context manager para TOR temporário
                with tor_manager.tor_context():
                    log.info(f"Sending request via TOR: {method} {full_url}")
                    response = requests.request(
                        method=method,
                        url=full_url,
                        headers=headers_to_send,
                        data=body.encode('utf-8') if body else None,
                        proxies=None,  # TOR handles routing via context
                        verify=False,
                        timeout=30
                    )
            else:
                proxies = {"http": f"http://127.0.0.1:{self.proxy_port}", "https": f"http://127.0.0.1:{self.proxy_port}"}
                log.info(f"Sending request: {method} {full_url}")
                response = requests.request(
                    method=method,
                    url=full_url,
                    headers=headers_to_send,
                    data=body.encode('utf-8') if body else None,
                    proxies=proxies,
                    verify=False,
                    timeout=30
                )
            
            return response
            
        except Exception as e:
            log.error(f"Error sending request: {e}")
            return None
        finally:
            # Always disconnect TOR after request
            if tor_manager:
                tor_manager.disconnect()
    
    def run_attack(self, queue=None):
        """
        Execute the attack and send all generated requests.
        
        Args:
            queue: Optional queue for progress updates and results
        """
        requests_to_send = self.generate_requests()
        total_requests = len(requests_to_send)
        
        log.info(f"Advanced Sender: Starting {self.attack_type} attack with {total_requests} requests")
        
        if queue:
            queue.put({'type': 'progress_start', 'total': total_requests})
        
        completed_requests = 0
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.num_threads) as executor:
            future_to_payloads = {
                executor.submit(self.send_request, req): payloads 
                for req, payloads in requests_to_send
            }
            
            for future in concurrent.futures.as_completed(future_to_payloads):
                response = future.result()
                payloads_used = future_to_payloads[future]
                completed_requests += 1
                
                if queue:
                    progress = (completed_requests / total_requests) * 100
                    queue.put({'type': 'progress_update', 'value': progress})
                    
                    if response:
                        # Extract grep matches
                        extracted = self.grep_extractor.extract(response.text)
                        
                        success = 200 <= response.status_code < 300
                        result_data = {
                            'url': response.request.url,
                            'status': response.status_code,
                            'success': success,
                            'response': response,
                            'payloads': payloads_used,
                            'extracted': extracted,
                            'length': len(response.content)
                        }
                    else:
                        result_data = {
                            'url': 'N/A',
                            'status': 'Error',
                            'success': False,
                            'response': None,
                            'payloads': payloads_used,
                            'extracted': [],
                            'length': 0
                        }
                    
                    queue.put({'type': 'result', 'data': result_data})
        
        log.info("Advanced Sender: Attack completed")
        if queue:
            queue.put({'type': 'progress_done'})
    
def _substitute_value(source: str, param_name: str, new_value: str) -> str:
    """Helper to substitute a value in a query string or form-urlencoded body."""
    # Pattern to find the parameter and its value
    pattern = re.compile(f"([?&]|^)({re.escape(param_name)}=)([^&]*)")

    if pattern.search(source):
        # Substitute the value if the parameter is found
        return pattern.sub(f"\\1\\2{new_value}", source)
    else:
        # Append the parameter if it's not found
        if '?' not in source:
            return f"{source}?{param_name}={new_value}"
        else:
            return f"{source}&{param_name}={new_value}"

def _substitute_placeholder(source: str, placeholder: str, new_value: str) -> str:
    """Helper to substitute a placeholder in the request body."""
    return source.replace(placeholder, str(new_value))

def send_from_raw(raw_request: str, param_name: str = None, new_value: str = None, proxy_port: int = 9507, use_tor: bool = False, tor_port: int = 9050):
    """
    Parses a raw HTTP request, optionally substitutes a parameter,
    and resends it, returning the response object.
    """
    full_url = ""
    tor_manager = None
    try:
        # Separate the request into head and body
        parts = raw_request.strip().split('\n\n', 1)
        if len(parts) == 2:
            head, body = parts
        else:
            head = parts[0]
            body = ""
        request_lines = head.split('\n')

        # 1. Parse the first line
        method, path, _ = request_lines[0].split(' ')

        # 2. Parse Headers
        headers = {}
        for line in request_lines[1:]:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()

        # 3. Build URL
        host = headers.get("Host")
        if not host:
            raise ValueError("Header 'Host' não encontrado.")
        # Use HTTP for local hosts, HTTPS for others
        if host.startswith(('127.0.0.1', 'localhost', '192.168.', '10.', '172.')):
            scheme = "http"
        else:
            scheme = "https"
        base_url = f"{scheme}://{host}"

        # 4. Substitute parameter
        if param_name and new_value is not None:
            new_value = str(new_value).strip()
            placeholder = f"${param_name}"
            # Try to substitute placeholder in body first
            if body and placeholder in body:
                body = _substitute_placeholder(body, placeholder, new_value)
            else:
                # Fallback to original logic
                # Try in URL path/query
                if param_name in path:
                    path = _substitute_value(path, param_name, new_value)
                # Try in urlencoded body
                elif body and "application/x-www-form-urlencoded" in headers.get("Content-Type", ""):
                     body = _substitute_value(body, param_name, new_value)
                # Otherwise, add to URL
                else:
                    path = _substitute_value(path, param_name, new_value)

        full_url = f"{base_url}{path}"

        # 5. Prepare for resending
        headers_to_send = {k: v for k, v in headers.items() if k.lower() not in ['host', 'content-length']}

        # Configure proxies based on TOR setting
        if use_tor:
            tor_manager = TorManager(tor_port=tor_port)
            # Use context manager para TOR temporário
            with tor_manager.tor_context():
                log.info(f"Resending request via TOR: {method} {full_url}")
                response = requests.request(
                    method=method,
                    url=full_url,
                    headers=headers_to_send,
                    data=body.encode('utf-8') if body else None,
                    proxies=None,  # TOR handles routing via context
                    verify=False
                )
        else:
            proxies = {"http": f"http://127.0.0.1:{proxy_port}", "https": f"http://127.0.0.1:{proxy_port}"}
            log.info(f"Resending request: {method} {full_url}")
            response = requests.request(
                method=method,
                url=full_url,
                headers=headers_to_send,
                data=body.encode('utf-8') if body else None,
                proxies=proxies,
                verify=False
            )

        log.info(f"Response received: {response.status_code}")
        return response

    except Exception as e:
        log.error(f"Error resending request: {e}", exc_info=True)
        return None


def load_payloads_from_file(file_path: str) -> List[str]:
    """Load payloads from a text file (one per line)"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return [line.strip() for line in f if line.strip()]
    except Exception as e:
        log.error(f"Error loading payloads from {file_path}: {e}")
        return []
