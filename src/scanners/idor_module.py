from typing import List, Any

import requests

from src.core.request_rebuilder import rebuild_attack_request
from src.core.vulnerability import Vulnerability
from src.scanners.IScanModule import IScanModule, RequestNode, InjectionPoint

OASTClient = Any


class IdorModule(IScanModule):
    """Detecta possivel IDOR por variacao de IDs numericos."""

    def run_test(
        self,
        request_node: RequestNode,
        injection_point: InjectionPoint,
        oast_client: OASTClient
    ) -> List[Vulnerability]:
        if injection_point['location'] not in {'QUERY', 'BODY_FORM', 'BODY_JSON'}:
            return []

        original_value = injection_point.get('original_value')
        if not isinstance(original_value, str) or not original_value.isdigit():
            return []

        base_id = int(original_value)
        test_values = [str(base_id + 1)]
        if base_id > 0:
            test_values.append(str(base_id - 1))

        session = requests.Session()
        session.verify = False
        session.timeout = 5

        try:
            baseline_req = rebuild_attack_request(request_node, injection_point, original_value)
            baseline_resp = session.send(baseline_req, timeout=session.timeout)
        except requests.exceptions.RequestException:
            return []
        except Exception:
            return []

        base_len = len(baseline_resp.text or "")
        base_status = baseline_resp.status_code

        for value in test_values:
            try:
                test_req = rebuild_attack_request(request_node, injection_point, value)
                test_resp = session.send(test_req, timeout=session.timeout)
                test_len = len(test_resp.text or "")

                if test_resp.status_code == 200 and base_status == 200:
                    if base_len > 0:
                        diff_ratio = abs(base_len - test_len) / float(base_len)
                    else:
                        diff_ratio = 0.0

                    if diff_ratio >= 0.3:
                        return [
                            Vulnerability(
                                name="Insecure Direct Object Reference (IDOR)",
                                severity="High",
                                description=(
                                    "Possivel IDOR detectada por diferenca significativa na resposta ao alterar o ID. "
                                    f"Parametro '{injection_point['parameter_name']}' foi alterado de {original_value} para {value}."
                                ),
                                evidence={
                                    "payload": value,
                                    "baseline_status": base_status,
                                    "test_status": test_resp.status_code,
                                    "baseline_length": base_len,
                                    "test_length": test_len,
                                    "tested_value": value,
                                },
                                request_node_id=request_node['id'],
                                injection_point_id=injection_point['id']
                            )
                        ]
            except requests.exceptions.RequestException:
                continue
            except Exception:
                return []

        return []
