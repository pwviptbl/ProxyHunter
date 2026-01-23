import re
from typing import List, Any

import requests

from src.core.request_rebuilder import rebuild_attack_request
from src.core.vulnerability import Vulnerability
from src.scanners.IScanModule import IScanModule, RequestNode, InjectionPoint

OASTClient = Any


class SstiModule(IScanModule):
    """Detecta SSTI por avaliacao de expressoes em templates."""

    PAYLOADS = [
        ("{{1337*1337}}", "1787569"),
        ("${1337*1337}", "1787569"),
        ("<%= 1337*1337 %>", "1787569"),
        ("${{1337*1337}}", "1787569"),
    ]

    def run_test(
        self,
        request_node: RequestNode,
        injection_point: InjectionPoint,
        oast_client: OASTClient
    ) -> List[Vulnerability]:
        relevant_locations = {'QUERY', 'BODY_FORM', 'BODY_JSON'}
        if injection_point['location'] not in relevant_locations:
            return []

        session = requests.Session()
        session.verify = False
        session.timeout = 5

        for payload, expected in self.PAYLOADS:
            try:
                request_to_send = rebuild_attack_request(request_node, injection_point, payload)
                response = session.send(request_to_send, timeout=session.timeout)
                if expected in (response.text or ""):
                    return [
                        Vulnerability(
                            name="SSTI (Template Injection)",
                            severity="High",
                            description=(
                                "Possivel SSTI detectada pela avaliacao de expressao no template. "
                                f"Payload '{payload}' em '{injection_point['parameter_name']}'."
                            ),
                            evidence=f"Payload: {payload} | Match: {expected}",
                            request_node_id=request_node['id'],
                            injection_point_id=injection_point['id']
                        )
                    ]
            except requests.exceptions.RequestException:
                continue
            except Exception:
                return []

        return []
