from typing import List, Any

import requests

from src.core.request_rebuilder import rebuild_attack_request
from src.core.vulnerability import Vulnerability
from src.scanners.IScanModule import IScanModule, RequestNode, InjectionPoint

OASTClient = Any


class HeaderInjectionModule(IScanModule):
    """Detecta CRLF/Header Injection refletida em response headers."""

    def run_test(
        self,
        request_node: RequestNode,
        injection_point: InjectionPoint,
        oast_client: OASTClient
    ) -> List[Vulnerability]:
        if injection_point['location'] not in {'QUERY', 'BODY_FORM', 'BODY_JSON', 'HEADER'}:
            return []

        session = requests.Session()
        session.verify = False
        session.timeout = 5

        payload = "pxh%0d%0aX-Injected-Header: pxh"

        try:
            request_to_send = rebuild_attack_request(request_node, injection_point, payload)
            response = session.send(request_to_send, timeout=session.timeout)
            injected = response.headers.get('X-Injected-Header')
            if injected and 'pxh' in injected.lower():
                return [
                    Vulnerability(
                        name="Header Injection (CRLF)",
                        severity="Medium",
                        description=(
                            "Possivel CRLF/Header Injection detectada pela presenca de header injetado. "
                            f"Parametro '{injection_point['parameter_name']}'."
                        ),
                        evidence=f"Payload: {payload} | X-Injected-Header: {injected}",
                        request_node_id=request_node['id'],
                        injection_point_id=injection_point['id']
                    )
                ]
        except requests.exceptions.RequestException:
            return []
        except Exception:
            return []

        return []
