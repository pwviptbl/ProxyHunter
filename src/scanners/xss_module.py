from typing import List, Any

import requests

from src.core.request_rebuilder import rebuild_attack_request
from src.core.vulnerability import Vulnerability
from src.scanners.IScanModule import IScanModule, RequestNode, InjectionPoint

OASTClient = Any


class XssModule(IScanModule):
    """Detecta XSS refletido por marcador simples."""

    MARKER = "PXH_XSS_TEST"

    def run_test(
        self,
        request_node: RequestNode,
        injection_point: InjectionPoint,
        oast_client: OASTClient
    ) -> List[Vulnerability]:
        if injection_point['location'] not in {'QUERY', 'BODY_FORM', 'BODY_JSON'}:
            return []

        session = requests.Session()
        session.verify = False
        session.timeout = 5

        payload = f"<svg/onload=alert(1)>{self.MARKER}"

        try:
            request_to_send = rebuild_attack_request(request_node, injection_point, payload)
            response = session.send(request_to_send, timeout=session.timeout)
            if self.MARKER in (response.text or ""):
                return [
                    Vulnerability(
                        name="Cross-Site Scripting (Reflected)",
                        severity="Medium",
                        description=(
                            "XSS refletido detectado por marcador no response. "
                            f"Parametro '{injection_point['parameter_name']}'."
                        ),
                        evidence=f"Payload: {payload} | Marker: {self.MARKER}",
                        request_node_id=request_node['id'],
                        injection_point_id=injection_point['id']
                    )
                ]
        except requests.exceptions.RequestException:
            return []
        except Exception:
            return []

        return []
