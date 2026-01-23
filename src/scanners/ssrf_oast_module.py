import time
from typing import List, Any

import requests

from src.core.request_rebuilder import rebuild_attack_request
from src.core.vulnerability import Vulnerability
from src.scanners.IScanModule import IScanModule, RequestNode, InjectionPoint

OASTClient = Any


class SsrfOastModule(IScanModule):
    """Detecta SSRF usando callbacks OAST."""

    def run_test(
        self,
        request_node: RequestNode,
        injection_point: InjectionPoint,
        oast_client: OASTClient
    ) -> List[Vulnerability]:
        if oast_client is None:
            return []

        relevant_locations = {'QUERY', 'BODY_FORM', 'BODY_JSON', 'HEADER'}
        if injection_point['location'] not in relevant_locations:
            return []

        session = requests.Session()
        session.verify = False
        session.timeout = 5

        try:
            interaction_id, domain = oast_client.generate_interaction_id(type_prefix="ssrf")
        except Exception:
            return []

        payloads = [
            f"http://{domain}/pxh",
            f"https://{domain}/pxh",
            f"//{domain}/pxh",
        ]
        last_payload = None

        for payload in payloads:
            try:
                last_payload = payload
                request_to_send = rebuild_attack_request(request_node, injection_point, payload)
                session.send(request_to_send, timeout=session.timeout)
            except requests.exceptions.RequestException:
                continue
            except Exception:
                return []

        time.sleep(2)

        try:
            result = oast_client.check_hit(interaction_id)
        except Exception:
            return []

        if result and result.get('hit'):
            return [
                Vulnerability(
                    name="SSRF (OAST)",
                    severity="High",
                    description=(
                        "Possivel SSRF detectada via callback OAST. "
                        f"Parametro '{injection_point['parameter_name']}' causou interacao externa."
                    ),
                    evidence=f"Payload: {last_payload} | Hit: {result.get('data', {})}",
                    request_node_id=request_node['id'],
                    injection_point_id=injection_point['id']
                )
            ]

        return []
