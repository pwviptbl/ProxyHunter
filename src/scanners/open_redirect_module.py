from typing import List, Any

import requests

from src.core.request_rebuilder import rebuild_attack_request
from src.core.vulnerability import Vulnerability
from src.scanners.IScanModule import IScanModule, RequestNode, InjectionPoint

OASTClient = Any


class OpenRedirectModule(IScanModule):
    """Detecta redirecionamento aberto via Location/3xx."""

    REDIRECT_PARAM_HINTS = {
        'next', 'url', 'redirect', 'return', 'continue', 'dest', 'destination',
        'redir', 'redirect_uri', 'callback', 'goto'
    }

    def run_test(
        self,
        request_node: RequestNode,
        injection_point: InjectionPoint,
        oast_client: OASTClient
    ) -> List[Vulnerability]:
        location = injection_point['location']
        if location not in {'QUERY', 'BODY_FORM', 'BODY_JSON'}:
            return []

        name = (injection_point.get('parameter_name') or '').lower()
        if name and name not in self.REDIRECT_PARAM_HINTS:
            return []

        session = requests.Session()
        session.verify = False
        session.timeout = 5

        payloads = [
            "https://example.com/pxh-redirect",
            "//example.com/pxh-redirect",
        ]

        for payload in payloads:
            try:
                request_to_send = rebuild_attack_request(request_node, injection_point, payload)
                response = session.send(request_to_send, allow_redirects=False, timeout=session.timeout)
                location_header = response.headers.get('Location', '')
                if response.status_code in (301, 302, 303, 307, 308) and "example.com/pxh-redirect" in location_header:
                    return [
                        Vulnerability(
                            name="Open Redirect",
                            severity="Medium",
                            description=(
                                "Redirecionamento aberto detectado via cabecalho Location. "
                                f"Parametro '{injection_point['parameter_name']}' aceitou destino externo."
                            ),
                            evidence=f"Payload: {payload} | Location: {location_header}",
                            request_node_id=request_node['id'],
                            injection_point_id=injection_point['id']
                        )
                    ]
            except requests.exceptions.RequestException:
                continue
            except Exception:
                return []

        return []
