import time
from typing import List, Any, Dict

import requests

from src.core.request_rebuilder import rebuild_attack_request
from src.core.vulnerability import Vulnerability
from src.scanners.IScanModule import IScanModule, RequestNode, InjectionPoint

# A placeholder for a real OAST client, to allow type hinting.
# In a real scenario, this would be `from src.core.oast_client import OASTClient`
OASTClient = Any


class RceOastModule(IScanModule):
    """
    A scan module for detecting Remote Code Execution (RCE) vulnerabilities
    using Out-of-Band Application Security Testing (OAST).
    """

    def run_test(
        self,
        request_node: RequestNode,
        injection_point: InjectionPoint,
        oast_client: OASTClient
    ) -> List[Vulnerability]:
        """
        Executes the RCE OAST scan logic.
        """
        # This module is relevant for locations where command injection is likely.
        relevant_locations = {'QUERY', 'BODY_FORM', 'BODY_JSON', 'HEADER', 'COOKIE'}
        if injection_point['location'] not in relevant_locations:
            return []

        session = requests.Session()
        session.verify = False  # Disable SSL verification for internal/test targets
        session.timeout = 3     # Set a timeout for requests

        # Store payloads with their unique interaction IDs
        payload_interactions = []

        # Generate payloads and send requests
        for payload_template in [
            "| nslookup {domain}",
            "$(nslookup {domain})",
            "& nslookup {domain}",
            "`nslookup {domain}`",
            "; nslookup {domain}",
        ]:
            try:
                interaction_id, domain = oast_client.generate_interaction_id(type_prefix="rce")
                payload = payload_template.format(domain=domain)
                payload_interactions.append({'payload': payload, 'id': interaction_id})

                request_to_send = rebuild_attack_request(request_node, injection_point, payload)
                session.send(request_to_send, timeout=session.timeout)
            except requests.exceptions.RequestException:
                continue
            except Exception:
                # If OAST client fails mid-run, stop.
                return []

        # Wait a moment for OAST callbacks to arrive
        time.sleep(2)

        # Check for hits for each interaction
        for interaction in payload_interactions:
            result = oast_client.check_hit(interaction['id'])
            if result and result.get('hit'):
                vulnerability = Vulnerability(
                    name="Remote Code Execution (OAST)",
                    severity="Critical",
                    description=(
                        f"An RCE vulnerability was detected using an out-of-band callback. "
                        f"The payload '{interaction['payload']}' was injected into the "
                        f"'{injection_point['parameter_name']}' parameter in '{injection_point['location']}' "
                        f"and triggered a DNS lookup to the OAST server."
                    ),
                    evidence=result.get('data', {}),
                    request_node_id=request_node['id'],
                    injection_point_id=injection_point['id']
                )
                return [vulnerability]  # Return on the first confirmed hit

        return []
