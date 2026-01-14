from abc import ABC, abstractmethod
from typing import List, Any, Dict

from src.core.vulnerability import Vulnerability

# Type hints for data structures that will be more formally defined later.
# For now, we assume they are dict-like objects representing database records.
RequestNode = Dict[str, Any]
InjectionPoint = Dict[str, Any]


class IScanModule(ABC):
    """
    Abstract base class for a scan module.

    This class defines the "contract" that all future scan modules
    (e.g., SQLi, SSTI, XSS) must implement.
    """

    @abstractmethod
    def run_test(
        self,
        request_node: RequestNode,
        injection_point: InjectionPoint,
        oast_client: Any
    ) -> List[Vulnerability]:
        """
        Executes a scan test against a specific injection point.

        Args:
            request_node: The request "template" data.
            injection_point: The specific injection point to be tested.
            oast_client: An instance of the OAST client for out-of-band checks.

        Returns:
            A list of Vulnerability objects found during the test.
            Returns an empty list if no vulnerabilities are found.
        """
        pass
