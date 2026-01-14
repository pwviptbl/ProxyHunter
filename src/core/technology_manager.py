import threading
from collections import defaultdict

class TechnologyManager:
    """
    Manages the storage of technologies discovered for each host.
    This class is thread-safe.
    """
    def __init__(self):
        self.technologies = defaultdict(set)
        self._lock = threading.Lock()

    def add_technology(self, hostname: str, technology: str):
        """
        Adds a detected technology for a given hostname.

        Args:
            hostname: The hostname of the target.
            technology: The name of the detected technology (e.g., 'jQuery 3.5.1').
        """
        with self._lock:
            if technology not in self.technologies[hostname]:
                self.technologies[hostname].add(technology)

    def get_technologies_for_host(self, hostname: str) -> set:
        """
        Retrieves all detected technologies for a specific hostname.

        Args:
            hostname: The hostname to retrieve technologies for.

        Returns:
            A set of technology strings.
        """
        with self._lock:
            return self.technologies.get(hostname, set()).copy()

    def get_all_hosts(self) -> list:
        """
        Retrieves a list of all hostnames for which technologies have been detected.

        Returns:
            A sorted list of hostnames.
        """
        with self._lock:
            return sorted(list(self.technologies.keys()))

    def get_all_data(self) -> dict:
        """
        Retrieves a copy of the entire technology database.

        Returns:
            A dictionary where keys are hostnames and values are sets of technologies.
        """
        with self._lock:
            return {host: techs.copy() for host, techs in self.technologies.items()}
