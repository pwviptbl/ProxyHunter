from PySide6.QtWidgets import (
    QWidget,
    QVBoxLayout,
    QSplitter,
    QGroupBox,
    QListWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QListWidgetItem
)
from PySide6.QtCore import Qt

class TechnologiesTab(QWidget):
    """
    UI tab to display detected technologies for each host.
    """
    def __init__(self):
        super().__init__()
        self.setLayout(QVBoxLayout(self))

        # Main splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.layout().addWidget(splitter)

        # Left side: List of hosts
        hosts_group = QGroupBox("Hosts")
        hosts_layout = QVBoxLayout()
        self.hosts_list = QListWidget()
        self.hosts_list.currentItemChanged.connect(self._on_host_selected)
        hosts_layout.addWidget(self.hosts_list)
        hosts_group.setLayout(hosts_layout)
        splitter.addWidget(hosts_group)

        # Right side: Detected technologies
        tech_group = QGroupBox("Detected Technologies")
        tech_layout = QVBoxLayout()
        self.tech_tree = QTreeWidget()
        self.tech_tree.setHeaderLabels(["Technology", "Category"])
        self.tech_tree.header().setStretchLastSection(False)
        self.tech_tree.header().setSectionResizeMode(0, self.tech_tree.header().ResizeMode.Stretch)
        self.tech_tree.header().setSectionResizeMode(1, self.tech_tree.header().ResizeMode.ResizeToContents)

        tech_layout.addWidget(self.tech_tree)
        tech_group.setLayout(tech_layout)
        splitter.addWidget(tech_group)

        splitter.setSizes([200, 400])

        self._all_technologies = {} # To store data from backend {hostname: {tech1, tech2}}

    def _on_host_selected(self, current_item: QListWidgetItem, previous_item: QListWidgetItem):
        """
        Updates the technology tree when a host is selected.
        """
        self.tech_tree.clear()
        if not current_item:
            return

        hostname = current_item.text()
        technologies = sorted(list(self._all_technologies.get(hostname, set())))

        # This is a placeholder for a more sophisticated categorization logic
        # For now, we'll just list them.
        for tech in technologies:
            item = QTreeWidgetItem(self.tech_tree, [tech, "Unknown"])
            self.tech_tree.addTopLevelItem(item)

    def update_technologies(self, all_tech_data: dict):
        """
        Receives all technology data from the backend and updates the UI.

        Args:
            all_tech_data: A dictionary like {hostname: {tech1, tech2}}.
        """
        self._all_technologies = all_tech_data

        current_host = self.hosts_list.currentItem().text() if self.hosts_list.currentItem() else None

        self.hosts_list.clear()

        sorted_hosts = sorted(all_tech_data.keys())

        for hostname in sorted_hosts:
            item = QListWidgetItem(hostname)
            self.hosts_list.addItem(item)
            if hostname == current_host:
                self.hosts_list.setCurrentItem(item)

        # If no host is selected, select the first one if available
        if not self.hosts_list.currentItem() and self.hosts_list.count() > 0:
            self.hosts_list.setCurrentRow(0)
