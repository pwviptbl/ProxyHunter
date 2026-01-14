from PySide6.QtCore import Qt, Signal, QAbstractTableModel, QModelIndex, QSortFilterProxyModel, QThread
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QPushButton, QLabel, QComboBox,
                               QGroupBox, QHBoxLayout, QTableView, QAbstractItemView,
                               QTextEdit, QSplitter, QHeaderView, QMessageBox, QLineEdit)
from PySide6.QtGui import QBrush, QColor

from src.core.history import RequestHistory
from src.core.active_scanner import ActiveScanner
from src.core.logger_config import log


class ScanWorker(QThread):
    """Worker thread to run the active scan without freezing the UI."""
    scan_complete = Signal(dict, list)

    def __init__(self, scanner: ActiveScanner, request_data: dict):
        super().__init__()
        self.scanner = scanner
        self.request_data = request_data

    def run(self):
        """Executa o scan ativo e emite o resultado."""
        try:
            results = self.scanner.scan_request(self.request_data)
            self.scan_complete.emit(self.request_data, results)
        except Exception as e:
            log.error(f"Erro durante a execução do ScanWorker: {e}")
            # Cria uma vulnerabilidade para reportar o erro na UI
            error_vuln = {
                'type': 'Scanner Crash',
                'severity': 'High',
                'source': 'Active',
                'url': self.request_data.get('url', 'N/A'),
                'method': self.request_data.get('method', 'N/A'),
                'description': 'Ocorreu um erro crítico que impediu a execução do scan ativo.',
                'evidence': str(e)
            }
            self.scan_complete.emit(self.request_data, [error_vuln])

class ScannerTab(QWidget):
    """Aba de UI para o Scanner de Vulnerabilidades."""

    def __init__(self, history: RequestHistory, active_scanner: ActiveScanner):
        super().__init__()
        self.history_manager = history
        self.active_scanner = active_scanner
        self.scan_worker = None

        layout = QVBoxLayout(self)

        self._setup_info_section(layout)
        self._setup_active_scanner_section(layout)
        self._setup_filters(layout)

        splitter = QSplitter(Qt.Orientation.Vertical)
        layout.addWidget(splitter)

        self._setup_vulnerability_table(splitter)
        self._setup_details_panel(splitter)

        splitter.setSizes([400, 200])

        self.count_label = QLabel("Total: 0 vulnerabilidade(s)")
        layout.addWidget(self.count_label)

    def _setup_info_section(self, layout):
        info_group = QGroupBox("Scanner de Vulnerabilidades")
        info_layout = QVBoxLayout()
        info_text = (
            "O scanner detecta automaticamente vulnerabilidades em requisições/respostas (Passivo) "
            "e permite testes ativos em requisições específicas (Ativo)."
        )
        info_label = QLabel(info_text)
        info_label.setWordWrap(True)
        info_layout.addWidget(info_label)
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)

    def _setup_active_scanner_section(self, layout):
        active_group = QGroupBox("Scanner Ativo")
        active_layout = QHBoxLayout()
        info_label = QLabel("Selecione uma requisição no Histórico e clique em 'Escanear Ativamente' para testar.")
        info_label.setStyleSheet("color: blue;")
        active_layout.addWidget(info_label)
        self.active_scan_status = QLabel("")
        self.active_scan_status.setStyleSheet("color: green;")
        active_layout.addWidget(self.active_scan_status)
        active_layout.addStretch()
        active_group.setLayout(active_layout)
        layout.addWidget(active_group)

    def _setup_filters(self, layout):
        filter_group = QGroupBox("Filtros")
        filter_layout = QHBoxLayout()

        filter_layout.addWidget(QLabel("Severidade:"))
        self.severity_filter = QComboBox()
        self.severity_filter.addItems(["Todas", "Critical", "High", "Medium", "Low"])
        filter_layout.addWidget(self.severity_filter)

        filter_layout.addWidget(QLabel("Origem:"))
        self.source_filter = QComboBox()
        self.source_filter.addItems(["Todas", "Active", "Passive"])
        filter_layout.addWidget(self.source_filter)

        filter_layout.addWidget(QLabel("Tipo:"))
        self.type_filter = QLineEdit()
        self.type_filter.setPlaceholderText("Ex: SQL Injection, XSS")
        filter_layout.addWidget(self.type_filter)

        filter_layout.addWidget(QLabel("Domínio:"))
        self.domain_filter = QLineEdit()
        self.domain_filter.setPlaceholderText("ex: google.com,*.site.com")
        filter_layout.addWidget(self.domain_filter)

        self.severity_filter.currentIndexChanged.connect(self._apply_filters)
        self.source_filter.currentIndexChanged.connect(self._apply_filters)
        self.type_filter.textChanged.connect(self._apply_filters)
        self.domain_filter.textChanged.connect(self._apply_filters)

        clear_button = QPushButton("Limpar Filtros")
        clear_button.clicked.connect(self._clear_filters)
        filter_layout.addWidget(clear_button)

        filter_layout.addStretch()
        filter_group.setLayout(filter_layout)
        layout.addWidget(filter_group)

    def _setup_vulnerability_table(self, parent):
        table_group = QGroupBox("Vulnerabilidades Detectadas")
        table_layout = QVBoxLayout()
        self.vuln_table = QTableView()
        self.vuln_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.vuln_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.vuln_table.setSortingEnabled(True)
        self.vuln_model = VulnerabilityTableModel([])
        self.proxy_model = VulnerabilityFilterProxyModel()
        self.proxy_model.setSourceModel(self.vuln_model)
        self.vuln_table.setModel(self.proxy_model)
        header = self.vuln_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch) # URL
        selection_model = self.vuln_table.selectionModel()
        selection_model.selectionChanged.connect(self._on_selection_changed)
        table_layout.addWidget(self.vuln_table)
        table_group.setLayout(table_layout)
        parent.addWidget(table_group)

    def _setup_details_panel(self, parent):
        details_group = QGroupBox("Detalhes da Vulnerabilidade")
        details_layout = QVBoxLayout()
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        details_layout.addWidget(self.details_text)
        details_group.setLayout(details_layout)
        parent.addWidget(details_group)

    def start_scan_from_request(self, entry: dict):
        """Slot público para iniciar um scan ativo a partir de um sinal externo."""
        if not entry:
            log.warning("ScannerTab recebeu uma requisição vazia para escanear.")
            return
        if self.scan_worker and self.scan_worker.isRunning():
            QMessageBox.warning(self, "Scanner Ativo", "Um scan ativo já está em execução.")
            return
        request_data_for_scanner = {
            'id': entry.get('id'),
            'method': entry.get('method'),
            'url': entry.get('url'),
            'headers': entry.get('request_headers', {}),
            'body': entry.get('request_body', '')
        }
        self.set_active_scan_status(f"Escaneando {request_data_for_scanner['url']}...", "blue")
        self.scan_worker = ScanWorker(self.active_scanner, request_data_for_scanner)
        self.scan_worker.scan_complete.connect(self._on_scan_complete)
        self.scan_worker.finished.connect(lambda: self.set_active_scan_status("Scan finalizado.", "green"))
        self.scan_worker.finished.connect(self.scan_worker.deleteLater)
        self.scan_worker.start()

    def _on_scan_complete(self, request_data: dict, vulnerabilities: list):
        if not vulnerabilities:
            log.info(f"Nenhuma vulnerabilidade encontrada para {request_data['url']}")
            return
        log.info(f"{len(vulnerabilities)} novas vulnerabilidades ativas encontradas para {request_data['id']}. Atualizando UI.")
        self.history_manager.add_vulnerabilities_to_entry(request_data['id'], vulnerabilities)
        self.refresh_vulnerabilities()

    def _on_selection_changed(self, selected, deselected):
        if not selected.indexes():
            return
        proxy_index = selected.indexes()[0]
        source_index = self.proxy_model.mapToSource(proxy_index)
        vuln_data = self.vuln_model.get_vulnerability(source_index.row())
        if vuln_data:
            vuln = vuln_data['vuln']
            entry = vuln_data['entry']
            details = f"VULNERABILIDADE DETECTADA\n"
            details += f"{ '='*80}\n\n"
            details += f"Origem: {vuln.get('source', 'N/A')}\n"
            details += f"Tipo: {vuln['type']}\n"
            details += f"Severidade: {vuln['severity']}\n"
            details += f"URL: {vuln.get('url', 'N/A')}\n"
            details += f"Método: {vuln.get('method', 'N/A')}\n\n"
            details += f"Descrição:\n{vuln['description']}\n\n"
            details += f"Evidência:\n{vuln.get('evidence', 'N/A')}\n\n"
            details += f"{ '='*80}\n\n"
            details += f"Requisição Original:\n"
            details += f"ID: {entry['id']}\n"
            details += f"Timestamp: {entry['timestamp']}\n"
            details += f"Host: {entry['host']}\n"
            details += f"Path: {entry['path']}\n"
            details += f"Status: {entry['status']}\n"
            self.details_text.setPlainText(details)

    def _apply_filters(self):
        severity = self.severity_filter.currentText()
        vuln_type = self.type_filter.text().strip()
        source = self.source_filter.currentText()
        domain = self.domain_filter.text().strip()
        self.proxy_model.set_filters(severity, vuln_type, source, domain)
        self._update_count()

    def _clear_filters(self):
        self.severity_filter.setCurrentIndex(0)
        self.source_filter.setCurrentIndex(0)
        self.type_filter.clear()
        self.domain_filter.clear()
        self._apply_filters()

    def refresh_vulnerabilities(self):
        vulnerabilities = []
        for entry in self.history_manager.get_history():
            if entry.get('vulnerabilities'):
                for i, vuln in enumerate(entry['vulnerabilities'], 1):
                    vulnerabilities.append({
                        'id': f"{entry['id']}-{i}",
                        'severity': vuln['severity'],
                        'source': vuln.get('source', 'N/A'),
                        'type': vuln['type'],
                        'url': vuln.get('url', 'N/A'),
                        'method': vuln.get('method', 'N/A'),
                        'vuln': vuln,
                        'entry': entry
                    })
        self.vuln_model.update_data(vulnerabilities)
        self._update_count()

    def _update_count(self):
        count = self.proxy_model.rowCount()
        self.count_label.setText(f"Total: {count} vulnerabilidade(s)")

    def set_active_scan_status(self, status: str, color: str = "green"):
        self.active_scan_status.setText(status)
        self.active_scan_status.setStyleSheet(f"color: {color};")

    def stop_active_scan(self):
        """Finaliza o scan ativo antes de encerrar a aplicação."""
        if self.scan_worker and self.scan_worker.isRunning():
            log.info("Aguardando finalização do scan ativo...")
            self.scan_worker.requestInterruption()
            self.scan_worker.wait(3000)
            if self.scan_worker.isRunning():
                log.warning("Scan ativo ainda em execução. Forçando encerramento.")
                self.scan_worker.terminate()
                self.scan_worker.wait(1000)


class VulnerabilityTableModel(QAbstractTableModel):
    def __init__(self, data=None):
        super().__init__()
        self._data = data or []
        self._headers = ['ID', 'Severidade', 'Origem', 'Tipo', 'URL', 'Método']

    def data(self, index, role):
        if role == Qt.ItemDataRole.DisplayRole:
            vuln = self._data[index.row()]
            col = index.column()
            if col == 0: return vuln['id']
            elif col == 1: return vuln['severity']
            elif col == 2: return vuln.get('source', '')
            elif col == 3: return vuln['type']
            elif col == 4:
                return vuln['url']
            elif col == 5: return vuln['method']
        
        elif role == Qt.ItemDataRole.ForegroundRole:
            vuln = self._data[index.row()]
            severity = vuln['severity']
            if severity == 'Critical': return QBrush(QColor(255, 0, 0))
            elif severity == 'High': return QBrush(QColor(255, 165, 0))
            elif severity == 'Medium': return QBrush(QColor(218, 165, 32))
            elif severity == 'Low': return QBrush(QColor(128, 128, 128))
        
        return None

    def rowCount(self, index=QModelIndex()):
        return len(self._data)

    def columnCount(self, index=QModelIndex()):
        return len(self._headers)

    def headerData(self, section, orientation, role):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self._headers[section]
        return None

    def get_vulnerability(self, row):
        if 0 <= row < len(self._data):
            return self._data[row]
        return None

    def update_data(self, new_data):
        self.beginResetModel()
        self._data = new_data
        self.endResetModel()


class VulnerabilityFilterProxyModel(QSortFilterProxyModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.severity_filter = "Todas"
        self.type_filter = ""
        self.source_filter = "Todas"
        self.domain_filter = ""

    def set_filters(self, severity: str, vuln_type: str, source: str, domain: str):
        self.severity_filter = severity
        self.type_filter = vuln_type.lower()
        self.source_filter = source
        self.domain_filter = domain.lower()
        self.invalidateFilter()

    def filterAcceptsRow(self, source_row, source_parent):
        severity_index = self.sourceModel().index(source_row, 1, source_parent)
        source_index = self.sourceModel().index(source_row, 2, source_parent)
        type_index = self.sourceModel().index(source_row, 3, source_parent)
        url_index = self.sourceModel().index(source_row, 4, source_parent)

        severity_data = self.sourceModel().data(severity_index, Qt.ItemDataRole.DisplayRole)
        source_data = self.sourceModel().data(source_index, Qt.ItemDataRole.DisplayRole)
        type_data = self.sourceModel().data(type_index, Qt.ItemDataRole.DisplayRole)
        url_data = self.sourceModel().data(url_index, Qt.ItemDataRole.DisplayRole)

        severity_match = (self.severity_filter == "Todas" or self.severity_filter == severity_data)
        source_match = (self.source_filter == "Todas" or self.source_filter == source_data)
        type_match = (self.type_filter in type_data.lower())
        domain_match = (self.domain_filter in url_data.lower())

        return severity_match and source_match and type_match and domain_match
