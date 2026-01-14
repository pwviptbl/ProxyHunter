import re
from PySide6.QtCore import Qt, Signal, QThread
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QPushButton, QLabel, QLineEdit,
                               QGroupBox, QHBoxLayout, QTextEdit, QProgressBar, QTableView,
                               QAbstractItemView, QMessageBox, QFileDialog, QSpinBox, QComboBox, QTabWidget, QHeaderView)
from PySide6.QtCore import QAbstractTableModel, QModelIndex
import queue
import threading

from src.core.attacker import run_attacker
from src.core.config import InterceptConfig
from src.core.cookie_manager import CookieManager
from src.core.logger_config import log


class AttackerResultsModel(QAbstractTableModel):
    """Model for displaying attacker results in a table."""
    def __init__(self):
        super().__init__()
        self._data = []
        self._headers = ['Payload', 'Status', 'Tamanho', 'URL']

    def data(self, index, role):
        if role == Qt.ItemDataRole.DisplayRole:
            row = index.row()
            col = index.column()
            if 0 <= row < len(self._data):
                result = self._data[row]
                if col == 0:
                    return result.get('payload', '')
                elif col == 1:
                    return str(result.get('status', 'Error'))
                elif col == 2:
                    return str(result.get('length', 0))
                elif col == 3:
                    return result.get('url', 'N/A')
        elif role == Qt.ItemDataRole.ForegroundRole:
            row = index.row()
            if 0 <= row < len(self._data):
                result = self._data[row]
                if result.get('success', False):
                    from PySide6.QtGui import QColor
                    return QColor('green')
                else:
                    from PySide6.QtGui import QColor
                    return QColor('red')
        return None

    def rowCount(self, index=QModelIndex()):
        return len(self._data)

    def columnCount(self, index=QModelIndex()):
        return len(self._headers)

    def headerData(self, section, orientation, role):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self._headers[section]
        return None

    def add_result(self, result):
        """Add a result to the model."""
        row = self.rowCount()
        self.beginInsertRows(QModelIndex(), row, row)
        self._data.append(result)
        self.endInsertRows()

    def clear(self):
        """Clear all results."""
        self.beginResetModel()
        self._data = []
        self.endResetModel()


class AttackerWorker(QThread):
    """Worker thread for running attacker operations."""
    progress_updated = Signal(int)
    result_added = Signal(dict)
    finished_signal = Signal()

    def __init__(self, raw_request: str, attack_type: str, payloads: dict, num_threads: int, proxy_port: int, use_tor: bool = False, tor_port: int = 9050, history=None):
        super().__init__()
        self.raw_request = raw_request
        self.attack_type = attack_type
        self.payloads = payloads
        self.num_threads = num_threads
        self.proxy_port = proxy_port
        self.use_tor = use_tor
        self.tor_port = tor_port
        self.history = history
        self.result_queue = queue.Queue()

    def run(self):
        """Execute the attacker operation in a separate thread."""
        try:
            # Start the attacker operation
            run_attacker(
                self.raw_request,
                self.attack_type,
                self.payloads,
                self.num_threads,
                self.result_queue,
                self.proxy_port,
                self.use_tor,
                self.tor_port,
                self.history
            )

            # Process results from the queue
            while True:
                try:
                    message = self.result_queue.get(timeout=0.1)
                    msg_type = message.get('type')

                    if msg_type == 'progress_update':
                        progress = int(message.get('value', 0))
                        self.progress_updated.emit(progress)
                    elif msg_type == 'result':
                        result_data = message.get('data')
                        if result_data:
                            self.result_added.emit(result_data)
                    elif msg_type == 'progress_done':
                        self.progress_updated.emit(100)
                        break
                except queue.Empty:
                    continue
        except Exception as e:
            log.error(f"Error in AttackerWorker: {e}", exc_info=True)
        finally:
            self.finished_signal.emit()


class AttackerTab(QWidget):
    def _show_request_response_dialog(self, index):
        row = index.row()
        if row < 0 or row >= self.results_model.rowCount():
            return
        result = self.results_model._data[row]

        # Monta o texto do request exatamente como foi enviado
        # Se possível, armazene o raw_request já montado no momento do envio e salve no result
        if 'raw_request' in result:
            request_text = result['raw_request']
        else:
            request_lines = []
            request_lines.append(f"{result.get('method', '')} {result.get('path', '')} HTTP/1.1")
            request_lines.append(f"Host: {result.get('host', '')}")
            for k, v in result.get('request_headers', {}).items():
                if k.lower() != 'host':
                    request_lines.append(f"{k}: {v}")
            request_lines.append("")
            if result.get('request_body'):
                request_lines.append(result['request_body'])
            # Se houver payload, destaque no corpo
            if result.get('payload') and result.get('payload') not in request_lines[-1]:
                request_lines.append(f"\n# Payload aplicado: {result['payload']}")
            request_text = '\n'.join(request_lines)

        # Monta o texto do response igual ao histórico
        response_lines = []
        status_code = result.get('status', '')
        # Tenta obter a linha de status HTTP completa
        status_line = f"HTTP/1.1 {status_code}"
        if 'response_headers' in result:
            # Se houver header 'Content-Type', tenta extrair o motivo (OK, Not Found, etc)
            # (Opcional: pode-se mapear status_code para motivo, mas para simplificar, só mostra o código)
            response_lines.append(status_line)
            for k, v in result.get('response_headers', {}).items():
                response_lines.append(f"{k}: {v}")
            response_lines.append("")
        if result.get('response_body'):
            response_lines.append(result['response_body'])
        response_text = '\n'.join(response_lines)

        from src.ui.dialogs.request_response_dialog import RequestResponseDialog
        dlg = RequestResponseDialog(request_text, response_text, self)
        dlg.exec()
    """Tab for automated attacker operations."""

    def __init__(self, cookie_manager: CookieManager = None, history=None):
        super().__init__()
        self.config = InterceptConfig()
        self.cookie_manager = cookie_manager if cookie_manager else CookieManager()
        self.history = history
        self.worker = None
        self.file_path = None
        self._setup_ui()

    def _select_payload_file(self):
        """Opens a file dialog to select a payload file."""
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select Payload File",
            "",
            "Text Files (*.txt);;All Files (*)"
        )
        if file_path:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    payloads = f.read()
                
                self.payload_list_text.setPlainText(payloads)
                self.payload_file_label.setText(file_path.split('/')[-1])
                self.file_path = file_path # Store the path
                
                # Switch to the Simple List tab to show the loaded payloads
                self.payloads_tabs.setCurrentIndex(0)
                log.info(f"Loaded payloads from {file_path}")

            except Exception as e:
                log.error(f"Failed to load payload file: {e}", exc_info=True)
                QMessageBox.warning(self, "Error", f"Could not load file: {e}")

    def _setup_ui(self):
        """Setup the user interface."""
        layout = QVBoxLayout(self)

        # Configuration panel
        self._setup_config_panel(layout)

        # Request text area
        self._setup_request_panel(layout)

        # Progress bar
        self._setup_progress_panel(layout)

        # Results table
        self._setup_results_panel(layout)

    def _setup_config_panel(self, layout):
        """Setup the attacker configuration panel."""
        config_group = QGroupBox("Attacker Configuration")
        config_layout = QVBoxLayout()

        # Attack Type
        attack_type_layout = QHBoxLayout()
        attack_type_layout.addWidget(QLabel("Attack Type:"))
        self.attack_type_combo = QComboBox()
        self.attack_type_combo.addItems(["Sniper", "Battering Ram", "Pitchfork", "Cluster Bomb"])
        attack_type_layout.addWidget(self.attack_type_combo)

        self.attack_type_help_button = QPushButton("?")
        self.attack_type_help_button.setFixedSize(25, 25)
        self.attack_type_help_button.setToolTip("Clique para obter ajuda sobre os tipos de ataque")
        self.attack_type_help_button.clicked.connect(self._show_attack_type_help)
        attack_type_layout.addWidget(self.attack_type_help_button)

        attack_type_layout.addStretch()
        config_layout.addLayout(attack_type_layout)

        # Payloads
        payloads_group = QGroupBox("Payloads")
        self.payloads_tabs = QTabWidget()

        # Simple List
        simple_list_tab = QWidget()
        simple_list_layout = QVBoxLayout()
        self.payload_list_text = QTextEdit()
        simple_list_layout.addWidget(self.payload_list_text)
        simple_list_tab.setLayout(simple_list_layout)
        self.payloads_tabs.addTab(simple_list_tab, "Simple List")

        # Load File
        load_file_tab = QWidget()
        load_file_layout = QHBoxLayout()
        self.payload_file_label = QLabel("No file selected.")
        self.payload_file_button = QPushButton("Select File...")
        self.payload_file_button.clicked.connect(self._select_payload_file)
        load_file_layout.addWidget(self.payload_file_label)
        load_file_layout.addWidget(self.payload_file_button)
        load_file_layout.addStretch()
        load_file_tab.setLayout(load_file_layout)
        self.payloads_tabs.addTab(load_file_tab, "Load File")

        config_layout.addWidget(self.payloads_tabs)

        # Threads
        threads_layout = QHBoxLayout()
        threads_layout.addWidget(QLabel("Threads:"))
        self.threads_spinbox = QSpinBox()
        self.threads_spinbox.setMinimum(1)
        self.threads_spinbox.setMaximum(100)
        self.threads_spinbox.setValue(10)
        threads_layout.addWidget(self.threads_spinbox)
        threads_layout.addStretch()
        config_layout.addLayout(threads_layout)

        # TOR Configuration
        tor_layout = QHBoxLayout()
        from PySide6.QtWidgets import QCheckBox
        self.use_tor_checkbox = QCheckBox("Use TOR")
        self.use_tor_checkbox.setToolTip("Route requests through TOR network for anonymity")
        tor_layout.addWidget(self.use_tor_checkbox)
        tor_layout.addStretch()
        config_layout.addLayout(tor_layout)

        # Start button
        self.start_button = QPushButton("Start Attack")
        self.start_button.clicked.connect(self._start_attacker)
        config_layout.addWidget(self.start_button)

        config_group.setLayout(config_layout)
        layout.addWidget(config_group)

    def _setup_request_panel(self, layout):
        """Setup the request text area."""
        request_group = QGroupBox("Target Request")
        request_layout = QVBoxLayout()

        self.request_text = QTextEdit()
        self.request_text.setFontFamily("Courier")
        self.request_text.setPlaceholderText(
            "Use 'Send to Attacker' from the History tab to load a request."
        )

        # Add buttons for payload markers
        marker_buttons_layout = QHBoxLayout()
        self.add_marker_button = QPushButton("Add §")
        self.add_marker_button.clicked.connect(self._add_payload_marker)
        self.clear_markers_button = QPushButton("Clear §§")
        self.clear_markers_button.clicked.connect(self._clear_payload_markers)
        marker_buttons_layout.addWidget(self.add_marker_button)
        marker_buttons_layout.addWidget(self.clear_markers_button)
        marker_buttons_layout.addStretch()
        request_layout.addLayout(marker_buttons_layout)

        request_layout.addWidget(self.request_text)
        request_group.setLayout(request_layout)
        layout.addWidget(request_group)

    def _setup_progress_panel(self, layout):
        """Setup the progress bar."""
        self.progress_bar = QProgressBar()
        self.progress_bar.setMinimum(0)
        self.progress_bar.setMaximum(100)
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)

    def _setup_results_panel(self, layout):
        """Setup the results table."""
        results_group = QGroupBox("Resultados do Envio")
        results_layout = QVBoxLayout()

        # Table view
        self.results_table = QTableView()
        self.results_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.results_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)

        self.results_model = AttackerResultsModel()
        self.results_table.setModel(self.results_model)

        # Ajusta largura da coluna URL
        header = self.results_table.horizontalHeader()
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)

        # Conecta duplo clique para abrir detalhes
        self.results_table.doubleClicked.connect(self._show_request_response_dialog)

        results_layout.addWidget(self.results_table)

        # Clear button
        clear_button = QPushButton("Limpar Resultados")
        clear_button.clicked.connect(self._clear_results)
        results_layout.addWidget(clear_button)

        results_group.setLayout(results_layout)
        layout.addWidget(results_group)

    def _show_attack_type_help(self):
        """Displays a message box with explanations of the attack types."""
        help_text = """<h3>Tipos de Ataque</h3>
<p><b>Sniper:</b> Testa um payload de cada vez em uma posição de cada vez. Ideal para fuzzing de parâmetros individuais para encontrar vulnerabilidades.</p>
<p><b>Battering Ram:</b> Usa o mesmo payload em todas as posições marcadas ao mesmo tempo. Útil quando um mesmo valor precisa ser enviado em múltiplos lugares.</p>
<p><b>Pitchfork:</b> Requer uma lista de payloads para cada posição. Ele envia o primeiro payload da lista 1 na posição 1, o primeiro da lista 2 na posição 2, e assim por diante. Perfeito para testar combinações de credenciais (lista de usuários na posição 1, lista de senhas na posição 2).</p>
<p><b>Cluster Bomb:</b> Testa todas as combinações possíveis de payloads entre as listas. Gera um número massivo de requisições, mas é o mais completo para testar múltiplos parâmetros interligados.</p>"""
        QMessageBox.information(self, "Ajuda sobre Tipos de Ataque", help_text)

    def _start_attacker(self):
        """Start the attacker operation."""
        # Validate inputs
        raw_request = self.request_text.toPlainText().strip()
        if not raw_request:
            QMessageBox.warning(self, "Warning", "The 'Target Request' is empty.")
            return

        # Injeta os cookies do Jar na requisição
        raw_request = self._inject_jar_cookies(raw_request)

        # Clear previous results
        self._clear_results()

        # Disable the start button
        self.start_button.setEnabled(False)

        attack_type = self.attack_type_combo.currentText()
        payloads = self.payload_list_text.toPlainText().splitlines()
        num_threads = self.threads_spinbox.value()
        proxy_port = self.config.get_port()
        use_tor = self.use_tor_checkbox.isChecked()
        tor_port = self.config.get_tor_port()

        # Create and start the worker
        self.worker = AttackerWorker(raw_request, attack_type, payloads, num_threads, proxy_port, use_tor, tor_port, self.history)
        self.worker.progress_updated.connect(self._on_progress_updated)
        self.worker.result_added.connect(self._on_result_added)
        self.worker.finished_signal.connect(self._on_worker_finished)
        self.worker.start()

        log.info("Started attacker")

    def _inject_jar_cookies(self, raw_request: str) -> str:
        """Substitui ou adiciona o cabeçalho de Cookie na requisição com os cookies do Jar."""
        jar_header = self.cookie_manager.get_jar_cookies_header()
        if not jar_header:
            return raw_request  # Retorna a requisição original se o Jar estiver vazio

        cookie_header_line = f"Cookie: {jar_header}"

        # Tenta substituir o cabeçalho de Cookie existente
        new_request, count = re.subn(
            r'^Cookie:.*$', cookie_header_line, raw_request, flags=re.IGNORECASE | re.MULTILINE
        )

        # Se nenhum cabeçalho de Cookie foi substituído, adiciona um novo
        if count == 0:
            # Insere o cabeçalho de Cookie após a linha do Host
            if '\nHost:' in new_request:
                new_request = re.sub(r'(\nHost:[^\n]*)', r'\1\n' + cookie_header_line, new_request, count=1)
            else:
                # Adiciona após a primeira linha (linha de requisição)
                parts = new_request.split('\n', 1)
                if len(parts) > 1:
                    new_request = f"{parts[0]}\n{cookie_header_line}\n{parts[1]}"
                else:
                    new_request = f"{parts[0]}\n{cookie_header_line}"

        return new_request

    def _on_progress_updated(self, progress: int):
        """Handle progress updates."""
        self.progress_bar.setValue(progress)

    def _on_result_added(self, result: dict):
        """Handle new result."""
        self.results_model.add_result(result)

    def _on_worker_finished(self):
        """Handle worker completion."""
        self.start_button.setEnabled(True)
        self.worker = None
        log.info("Attacker operation completed")

    def _clear_results(self):
        """Clear the results table and progress bar."""
        self.results_model.clear()
        self.progress_bar.setValue(0)

    def set_request_data(self, entry: dict):
        """
        Populate the request text area with data from a history entry.
        This is the public method called when sending data from the History tab.

        Args:
            entry: Dictionary containing request data from history
        """
        # Format the request
        request_info = f"{entry['method']} {entry['path']} HTTP/1.1\n"
        request_info += f"Host: {entry['host']}\n"

        for key, value in entry['request_headers'].items():
            request_info += f"{key}: {value}\n"

        if entry.get('request_body'):
            request_info += f"\n{entry['request_body']}"

        # Set the text
        self.request_text.setPlainText(request_info)

        log.info(f"Populated Attacker tab with request from history entry {entry['id']}")

    def _add_payload_marker(self):
        """Adds payload markers (§) around the selected text in the request."""
        cursor = self.request_text.textCursor()
        if cursor.hasSelection():
            selected_text = cursor.selectedText()
            cursor.insertText(f"§{selected_text}§")

    def _clear_payload_markers(self):
        """Removes all payload markers (§) from the request text."""
        current_text = self.request_text.toPlainText()
        new_text = current_text.replace("§", "")
        self.request_text.setPlainText(new_text)
