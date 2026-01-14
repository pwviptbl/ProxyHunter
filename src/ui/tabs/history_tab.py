import re
from PySide6.QtCore import QAbstractTableModel, Qt, Signal, QSortFilterProxyModel, QModelIndex
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QPushButton, QLabel, QLineEdit,
                               QGroupBox, QHBoxLayout, QTableView, QAbstractItemView,
                               QTextEdit, QTabWidget, QSplitter, QComboBox, QHeaderView, QMessageBox, QMenu, QCheckBox)
from PySide6.QtGui import QAction, QCursor
from urllib.parse import urlparse

from src.core.history import RequestHistory

class HistoryTab(QWidget):
    """Aba de UI para exibir o histórico de requisições."""

    send_to_repeater_requested = Signal(dict)
    send_to_attacker_requested = Signal(dict)
    send_to_jwt_editor_requested = Signal(str, dict) # token, entry
    scan_requested = Signal(dict)
    set_comparator_request_1_requested = Signal(dict)
    set_comparator_request_2_requested = Signal(dict)
    add_host_to_scope_requested = Signal(str)
    clear_history_requested = Signal()

    def __init__(self, history: RequestHistory, config):
        super().__init__()
        self.history_manager = history
        self.config = config

        layout = QVBoxLayout(self)

        self._setup_filters(layout)

        splitter = QSplitter(Qt.Orientation.Vertical)
        layout.addWidget(splitter)

        self._setup_history_table(splitter)
        self._setup_details_panel(splitter)

        splitter.setSizes([400, 300]) # Tamanhos iniciais

    def _setup_filters(self, layout):
        filter_group = QGroupBox("Filtros")
        filter_layout = QHBoxLayout()

        # Filtro por método
        filter_layout.addWidget(QLabel("Método:"))
        self.method_filter = QComboBox()
        self.method_filter.addItems(["Todos", "GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
        filter_layout.addWidget(self.method_filter)

        # Filtro por domínio
        filter_layout.addWidget(QLabel("Domínio:"))
        self.domain_filter = QLineEdit()
        self.domain_filter.setPlaceholderText("ex: google.com")
        filter_layout.addWidget(self.domain_filter)

        # Filtro por status
        filter_layout.addWidget(QLabel("Status:"))
        self.status_filter = QLineEdit()
        self.status_filter.setPlaceholderText("ex: 200,201 ou !404,!500")
        filter_layout.addWidget(self.status_filter)

        # Filtro de escopo
        self.scope_filter_checkbox = QCheckBox("Apenas no escopo")
        filter_layout.addWidget(self.scope_filter_checkbox)

        # Botões de ação
        apply_button = QPushButton("Aplicar Filtros")
        apply_button.clicked.connect(self._apply_filters)
        filter_layout.addWidget(apply_button)

        clear_button = QPushButton("Limpar Histórico")
        clear_button.clicked.connect(self._confirm_clear_history)
        filter_layout.addWidget(clear_button)

        filter_layout.addStretch()
        filter_group.setLayout(filter_layout)
        layout.addWidget(filter_group)

    def _setup_history_table(self, parent):
        table_group = QGroupBox("Requisições Capturadas")
        table_layout = QVBoxLayout()

        self.history_table = QTableView()
        self.history_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.history_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.history_table.setSortingEnabled(True)

        self.history_model = HistoryTableModel(self.history_manager.get_history())
        self.proxy_model = HistoryFilterProxyModel(self.config)
        self.proxy_model.setSourceModel(self.history_model)
        self.history_table.setModel(self.proxy_model)

        header = self.history_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch) # Host
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch) # URL
        self.history_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.history_table.customContextMenuRequested.connect(self._show_context_menu)

        selection_model = self.history_table.selectionModel()
        selection_model.selectionChanged.connect(self._on_selection_changed)

        table_layout.addWidget(self.history_table)
        table_group.setLayout(table_layout)
        parent.addWidget(table_group)

    def _setup_details_panel(self, parent):
        details_group = QGroupBox("Detalhes da Requisição")
        details_layout = QVBoxLayout()

        self.details_tabs = QTabWidget()
        self.request_text = QTextEdit()
        self.request_text.setReadOnly(True)
        self.response_text = QTextEdit()
        self.response_text.setReadOnly(True)

        self.details_tabs.addTab(self.request_text, "Request")
        self.details_tabs.addTab(self.response_text, "Response")

        details_layout.addWidget(self.details_tabs)
        details_group.setLayout(details_layout)
        parent.addWidget(details_group)

    def _show_context_menu(self, pos):
        """Exibe o menu de contexto na tabela."""
        selected_indexes = self.history_table.selectionModel().selectedRows()
        if not selected_indexes:
            return

        row = selected_indexes[0].row()
        source_index = self.proxy_model.mapToSource(selected_indexes[0])
        entry = self.history_model.get_entry(source_index.row())

        if not entry:
            return

        menu = QMenu(self)

        scan_action = QAction("Escanear Ativamente esta Requisição", self)
        scan_action.triggered.connect(lambda: self.scan_requested.emit(entry))
        menu.addAction(scan_action)

        menu.addSeparator()

        send_to_repeater_action = QAction("Enviar para Repetição", self)
        send_to_repeater_action.triggered.connect(lambda: self.send_to_repeater_requested.emit(entry))
        menu.addAction(send_to_repeater_action)

        send_to_attacker_action = QAction("Enviar para o Attacker", self)
        send_to_attacker_action.triggered.connect(lambda: self.send_to_attacker_requested.emit(entry))
        menu.addAction(send_to_attacker_action)

        menu.addSeparator()

        set_comparator_1_action = QAction("Definir como Requisição 1 (Comparador)", self)
        set_comparator_1_action.triggered.connect(lambda: self.set_comparator_request_1_requested.emit(entry))
        menu.addAction(set_comparator_1_action)

        set_comparator_2_action = QAction("Definir como Requisição 2 (Comparador)", self)
        set_comparator_2_action.triggered.connect(lambda: self.set_comparator_request_2_requested.emit(entry))
        menu.addAction(set_comparator_2_action)

        menu.addSeparator()

        add_to_scope_action = QAction("Adicionar host ao Escopo", self)
        url_value = entry.get('url', '') if isinstance(entry, dict) else ''
        parsed = urlparse(url_value) if url_value else None
        scope_target = parsed.netloc if parsed and parsed.netloc else entry.get('host', '')
        add_to_scope_action.triggered.connect(lambda: self.add_host_to_scope_requested.emit(scope_target))
        menu.addAction(add_to_scope_action)

        # Verifica se há um JWT na requisição
        jwt_token = self._find_jwt_in_request(entry)
        if jwt_token:
            menu.addSeparator()
            send_to_jwt_action = QAction("Enviar para o Editor de JWT", self)
            send_to_jwt_action.triggered.connect(
                lambda: self.send_to_jwt_editor_requested.emit(jwt_token, entry)
            )
            menu.addAction(send_to_jwt_action)

        menu.addSeparator()

        add_to_filter_action = QAction("Adicionar ao Filtro", self)
        add_to_filter_action.triggered.connect(lambda: self._add_to_filter(entry))
        menu.addAction(add_to_filter_action)

        menu.exec_(self.history_table.viewport().mapToGlobal(pos))

    def _add_to_filter(self, entry: dict):
        """Adiciona o host da entrada ao filtro de domínio."""
        if 'host' in entry:
            self.domain_filter.setText(entry['host'])


    def _find_jwt_in_request(self, entry: dict):
        """Procura por um JWT nos headers ou no corpo de uma requisição e retorna o primeiro encontrado."""
        jwt_pattern = r'ey[a-zA-Z0-9_-]{10,}\.ey[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]*'

        # 1. Procura no header Authorization
        auth_header = entry['request_headers'].get('Authorization', '')
        if 'bearer' in auth_header.lower():
            match = re.search(jwt_pattern, auth_header)
            if match:
                return match.group(0)

        # 2. Procura em outros headers (ex: Cookies)
        for value in entry['request_headers'].values():
            match = re.search(jwt_pattern, value)
            if match:
                return match.group(0)

        # 3. Procura no corpo da requisição
        if isinstance(entry['request_body'], str):
            match = re.search(jwt_pattern, entry['request_body'])
            if match:
                return match.group(0)

        return None

    def _on_selection_changed(self, selected, deselected):
        """Exibe os detalhes da requisição selecionada."""
        if not selected.indexes():
            return

        proxy_index = selected.indexes()[0]
        source_index = self.proxy_model.mapToSource(proxy_index)
        entry = self.history_model.get_entry(source_index.row())

        if entry:
            req_headers = "\n".join(f"{k}: {v}" for k, v in entry['request_headers'].items())
            req_full = f"{entry['method']} {entry['path']} HTTP/1.1\nHost: {entry['host']}\n{req_headers}\n\n{entry['request_body']}"
            self.request_text.setPlainText(req_full)

            resp_headers = "\n".join(f"{k}: {v}" for k, v in entry['response_headers'].items())
            resp_full = f"Status: {entry['status']}\n{resp_headers}\n\n{entry['response_body']}"
            self.response_text.setPlainText(resp_full)

    def add_history_entry(self, entry: dict):
        """Adiciona uma nova entrada de histórico à tabela."""
        self.history_model.add_entry(entry)

    def refresh_data(self):
        """Atualiza a tabela com os dados do history manager."""
        self.history_model.update_data(self.history_manager.get_history())

    def clear_display(self):
        """Limpa a exibição da tabela."""
        self.history_model.clear()

    def _confirm_clear_history(self):
        """Exibe um diálogo de confirmação antes de limpar o histórico."""
        reply = QMessageBox.question(self, 'Confirmar Limpeza',
                                     "Você tem certeza que deseja limpar todo o histórico?",
                                     QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                     QMessageBox.StandardButton.No)
        if reply == QMessageBox.StandardButton.Yes:
            self.clear_history_requested.emit()

    def _apply_filters(self):
        """Aplica os filtros de método, domínio, status e escopo na tabela."""
        method = self.method_filter.currentText()
        domain = self.domain_filter.text().strip()
        status = self.status_filter.text().strip()
        scope_only = self.scope_filter_checkbox.isChecked()
        self.proxy_model.set_filters(method, domain, status, scope_only)

class HistoryTableModel(QAbstractTableModel):
    def __init__(self, data=None):
        super().__init__()
        self._data = data or []
        self._headers = ['ID', 'Host', 'Método', 'Status', 'URL']

    def data(self, index, role):
        if role == Qt.ItemDataRole.DisplayRole:
            entry = self._data[index.row()]
            col = index.column()
            if col == 0: return entry['id']
            if col == 1: return entry['host']
            if col == 2: return entry['method']
            if col == 3: return entry['status']
            if col == 4: return entry['url']
        return None

    def rowCount(self, index=QModelIndex()):
        return len(self._data)

    def columnCount(self, index=QModelIndex()):
        return len(self._headers)

    def headerData(self, section, orientation, role):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self._headers[section]
        return None

    def add_entry(self, entry):
        row = self.rowCount()
        self.beginInsertRows(QModelIndex(), row, row)
        self._data.append(entry)
        self.endInsertRows()

    def get_entry_id(self, row):
        return self._data[row]['id']

    def get_entry(self, row):
        if 0 <= row < len(self._data):
            return self._data[row]
        return None

    def clear(self):
        """Limpa todos os dados do modelo."""
        self.beginResetModel()
        self._data = []
        self.endResetModel()

    def update_data(self, new_data):
        """Atualiza os dados do modelo."""
        self.beginResetModel()
        self._data = new_data
        self.endResetModel()

class HistoryFilterProxyModel(QSortFilterProxyModel):
    """Proxy model para filtrar o histórico."""
    def __init__(self, config, parent=None):
        super().__init__(parent)
        self.config = config
        self.method_filter = "Todos"
        self.domain_filter = ""
        self.status_filter = ""
        self.scope_only_filter = False

    def set_filters(self, method: str, domain: str, status: str, scope_only: bool):
        self.method_filter = method
        self.domain_filter = domain
        self.status_filter = status
        self.scope_only_filter = scope_only
        self.invalidateFilter()

    def parse_status_filter(self, filter_str: str):
        """Parse o filtro de status, retornando sets de include e exclude."""
        include = set()
        exclude = set()
        parts = [p.strip() for p in filter_str.split(',') if p.strip()]
        for part in parts:
            if part.startswith('!'):
                try:
                    exclude.add(int(part[1:]))
                except ValueError:
                    pass  # ignorar inválidos
            else:
                try:
                    include.add(int(part))
                except ValueError:
                    pass
        return include, exclude

    def filterAcceptsRow(self, source_row, source_parent):
        # Pega os dados da linha do modelo original
        method_index = self.sourceModel().index(source_row, 2, source_parent)
        domain_index = self.sourceModel().index(source_row, 1, source_parent)
        status_index = self.sourceModel().index(source_row, 3, source_parent)
        url_index = self.sourceModel().index(source_row, 4, source_parent)

        method_data = self.sourceModel().data(method_index, Qt.ItemDataRole.DisplayRole)
        domain_data = self.sourceModel().data(domain_index, Qt.ItemDataRole.DisplayRole)
        status_data = int(self.sourceModel().data(status_index, Qt.ItemDataRole.DisplayRole) or 0)
        url_data = self.sourceModel().data(url_index, Qt.ItemDataRole.DisplayRole)

        # Garante que os dados sejam strings antes de comparar
        method_data_str = str(method_data or "").strip().lower()
        domain_data_str = str(domain_data or "").lower()

        # Verifica as condições do filtro
        method_match = (self.method_filter.lower() == "todos" or self.method_filter.lower() == method_data_str)
        domain_match = (self.domain_filter.lower() in domain_data_str)

        # Filtro de status
        include, exclude = self.parse_status_filter(self.status_filter)
        if include:
            status_match = status_data in include
        elif exclude:
            status_match = status_data not in exclude
        else:
            status_match = True

        # Filtro de escopo
        scope_match = True
        if self.scope_only_filter:
            scope_match = self.config.is_in_scope(url_data)

        return method_match and domain_match and status_match and scope_match
