from PySide6.QtCore import Qt, Signal, QAbstractTableModel, QModelIndex, QTimer
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QPushButton, QLabel,
                               QGroupBox, QHBoxLayout, QTableView, QAbstractItemView,
                               QTextEdit, QSplitter, QHeaderView, QMessageBox)

from src.core.websocket_history import WebSocketHistory
from src.core.logger_config import log


class WebSocketConnectionsTableModel(QAbstractTableModel):
    """Model para a tabela de conexões WebSocket."""

    def __init__(self, connections):
        super().__init__()
        self.connections = connections
        self.headers = ['ID', 'Host', 'URL', 'Status', 'Mensagens', 'Início']

    def rowCount(self, parent=QModelIndex()):
        return len(self.connections)

    def columnCount(self, parent=QModelIndex()):
        return len(self.headers)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None

        conn = self.connections[index.row()]

        if role == Qt.ItemDataRole.DisplayRole:
            col = index.column()
            if col == 0:  # ID
                return str(conn['id'])
            elif col == 1:  # Host
                return conn['host']
            elif col == 2:  # URL
                return conn['url']
            elif col == 3:  # Status
                return conn['status']
            elif col == 4:  # Mensagens
                return str(conn['message_count'])
            elif col == 5:  # Início
                return conn['start_time'].strftime('%Y-%m-%d %H:%M:%S')

        return None

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.headers[section]
        return None

    def update_data(self, connections):
        """Atualiza os dados do modelo."""
        self.beginResetModel()
        self.connections = connections
        self.endResetModel()


class WebSocketMessagesTableModel(QAbstractTableModel):
    """Model para a tabela de mensagens WebSocket."""

    def __init__(self, messages):
        super().__init__()
        self.messages = messages
        self.headers = ['Timestamp', 'Direção', 'Tamanho', 'Tipo']

    def rowCount(self, parent=QModelIndex()):
        return len(self.messages)

    def columnCount(self, parent=QModelIndex()):
        return len(self.headers)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid():
            return None

        msg = self.messages[index.row()]

        if role == Qt.ItemDataRole.DisplayRole:
            col = index.column()
            if col == 0:  # Timestamp
                return msg['timestamp'].strftime('%H:%M:%S.%f')[:-3]
            elif col == 1:  # Direção
                return "Cliente → Servidor" if msg['from_client'] else "Servidor → Cliente"
            elif col == 2:  # Tamanho
                return f"{msg['size']} bytes"
            elif col == 3:  # Tipo
                return "Binário" if msg['is_binary'] else "Texto"

        return None

    def headerData(self, section, orientation, role=Qt.ItemDataRole.DisplayRole):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self.headers[section]
        return None

    def update_data(self, messages):
        """Atualiza os dados do modelo."""
        self.beginResetModel()
        self.messages = messages
        self.endResetModel()


class WebSocketTab(QWidget):
    """Aba de UI para gerenciar conexões e mensagens WebSocket."""

    def __init__(self, websocket_history: WebSocketHistory):
        super().__init__()
        self.websocket_history = websocket_history
        self.selected_ws_connection = None
        self.ws_connections_map = {}  # Mapeia índices de linha para flow_ids

        layout = QVBoxLayout(self)

        # Splitter principal para dividir conexões/mensagens/detalhes
        main_splitter = QSplitter(Qt.Orientation.Vertical)
        layout.addWidget(main_splitter)

        # Seção de conexões
        self._setup_connections_section(main_splitter)

        # Seção de mensagens
        self._setup_messages_section(main_splitter)

        # Seção de conteúdo da mensagem
        self._setup_message_content_section(main_splitter)

        # Seção de botões
        self._setup_buttons_section(layout)

        # Define tamanhos iniciais do splitter
        main_splitter.setSizes([300, 300, 200])

        # Timer para atualizar a lista de conexões periodicamente
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self._update_websocket_list)
        self.update_timer.start(2000)  # Atualiza a cada 2 segundos

    def _setup_connections_section(self, parent):
        """Configura a seção de lista de conexões WebSocket."""
        connections_group = QGroupBox("Conexões WebSocket")
        connections_layout = QVBoxLayout()

        # Tabela de conexões
        self.connections_table = QTableView()
        self.connections_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.connections_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.connections_table.setSortingEnabled(False)

        # Modelo de dados
        self.connections_model = WebSocketConnectionsTableModel([])
        self.connections_table.setModel(self.connections_model)

        # Configuração do header
        header = self.connections_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch) # Host
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch) # URL

        # Conecta seleção
        selection_model = self.connections_table.selectionModel()
        selection_model.selectionChanged.connect(self._on_connection_selected)

        connections_layout.addWidget(self.connections_table)
        connections_group.setLayout(connections_layout)
        parent.addWidget(connections_group)

    def _setup_messages_section(self, parent):
        """Configura a seção de lista de mensagens."""
        messages_group = QGroupBox("Mensagens")
        messages_layout = QVBoxLayout()

        # Tabela de mensagens
        self.messages_table = QTableView()
        self.messages_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.messages_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.messages_table.setSortingEnabled(False)

        # Modelo de dados
        self.messages_model = WebSocketMessagesTableModel([])
        self.messages_table.setModel(self.messages_model)

        # Configuração do header
        header = self.messages_table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setStretchLastSection(True)

        # Conecta seleção
        selection_model = self.messages_table.selectionModel()
        selection_model.selectionChanged.connect(self._on_message_selected)

        messages_layout.addWidget(self.messages_table)
        messages_group.setLayout(messages_layout)
        parent.addWidget(messages_group)

    def _setup_message_content_section(self, parent):
        """Configura a seção de conteúdo da mensagem."""
        content_group = QGroupBox("Conteúdo da Mensagem")
        content_layout = QVBoxLayout()

        # Área de texto para exibir o conteúdo
        self.message_content_text = QTextEdit()
        self.message_content_text.setReadOnly(True)

        content_layout.addWidget(self.message_content_text)
        content_group.setLayout(content_layout)
        parent.addWidget(content_group)

    def _setup_buttons_section(self, layout):
        """Configura a seção de botões de ação."""
        buttons_layout = QHBoxLayout()

        # Botão de atualizar
        refresh_button = QPushButton("Atualizar Lista")
        refresh_button.clicked.connect(self._refresh_websocket_list)
        buttons_layout.addWidget(refresh_button)

        # Botão de limpar histórico
        clear_button = QPushButton("Limpar Histórico")
        clear_button.clicked.connect(self._clear_websocket_history)
        buttons_layout.addWidget(clear_button)

        # Botão de reenviar mensagem (desabilitado por padrão)
        self.resend_button = QPushButton("Reenviar Mensagem")
        self.resend_button.clicked.connect(self._resend_websocket_message)
        self.resend_button.setEnabled(False)
        buttons_layout.addWidget(self.resend_button)

        buttons_layout.addStretch()
        layout.addLayout(buttons_layout)

    def _update_websocket_list(self):
        """Atualiza periodicamente a lista de conexões WebSocket."""
        try:
            connections = self.websocket_history.get_connections()
            
            # Atualiza o modelo de conexões
            self.connections_model.update_data(connections)
            
            # Atualiza o mapeamento de flow_ids
            self.ws_connections_map = {}
            for idx, conn in enumerate(connections):
                self.ws_connections_map[idx] = conn['flow_id']

        except Exception as e:
            log.error(f"Erro ao atualizar lista de WebSocket: {e}")

    def _on_connection_selected(self, selected, deselected):
        """Chamado quando uma conexão WebSocket é selecionada."""
        indexes = selected.indexes()
        if not indexes:
            return

        row = indexes[0].row()
        flow_id = self.ws_connections_map.get(row)

        if flow_id:
            self.selected_ws_connection = flow_id
            self._refresh_ws_messages()

    def _refresh_ws_messages(self):
        """Atualiza a lista de mensagens da conexão selecionada."""
        # Limpa conteúdo
        self.message_content_text.clear()

        if not self.selected_ws_connection:
            self.messages_model.update_data([])
            return

        messages = self.websocket_history.get_messages(self.selected_ws_connection)
        self.messages_model.update_data(messages)

    def _on_message_selected(self, selected, deselected):
        """Chamado quando uma mensagem WebSocket é selecionada."""
        indexes = selected.indexes()
        if not indexes:
            return

        if not self.selected_ws_connection:
            return

        row = indexes[0].row()
        messages = self.websocket_history.get_messages(self.selected_ws_connection)

        if row < len(messages):
            msg = messages[row]

            # Mostra o conteúdo
            self.message_content_text.clear()

            if msg['is_binary']:
                # Mostra representação hexadecimal para mensagens binárias
                content = f"Mensagem Binária ({msg['size']} bytes):\n\n{msg['content']}"
                self.message_content_text.setPlainText(content)
            else:
                self.message_content_text.setPlainText(msg['content'])

    def _refresh_websocket_list(self):
        """Força atualização da lista de WebSocket."""
        self._update_websocket_list()

        # Atualiza mensagens se houver conexão selecionada
        if self.selected_ws_connection:
            self._refresh_ws_messages()

        #QMessageBox.information(self, "Atualizado", "Lista de WebSocket atualizada!")

    def _clear_websocket_history(self):
        """Limpa o histórico de WebSocket."""
        reply = QMessageBox.question(
            self,
            "Confirmar",
            "Deseja limpar todo o histórico de WebSocket?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            self.websocket_history.clear_history()
            self.ws_connections_map = {}
            self.selected_ws_connection = None

            # Limpa as tabelas
            self.connections_model.update_data([])
            self.messages_model.update_data([])

            # Limpa conteúdo
            self.message_content_text.clear()

            #QMessageBox.information(self, "Limpo", "Histórico de WebSocket limpo!")

    def _resend_websocket_message(self):
        """Reenvia uma mensagem WebSocket (funcionalidade futura)."""
        QMessageBox.information(
            self,
            "Em Desenvolvimento",
            "A funcionalidade de reenvio de mensagens WebSocket\nserá implementada em uma versão futura."
        )
