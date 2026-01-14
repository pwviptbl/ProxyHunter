from PySide6.QtCore import QAbstractTableModel, Qt
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
                               QLineEdit, QGroupBox, QMessageBox, QTableView,
                               QAbstractItemView, QGridLayout, QHeaderView, QComboBox)

from src.core.config import InterceptConfig

class RulesTab(QWidget):
    """Aba de UI para gerenciar as Regras de Interceptação."""

    def __init__(self, config: InterceptConfig):
        super().__init__()
        self.config = config

        rules_layout = QVBoxLayout(self)

        # --- Formulário de Adicionar Regra ---
        self._setup_form(rules_layout)

        # --- Lista de Regras ---
        self._setup_table(rules_layout)

        # --- Botões de Ação ---
        self._setup_action_buttons(rules_layout)

        self._refresh_rules_list()

    def _setup_form(self, layout):
        add_rule_group = QGroupBox("Adicionar Regra de Interceptação")
        add_rule_layout = QGridLayout()
        self.host_entry = QLineEdit("exemplo.com")
        self.path_entry = QLineEdit("/contato")
        self.param_name_entry = QLineEdit("Titulo")
        self.param_value_entry = QLineEdit("teste1")
        self.type_combo = QComboBox()
        self.type_combo.addItems(["request", "response"])
        add_button = QPushButton("Adicionar Regra")
        add_button.clicked.connect(self.add_rule)

        add_rule_layout.addWidget(QLabel("Tipo:"), 0, 0)
        add_rule_layout.addWidget(self.type_combo, 0, 1)
        add_rule_layout.addWidget(QLabel("Host/Domínio:"), 0, 2)
        add_rule_layout.addWidget(self.host_entry, 0, 3)
        add_rule_layout.addWidget(QLabel("Caminho:"), 1, 0)
        add_rule_layout.addWidget(self.path_entry, 1, 1)
        add_rule_layout.addWidget(QLabel("Nome do Parâmetro:"), 1, 2)
        add_rule_layout.addWidget(self.param_name_entry, 1, 3)
        add_rule_layout.addWidget(QLabel("Novo Valor:"), 2, 0)
        add_rule_layout.addWidget(self.param_value_entry, 2, 1)
        add_rule_layout.addWidget(add_button, 2, 2, 1, 2)

        add_rule_group.setLayout(add_rule_layout)
        layout.addWidget(add_rule_group)

    def _setup_table(self, layout):
        rules_list_group = QGroupBox("Regras Configuradas")
        rules_list_layout = QVBoxLayout()
        self.rules_table = QTableView()
        self.rules_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.rules_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.rules_model = RulesTableModel([])
        self.rules_table.setModel(self.rules_model)
        self.rules_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        rules_list_layout.addWidget(self.rules_table)
        rules_list_group.setLayout(rules_list_layout)
        layout.addWidget(rules_list_group)

    def _setup_action_buttons(self, layout):
        action_buttons_layout = QHBoxLayout()
        remove_button = QPushButton("Remover Regra Selecionada")
        remove_button.clicked.connect(self.remove_rule)
        toggle_button = QPushButton("Ativar/Desativar Regra")
        toggle_button.clicked.connect(self.toggle_rule)
        duplicate_button = QPushButton("Duplicar Regra")
        duplicate_button.clicked.connect(self.duplicate_rule)

        action_buttons_layout.addWidget(remove_button)
        action_buttons_layout.addWidget(toggle_button)
        action_buttons_layout.addWidget(duplicate_button)
        action_buttons_layout.addStretch()
        layout.addLayout(action_buttons_layout)

    def add_rule(self):
        success, message = self.config.add_rule(
            self.host_entry.text(), self.path_entry.text(),
            self.param_name_entry.text(), self.param_value_entry.text(),
            self.type_combo.currentText()
        )
        if success:
            QMessageBox.information(self, "Sucesso", message)
            self._refresh_rules_list()
        else:
            QMessageBox.warning(self, "Erro de Validação", message)

    def remove_rule(self):
        selected_indexes = self.rules_table.selectionModel().selectedRows()
        if not selected_indexes:
            QMessageBox.warning(self, "Aviso", "Selecione uma regra para remover.")
            return
        if self.config.remove_rule(selected_indexes[0].row()):
            #QMessageBox.information(self, "Sucesso", "Regra removida.")
            self._refresh_rules_list()
        else:
            QMessageBox.critical(self, "Erro", "Não foi possível remover a regra.")

    def toggle_rule(self):
        selected_indexes = self.rules_table.selectionModel().selectedRows()
        if not selected_indexes:
            QMessageBox.warning(self, "Aviso", "Selecione uma regra.")
            return
        if self.config.toggle_rule(selected_indexes[0].row()):
            self._refresh_rules_list()

    def duplicate_rule(self):
        selected_indexes = self.rules_table.selectionModel().selectedRows()
        if not selected_indexes:
            QMessageBox.warning(self, "Aviso", "Selecione uma regra para duplicar.")
            return
        rule = self.config.get_rules()[selected_indexes[0].row()]
        success, _ = self.config.add_rule(
            rule['host'], rule['path'], rule['param_name'], rule['param_value'], rule.get('type', 'request')
        )
        if success:
            #QMessageBox.information(self, "Sucesso", "Regra duplicada.")
            self._refresh_rules_list()
        else:
            QMessageBox.critical(self, "Erro", "Não foi possível duplicar a regra.")

    def _refresh_rules_list(self):
        self.rules_model.update_data(self.config.get_rules())

class RulesTableModel(QAbstractTableModel):
    def __init__(self, data=None):
        super().__init__()
        self._data = data or []
        self._headers = ['Tipo', 'Host', 'Caminho', 'Parâmetro', 'Valor', 'Status']

    def data(self, index, role):
        if role == Qt.ItemDataRole.DisplayRole:
            rule = self._data[index.row()]
            col = index.column()
            if col == 0: return rule.get('type', 'request')
            if col == 1: return rule.get('host', '')
            if col == 2: return rule.get('path', '')
            if col == 3: return rule.get('param_name', '')
            if col == 4: return rule.get('param_value', '')
            if col == 5: return "Ativo" if rule.get('enabled', True) else "Inativo"
        return None

    def rowCount(self, index):
        return len(self._data)

    def columnCount(self, index):
        return len(self._headers)

    def headerData(self, section, orientation, role):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self._headers[section]
        return None

    def update_data(self, new_data):
        self.beginResetModel()
        self._data = new_data
        self.endResetModel()
