from PySide6.QtCore import Qt, Signal, QAbstractItemModel, QModelIndex
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QPushButton, QLabel,
                               QGroupBox, QHBoxLayout, QTreeView, QSplitter, 
                               QMessageBox, QHeaderView, QTableView, QAbstractItemView)
from PySide6.QtGui import QStandardItemModel, QStandardItem

from src.core.cookie_manager import CookieManager


class CookieTreeModel(QAbstractItemModel):
    """Model para exibir cookies capturados com hierarquia de domínio."""
    
    def __init__(self, cookie_manager: CookieManager):
        super().__init__()
        self.cookie_manager = cookie_manager
        self.root_items = []
        self.refresh()
    
    def refresh(self):
        """Atualiza o modelo com os dados mais recentes do CookieManager."""
        self.beginResetModel()
        self.root_items = []
        
        all_cookies = self.cookie_manager.get_all_cookies()
        for domain, cookies in sorted(all_cookies.items()):
            domain_item = {'type': 'domain', 'domain': domain, 'cookies': []}
            for name, value in sorted(cookies.items()):
                cookie_item = {'type': 'cookie', 'name': name, 'value': value}
                domain_item['cookies'].append(cookie_item)
            self.root_items.append(domain_item)
        
        self.endResetModel()
    
    def index(self, row: int, column: int, parent: QModelIndex = QModelIndex()):
        """Cria um índice para o item especificado."""
        if not self.hasIndex(row, column, parent):
            return QModelIndex()
        
        if not parent.isValid():
            # Item raiz (domínio)
            if row < len(self.root_items):
                return self.createIndex(row, column, self.root_items[row])
        else:
            # Item filho (cookie)
            parent_item = parent.internalPointer()
            if parent_item and parent_item['type'] == 'domain':
                cookies = parent_item['cookies']
                if row < len(cookies):
                    return self.createIndex(row, column, cookies[row])
        
        return QModelIndex()
    
    def parent(self, index: QModelIndex):
        """Retorna o índice pai do item especificado."""
        if not index.isValid():
            return QModelIndex()
        
        item = index.internalPointer()
        if item and item['type'] == 'cookie':
            # Encontra o domínio pai
            for i, domain_item in enumerate(self.root_items):
                if item in domain_item['cookies']:
                    return self.createIndex(i, 0, domain_item)
        
        return QModelIndex()
    
    def rowCount(self, parent: QModelIndex = QModelIndex()):
        """Retorna o número de linhas sob o item pai."""
        if parent.column() > 0:
            return 0
        
        if not parent.isValid():
            # Contagem de domínios raiz
            return len(self.root_items)
        
        parent_item = parent.internalPointer()
        if parent_item and parent_item['type'] == 'domain':
            # Contagem de cookies sob o domínio
            return len(parent_item['cookies'])
        
        return 0
    
    def columnCount(self, parent: QModelIndex = QModelIndex()):
        """Retorna o número de colunas."""
        return 2  # Nome e Valor
    
    def data(self, index: QModelIndex, role: int = Qt.ItemDataRole.DisplayRole):
        """Retorna os dados para o item especificado."""
        if not index.isValid():
            return None
        
        item = index.internalPointer()
        if not item:
            return None
        
        if role == Qt.ItemDataRole.DisplayRole:
            if item['type'] == 'domain':
                if index.column() == 0:
                    return item['domain']
                return ""
            elif item['type'] == 'cookie':
                if index.column() == 0:
                    return item['name']
                elif index.column() == 1:
                    return item['value']
        
        return None
    
    def headerData(self, section: int, orientation: Qt.Orientation, role: int = Qt.ItemDataRole.DisplayRole):
        """Retorna os dados do cabeçalho."""
        if orientation == Qt.Orientation.Horizontal and role == Qt.ItemDataRole.DisplayRole:
            if section == 0:
                return "Domínio / Nome"
            elif section == 1:
                return "Valor"
        return None
    
    def flags(self, index: QModelIndex):
        """Retorna as flags do item."""
        if not index.isValid():
            return Qt.ItemFlag.NoItemFlags
        return Qt.ItemFlag.ItemIsEnabled | Qt.ItemFlag.ItemIsSelectable


class JarCookieTableModel(QStandardItemModel):
    """Model para exibir cookies do jar em uma tabela simples."""
    
    def __init__(self, cookie_manager: CookieManager):
        super().__init__()
        self.cookie_manager = cookie_manager
        self.setHorizontalHeaderLabels(["Nome", "Valor"])
        self.refresh()
    
    def refresh(self):
        """Atualiza o modelo com os dados mais recentes do jar."""
        self.removeRows(0, self.rowCount())
        
        jar_cookies = self.cookie_manager.get_jar_cookies_list()
        for cookie in jar_cookies:
            name_item = QStandardItem(cookie['name'])
            value_item = QStandardItem(cookie['value'])
            self.appendRow([name_item, value_item])


class CookieJarTab(QWidget):
    """Aba de UI para gerenciar o Cookie Jar."""
    
    def __init__(self, cookie_manager: CookieManager):
        super().__init__()
        self.cookie_manager = cookie_manager
        
        # Define o callback da UI
        self.cookie_manager.set_ui_callback(self._refresh_cookie_views)
        
        self._setup_ui()
    
    def _setup_ui(self):
        """Configura a interface da aba."""
        layout = QHBoxLayout(self)
        
        # Splitter horizontal para dividir em 3 seções
        splitter = QSplitter(Qt.Orientation.Horizontal)
        layout.addWidget(splitter)
        
        # Seção 1: Todos os cookies capturados
        self._setup_all_cookies_section(splitter)
        
        # Seção 2: Botões de ação
        self._setup_action_buttons(splitter)
        
        # Seção 3: Cookie Jar
        self._setup_jar_section(splitter)
        
        # Define os tamanhos relativos das seções
        splitter.setSizes([400, 50, 400])
    
    def _setup_all_cookies_section(self, parent):
        """Configura a seção de todos os cookies capturados."""
        all_cookies_group = QGroupBox("Todos os Cookies Capturados")
        all_cookies_layout = QVBoxLayout()
        
        self.all_cookies_tree = QTreeView()
        self.all_cookies_tree.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.all_cookies_tree.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        
        self.all_cookies_model = CookieTreeModel(self.cookie_manager)
        self.all_cookies_tree.setModel(self.all_cookies_model)
        
        # Configura as colunas
        header = self.all_cookies_tree.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.all_cookies_tree.setColumnWidth(0, 200)
        
        # Expande todos os domínios por padrão
        self.all_cookies_tree.expandAll()
        
        all_cookies_layout.addWidget(self.all_cookies_tree)
        all_cookies_group.setLayout(all_cookies_layout)
        parent.addWidget(all_cookies_group)
    
    def _setup_action_buttons(self, parent):
        """Configura os botões de ação no meio."""
        actions_widget = QWidget()
        actions_layout = QVBoxLayout()
        actions_layout.addStretch()
        
        add_button = QPushButton(">>")
        add_button.setToolTip("Adicionar selecionado ao Cookie Jar")
        add_button.setMaximumWidth(60)
        add_button.clicked.connect(self._add_cookie_to_jar)
        actions_layout.addWidget(add_button)
        
        actions_layout.addSpacing(20)
        
        remove_button = QPushButton("<<")
        remove_button.setToolTip("Remover selecionado do Cookie Jar")
        remove_button.setMaximumWidth(60)
        remove_button.clicked.connect(self._remove_cookie_from_jar)
        actions_layout.addWidget(remove_button)
        
        actions_layout.addStretch()
        actions_widget.setLayout(actions_layout)
        parent.addWidget(actions_widget)
    
    def _setup_jar_section(self, parent):
        """Configura a seção do Cookie Jar."""
        jar_group = QGroupBox("Cookie Jar (Sessão Forçada)")
        jar_layout = QVBoxLayout()
        
        self.jar_table = QTableView()
        self.jar_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.jar_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        
        self.jar_model = JarCookieTableModel(self.cookie_manager)
        self.jar_table.setModel(self.jar_model)
        
        # Configura as colunas
        header = self.jar_table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.jar_table.setColumnWidth(0, 150)
        
        jar_layout.addWidget(self.jar_table)
        
        # Botão para limpar o jar
        clear_button = QPushButton("Limpar Cookie Jar")
        clear_button.setToolTip("Remove todos os cookies do Jar")
        clear_button.clicked.connect(self._clear_cookie_jar)
        jar_layout.addWidget(clear_button)
        
        jar_group.setLayout(jar_layout)
        parent.addWidget(jar_group)
    
    def _refresh_cookie_views(self):
        """Atualiza as visualizações de cookies."""
        self.all_cookies_model.refresh()
        self.jar_model.refresh()
        # Expande todos os domínios após a atualização
        self.all_cookies_tree.expandAll()
    
    def _add_cookie_to_jar(self):
        """Adiciona o cookie selecionado ao Cookie Jar."""
        selection = self.all_cookies_tree.selectionModel().selectedIndexes()
        if not selection:
            return
        
        index = selection[0]
        item = index.internalPointer()
        
        # Garante que estamos pegando um cookie, não um domínio
        if item and item['type'] == 'cookie':
            name = item['name']
            value = item['value']
            self.cookie_manager.add_to_jar(name, value)
            self._refresh_cookie_views()
    
    def _remove_cookie_from_jar(self):
        """Remove o cookie selecionado do Cookie Jar."""
        selection = self.jar_table.selectionModel().selectedIndexes()
        if not selection:
            return
        
        row = selection[0].row()
        name_item = self.jar_model.item(row, 0)
        if name_item:
            name = name_item.text()
            self.cookie_manager.remove_from_jar(name)
            self._refresh_cookie_views()
    
    def _clear_cookie_jar(self):
        """Limpa todos os cookies do Cookie Jar após confirmação."""
        reply = QMessageBox.question(
            self, 
            "Confirmar", 
            "Deseja realmente limpar todo o Cookie Jar?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            self.cookie_manager.clear_jar()
            self._refresh_cookie_views()
