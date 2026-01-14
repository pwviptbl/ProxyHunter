import difflib
from PySide6.QtCore import Signal, Qt
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel,
                               QGroupBox, QTabWidget, QTextEdit, QSplitter, QMessageBox)
from PySide6.QtGui import QTextCursor, QTextCharFormat, QColor

from src.core.logger_config import log


class ComparatorTab(QWidget):
    """Aba de UI para comparar duas requisições lado a lado."""

    def __init__(self):
        super().__init__()
        
        # Estado do comparador
        self.comparator_request_1 = None
        self.comparator_request_2 = None
        
        layout = QVBoxLayout(self)
        
        self._setup_instructions(layout)
        self._setup_status(layout)
        self._setup_buttons(layout)
        self._setup_comparison_view(layout)
    
    def _setup_instructions(self, layout):
        """Cria o frame de instruções."""
        info_group = QGroupBox("Instruções")
        info_layout = QVBoxLayout()
        
        info_label = QLabel(
            "Use o menu de contexto (clique direito) no Histórico de Requisições "
            "para selecionar duas requisições para comparar."
        )
        info_label.setWordWrap(True)
        info_layout.addWidget(info_label)
        
        info_group.setLayout(info_layout)
        layout.addWidget(info_group)
    
    def _setup_status(self, layout):
        """Cria o frame de status mostrando as requisições selecionadas."""
        status_layout = QHBoxLayout()
        
        # Status da Requisição 1
        req1_group = QGroupBox("Requisição 1")
        req1_layout = QVBoxLayout()
        self.req1_label = QLabel("Nenhuma requisição selecionada")
        self.req1_label.setStyleSheet("color: gray;")
        self.req1_label.setWordWrap(True)
        req1_layout.addWidget(self.req1_label)
        req1_group.setLayout(req1_layout)
        status_layout.addWidget(req1_group)
        
        # Status da Requisição 2
        req2_group = QGroupBox("Requisição 2")
        req2_layout = QVBoxLayout()
        self.req2_label = QLabel("Nenhuma requisição selecionada")
        self.req2_label.setStyleSheet("color: gray;")
        self.req2_label.setWordWrap(True)
        req2_layout.addWidget(self.req2_label)
        req2_group.setLayout(req2_layout)
        status_layout.addWidget(req2_group)
        
        layout.addLayout(status_layout)
    
    def _setup_buttons(self, layout):
        """Cria os botões de ação."""
        buttons_layout = QHBoxLayout()
        
        compare_button = QPushButton("Comparar")
        compare_button.clicked.connect(self.compare_requests)
        buttons_layout.addWidget(compare_button)
        
        clear_button = QPushButton("Limpar")
        clear_button.clicked.connect(self.clear_comparator)
        buttons_layout.addWidget(clear_button)
        
        buttons_layout.addStretch()
        layout.addLayout(buttons_layout)
    
    def _setup_comparison_view(self, layout):
        """Cria a visualização de comparação com abas."""
        self.comparison_tabs = QTabWidget()
        
        # Aba de comparação de Request
        self.request_comparison_widget = self._create_comparison_widget()
        self.request1_text = self.request_comparison_widget['text1']
        self.request2_text = self.request_comparison_widget['text2']
        self.comparison_tabs.addTab(
            self.request_comparison_widget['widget'],
            "Request Comparison"
        )
        
        # Aba de comparação de Response
        self.response_comparison_widget = self._create_comparison_widget()
        self.response1_text = self.response_comparison_widget['text1']
        self.response2_text = self.response_comparison_widget['text2']
        self.comparison_tabs.addTab(
            self.response_comparison_widget['widget'],
            "Response Comparison"
        )
        
        layout.addWidget(self.comparison_tabs)
    
    def _create_comparison_widget(self):
        """Cria um widget de comparação lado a lado."""
        widget = QWidget()
        layout = QHBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        
        splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Lado esquerdo
        left_group = QGroupBox("Item 1")
        left_layout = QVBoxLayout()
        text1 = QTextEdit()
        text1.setReadOnly(True)
        left_layout.addWidget(text1)
        left_group.setLayout(left_layout)
        splitter.addWidget(left_group)
        
        # Lado direito
        right_group = QGroupBox("Item 2")
        right_layout = QVBoxLayout()
        text2 = QTextEdit()
        text2.setReadOnly(True)
        right_layout.addWidget(text2)
        right_group.setLayout(right_layout)
        splitter.addWidget(right_group)
        
        splitter.setSizes([500, 500])
        layout.addWidget(splitter)
        
        return {
            'widget': widget,
            'text1': text1,
            'text2': text2
        }
    
    def set_comparator_request_1(self, entry: dict):
        """Define a primeira requisição para comparação."""
        self.comparator_request_1 = entry
        label_text = f"{entry['method']} {entry['host']}{entry['path']} - {entry['timestamp']}"
        self.req1_label.setText(label_text)
        self.req1_label.setStyleSheet("color: black;")
        log.info(f"Requisição 1 selecionada para comparação: {label_text}")
    
    def set_comparator_request_2(self, entry: dict):
        """Define a segunda requisição para comparação."""
        self.comparator_request_2 = entry
        label_text = f"{entry['method']} {entry['host']}{entry['path']} - {entry['timestamp']}"
        self.req2_label.setText(label_text)
        self.req2_label.setStyleSheet("color: black;")
        log.info(f"Requisição 2 selecionada para comparação: {label_text}")
    
    def compare_requests(self):
        """Compara as duas requisições selecionadas."""
        if not self.comparator_request_1 or not self.comparator_request_2:
            QMessageBox.warning(
                self,
                "Aviso",
                "Por favor, selecione duas requisições para comparar!"
            )
            return
        
        # Formata as requisições
        req1_text = self._format_request(self.comparator_request_1)
        req2_text = self._format_request(self.comparator_request_2)
        
        resp1_text = self._format_response(self.comparator_request_1)
        resp2_text = self._format_response(self.comparator_request_2)
        
        # Limpa os campos
        self.request1_text.clear()
        self.request2_text.clear()
        self.response1_text.clear()
        self.response2_text.clear()
        
        # Insere o texto
        self.request1_text.setPlainText(req1_text)
        self.request2_text.setPlainText(req2_text)
        self.response1_text.setPlainText(resp1_text)
        self.response2_text.setPlainText(resp2_text)
        
        # Aplica highlighting de diferenças
        self._highlight_differences(self.request1_text, self.request2_text, req1_text, req2_text)
        self._highlight_differences(self.response1_text, self.response2_text, resp1_text, resp2_text)
        
        log.info("Comparação realizada")
    
    def _format_request(self, entry: dict) -> str:
        """Formata uma requisição para exibição."""
        request_info = f"{entry['method']} {entry['path']} HTTP/1.1\n"
        request_info += f"Host: {entry['host']}\n"
        for key, value in entry['request_headers'].items():
            request_info += f"{key}: {value}\n"
        
        if entry['request_body']:
            request_info += f"\n{entry['request_body']}"
        
        return request_info
    
    def _format_response(self, entry: dict) -> str:
        """Formata uma resposta para exibição."""
        response_info = f"Status: {entry['status']}\n\n"
        for key, value in entry['response_headers'].items():
            response_info += f"{key}: {value}\n"
        
        if entry['response_body']:
            response_info += f"\n{entry['response_body']}"
        
        return response_info
    
    def _highlight_differences(self, text_widget1: QTextEdit, text_widget2: QTextEdit, 
                               text1: str, text2: str):
        """Aplica highlighting de diferenças entre dois textos usando difflib."""
        lines1 = text1.splitlines(keepends=True)
        lines2 = text2.splitlines(keepends=True)
        
        # Usa SequenceMatcher para encontrar diferenças
        matcher = difflib.SequenceMatcher(None, lines1, lines2)
        
        # Formato para highlighting
        diff_format = QTextCharFormat()
        diff_format.setBackground(QColor("#ffcccc"))
        
        # Marca as linhas diferentes
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            if tag in ('replace', 'delete'):
                # Marca linhas diferentes no primeiro widget
                self._highlight_lines(text_widget1, i1, i2, diff_format)
            
            if tag in ('replace', 'insert'):
                # Marca linhas diferentes no segundo widget
                self._highlight_lines(text_widget2, j1, j2, diff_format)
    
    def _highlight_lines(self, text_widget: QTextEdit, start_line: int, end_line: int,
                         char_format: QTextCharFormat):
        """Aplica formato a um intervalo de linhas em um QTextEdit."""
        cursor = text_widget.textCursor()
        
        for line_num in range(start_line, end_line):
            # Move o cursor para o início da linha
            cursor.movePosition(QTextCursor.MoveOperation.Start)
            for _ in range(line_num):
                cursor.movePosition(QTextCursor.MoveOperation.Down)
            
            # Seleciona a linha inteira
            cursor.movePosition(QTextCursor.MoveOperation.StartOfLine)
            cursor.movePosition(QTextCursor.MoveOperation.EndOfLine, QTextCursor.MoveMode.KeepAnchor)
            
            # Aplica o formato
            cursor.mergeCharFormat(char_format)
    
    def clear_comparator(self):
        """Limpa o comparador."""
        self.comparator_request_1 = None
        self.comparator_request_2 = None
        
        self.req1_label.setText("Nenhuma requisição selecionada")
        self.req1_label.setStyleSheet("color: gray;")
        
        self.req2_label.setText("Nenhuma requisição selecionada")
        self.req2_label.setStyleSheet("color: gray;")
        
        self.request1_text.clear()
        self.request2_text.clear()
        self.response1_text.clear()
        self.response2_text.clear()
        
        log.info("Comparador limpo")
