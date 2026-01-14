from PySide6.QtCore import Signal
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QPushButton, QLabel, QTextEdit,
                               QGroupBox, QHBoxLayout, QGridLayout)

class InterceptTab(QWidget):
    """Aba de UI para interceptação manual de requisições."""

    forward_requested = Signal(dict)
    drop_requested = Signal()
    toggle_intercept_requested = Signal()

    def __init__(self):
        super().__init__()

        layout = QVBoxLayout(self)

        self._setup_controls(layout)
        self._setup_request_display(layout)
        self._setup_action_buttons(layout)

        self.reset_ui()

    def _setup_controls(self, layout):
        control_group = QGroupBox("Controle de Interceptação")
        control_layout = QHBoxLayout()

        self.intercept_status_label = QLabel("Intercept: OFF")
        self.intercept_status_label.setStyleSheet("color: red; font-weight: bold;")

        self.intercept_toggle_button = QPushButton("Intercept is OFF")
        self.intercept_toggle_button.setCheckable(True)
        self.intercept_toggle_button.clicked.connect(self.toggle_intercept_requested.emit)

        control_layout.addWidget(self.intercept_status_label)
        control_layout.addWidget(self.intercept_toggle_button)
        control_layout.addStretch()

        control_group.setLayout(control_layout)
        layout.addWidget(control_group)

    def _setup_request_display(self, layout):
        request_group = QGroupBox("Requisição Interceptada")
        request_layout = QVBoxLayout()

        info_layout = QGridLayout()
        info_layout.addWidget(QLabel("<b>Método:</b>"), 0, 0)
        self.method_label = QLabel("-")
        info_layout.addWidget(self.method_label, 0, 1)

        info_layout.addWidget(QLabel("<b>URL:</b>"), 1, 0)
        self.url_label = QLabel("-")
        self.url_label.setWordWrap(True)
        info_layout.addWidget(self.url_label, 1, 1)

        request_layout.addLayout(info_layout)

        headers_group = QGroupBox("Headers")
        headers_layout = QVBoxLayout()
        self.headers_text = QTextEdit()
        headers_layout.addWidget(self.headers_text)
        headers_group.setLayout(headers_layout)
        request_layout.addWidget(headers_group)

        body_group = QGroupBox("Body")
        body_layout = QVBoxLayout()
        self.body_text = QTextEdit()
        body_layout.addWidget(self.body_text)
        body_group.setLayout(body_layout)
        request_layout.addWidget(body_group)

        request_group.setLayout(request_layout)
        layout.addWidget(request_group)

    def _setup_action_buttons(self, layout):
        action_layout = QHBoxLayout()
        self.forward_button = QPushButton("Forward")
        self.forward_button.clicked.connect(self._on_forward)

        self.drop_button = QPushButton("Drop")
        self.drop_button.clicked.connect(self.drop_requested.emit)

        action_layout.addStretch()
        action_layout.addWidget(self.forward_button)
        action_layout.addWidget(self.drop_button)
        action_layout.addStretch()

        layout.addLayout(action_layout)

    def _on_forward(self):
        """Coleta os dados modificados e emite o sinal."""
        modified_data = self.get_modified_request_data()
        self.forward_requested.emit(modified_data)

    def set_intercept_state(self, is_enabled: bool):
        """Atualiza a UI para refletir o estado de interceptação."""
        self.intercept_toggle_button.setChecked(is_enabled)
        if is_enabled:
            self.intercept_status_label.setText("Intercept: ON")
            self.intercept_status_label.setStyleSheet("color: green; font-weight: bold;")
            self.intercept_toggle_button.setText("Intercept is ON")
        else:
            self.intercept_status_label.setText("Intercept: OFF")
            self.intercept_status_label.setStyleSheet("color: red; font-weight: bold;")
            self.intercept_toggle_button.setText("Intercept is OFF")
            self.reset_ui()

    def display_request(self, request_data: dict):
        """Preenche a UI com os dados de uma requisição interceptada."""
        self.method_label.setText(request_data.get('method', '-'))
        self.url_label.setText(request_data.get('url', '-'))

        headers = "\n".join(f"{k}: {v}" for k, v in request_data.get('headers', {}).items())
        self.headers_text.setPlainText(headers)
        self.body_text.setPlainText(request_data.get('body', ''))

        self.forward_button.setEnabled(True)
        self.drop_button.setEnabled(True)

    def get_modified_request_data(self) -> dict:
        """Retorna os dados da requisição, incluindo modificações do usuário."""
        headers_text = self.headers_text.toPlainText().strip()
        body_text = self.body_text.toPlainText() # Não usa strip para não remover espaços intencionais

        modified_headers = {}
        for line in headers_text.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                modified_headers[key.strip()] = value.strip()

        return {
            'modified_headers': modified_headers,
            'modified_body': body_text
        }

    def reset_ui(self):
        """Limpa os campos e desabilita os botões de ação."""
        self.method_label.setText("-")
        self.url_label.setText("-")
        self.headers_text.clear()
        self.body_text.clear()
        self.forward_button.setEnabled(False)
        self.drop_button.setEnabled(False)
