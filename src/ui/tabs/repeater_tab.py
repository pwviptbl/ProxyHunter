import re
from PySide6.QtCore import Qt, Signal, QThread
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QPushButton, QLabel, QLineEdit,
                               QGroupBox, QHBoxLayout, QTextEdit, QSplitter, QMessageBox, QCheckBox)

from src.core.advanced_sender import send_from_raw
from src.core.config import InterceptConfig
from src.core.cookie_manager import CookieManager

class RepeaterWorker(QThread):
    """Worker para enviar requisições em uma thread separada."""
    response_received = Signal(str)

    def __init__(self, raw_request: str, port: int, use_tor: bool = False, tor_port: int = 9050):
        super().__init__()
        self.raw_request = raw_request
        self.port = port
        self.use_tor = use_tor
        self.tor_port = tor_port

    def run(self):
        """Executa o envio da requisição."""
        response = send_from_raw(self.raw_request, None, None, self.port, self.use_tor, self.tor_port)

        if response is not None:
            status_line = f"HTTP/1.1 {response.status_code} {response.reason}\n"
            headers = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
            body = response.text
            full_response = f"{status_line}{headers}\n\n{body}"
            self.response_received.emit(full_response)
        else:
            self.response_received.emit("Erro: A requisição falhou. Verifique os logs.")

class RepeaterTab(QWidget):
    """Aba de UI para reenviar e modificar requisições manualmente."""
    send_request = Signal(dict)

    def __init__(self, cookie_manager: CookieManager = None):
        super().__init__()
        self.raw_request_data = None
        self.config = InterceptConfig()
        self.cookie_manager = cookie_manager if cookie_manager else CookieManager()
        self.worker = None
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        self._setup_config_panel(layout)
        splitter = QSplitter(Qt.Orientation.Vertical)
        layout.addWidget(splitter)
        self._setup_request_panel(splitter)
        self._setup_response_panel(splitter)
        splitter.setSizes([self.height() // 2, self.height() // 2])

    def _setup_config_panel(self, layout):
        config_group = QGroupBox("Configuração do Reenvio")
        config_layout = QHBoxLayout()

        self.inject_cookies_checkbox = QCheckBox("Inject Cookies from Jar")
        self.inject_cookies_checkbox.setChecked(True)
        config_layout.addWidget(self.inject_cookies_checkbox)

        config_layout.addStretch()

        self.send_button = QPushButton("Reenviar Requisição")
        self.send_button.clicked.connect(self._send_request)
        config_layout.addWidget(self.send_button)

        config_group.setLayout(config_layout)
        layout.addWidget(config_group)

    def _setup_request_panel(self, parent):
        request_group = QGroupBox("Request")
        request_layout = QVBoxLayout()
        self.request_text = QTextEdit()
        self.request_text.setFontFamily("Courier")
        request_layout.addWidget(self.request_text)
        request_group.setLayout(request_layout)
        parent.addWidget(request_group)

    def _setup_response_panel(self, parent):
        response_group = QGroupBox("Response")
        response_layout = QVBoxLayout()
        self.response_text = QTextEdit()
        self.response_text.setFontFamily("Courier")
        self.response_text.setReadOnly(True)
        response_layout.addWidget(self.response_text)
        response_group.setLayout(response_layout)
        parent.addWidget(response_group)

    def set_request_data(self, entry: dict):
        self.raw_request_data = entry
        headers = "\n".join(f"{k}: {v}" for k, v in entry['request_headers'].items())
        request_info = (
            f"{entry['method']} {entry['path']} HTTP/1.1\n"
            f"Host: {entry['host']}\n"
            f"{headers}"
        )
        if entry['request_body']:
            request_info += f"\n\n{entry['request_body']}"
        self.request_text.setPlainText(request_info)
        self.response_text.clear()

    def _send_request(self):
        raw_request = self.request_text.toPlainText()
        if not raw_request:
            QMessageBox.warning(self, "Aviso", "Não há nenhuma requisição para reenviar.")
            return

        if self.inject_cookies_checkbox.isChecked():
            # Injeta os cookies do Jar na requisição
            raw_request = self._inject_jar_cookies(raw_request)

        port = self.config.get_port()
        use_tor = self.config.get_tor_enabled()
        tor_port = self.config.get_tor_port()

        # Desabilita o botão para evitar cliques múltiplos
        self.send_button.setEnabled(False)
        self.response_text.setPlainText("Enviando requisição...")

        # Cria e inicia o worker
        self.worker = RepeaterWorker(raw_request, port, use_tor, tor_port)
        self.worker.response_received.connect(self._on_response_received)
        self.worker.finished.connect(self._on_worker_finished)
        self.worker.start()

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

    def _on_response_received(self, response_text: str):
        self.response_text.setPlainText(response_text)

    def _on_worker_finished(self):
        self.send_button.setEnabled(True)
        self.worker = None
