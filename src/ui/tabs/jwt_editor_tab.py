from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTextEdit,
    QPushButton, QGroupBox, QLabel, QLineEdit
)
from PySide6.QtCore import Signal
from src.core.jwt_editor import JWTEditor
import json
import re

class JWTEditorTab(QWidget):
    send_to_repeater_requested = Signal(dict) # Sinal para enviar a requisição atualizada

    def __init__(self):
        super().__init__()
        self.jwt_editor: JWTEditor = None
        self.original_request_entry: dict = {} # Mantém a entrada original do histórico
        self._setup_ui()

    def _setup_ui(self):
        main_layout = QVBoxLayout(self)

        # 1. Painel do Token Decodificado
        decoded_group = QGroupBox("Decoded JWT")
        decoded_layout = QVBoxLayout()
        self.decoded_header_text = QTextEdit()
        self.decoded_header_text.setReadOnly(True)
        self.decoded_payload_text = QTextEdit()
        self.decoded_payload_text.setReadOnly(True)
        decoded_layout.addWidget(QLabel("Header:"))
        decoded_layout.addWidget(self.decoded_header_text)
        decoded_layout.addWidget(QLabel("Payload:"))
        decoded_layout.addWidget(self.decoded_payload_text)
        decoded_group.setLayout(decoded_layout)

        # 2. Painel de Edição e Ataques
        editor_group = QGroupBox("Editor / Attacks")
        editor_layout = QVBoxLayout()
        self.editable_header_text = QTextEdit()
        self.editable_payload_text = QTextEdit()
        editor_layout.addWidget(QLabel("Editable Header:"))
        editor_layout.addWidget(self.editable_header_text)
        editor_layout.addWidget(QLabel("Editable Payload:"))
        editor_layout.addWidget(self.editable_payload_text)

        # Botões de Ataque
        attacks_layout = QHBoxLayout()
        self.alg_none_button = QPushButton("alg:none Attack")
        self.alg_none_button.clicked.connect(self._apply_alg_none)
        attacks_layout.addWidget(self.alg_none_button)
        editor_layout.addLayout(attacks_layout)
        editor_group.setLayout(editor_layout)

        # 3. Painel de Assinatura
        signing_group = QGroupBox("Signing Options")
        signing_layout = QHBoxLayout()
        self.secret_key_input = QLineEdit()
        self.secret_key_input.setPlaceholderText("Enter HMAC secret key...")
        self.sign_button = QPushButton("Sign")
        self.sign_button.clicked.connect(self._sign_token)
        signing_layout.addWidget(QLabel("Secret:"))
        signing_layout.addWidget(self.secret_key_input)
        signing_layout.addWidget(self.sign_button)
        signing_group.setLayout(signing_layout)

        # 4. Token Resultante e Ações
        result_group = QGroupBox("Resulting Token")
        result_layout = QVBoxLayout()
        self.final_token_text = QTextEdit()
        self.final_token_text.setReadOnly(True)
        self.send_repeater_button = QPushButton("Send to Repeater")
        self.send_repeater_button.clicked.connect(self._send_to_repeater)
        result_layout.addWidget(self.final_token_text)
        result_layout.addWidget(self.send_repeater_button)
        result_group.setLayout(result_layout)

        main_layout.addWidget(decoded_group, 2)
        main_layout.addWidget(editor_group, 3)
        main_layout.addWidget(signing_group, 1)
        main_layout.addWidget(result_group, 2)

    def set_request_data(self, token: str, entry: dict):
        """Recebe o token e a entrada do histórico para popular a UI."""
        self.original_request_entry = entry
        self.jwt_editor = JWTEditor(token)

        success, message = self.jwt_editor.decode()
        if success:
            header_str = self.jwt_editor.get_header_str()
            payload_str = self.jwt_editor.get_payload_str()

            self.decoded_header_text.setText(header_str)
            self.decoded_payload_text.setText(payload_str)
            self.editable_header_text.setText(header_str)
            self.editable_payload_text.setText(payload_str)
            self.final_token_text.setText(self.jwt_editor.original_token)
        else:
            # Limpa a UI se o token for inválido
            self._clear_ui(f"Error: {message}")

    def _clear_ui(self, message=""):
        self.decoded_header_text.setText(message)
        self.decoded_payload_text.setText("")
        self.editable_header_text.setText("")
        self.editable_payload_text.setText("")
        self.final_token_text.setText("")
        self.original_request_entry = {}

    def _apply_alg_none(self):
        if not self.jwt_editor: return

        try:
            header_json = json.loads(self.editable_header_text.toPlainText())
            self.jwt_editor.update_header(header_json)
            self.jwt_editor.update_payload(json.loads(self.editable_payload_text.toPlainText()))

            new_token = self.jwt_editor.apply_alg_none_attack()
            self.final_token_text.setText(new_token)

            # Atualiza o header editável para refletir a mudança no 'alg'
            self.editable_header_text.setText(self.jwt_editor.get_header_str())

        except json.JSONDecodeError as e:
            self.final_token_text.setText(f"JSON Error: {e}")

    def _sign_token(self):
        if not self.jwt_editor: return

        try:
            self.jwt_editor.update_header(json.loads(self.editable_header_text.toPlainText()))
            self.jwt_editor.update_payload(json.loads(self.editable_payload_text.toPlainText()))

            secret = self.secret_key_input.text()
            new_token = self.jwt_editor.sign(secret)
            self.final_token_text.setText(new_token)
        except json.JSONDecodeError as e:
            self.final_token_text.setText(f"JSON Error: {e}")

    def _send_to_repeater(self):
        """Substitui o JWT antigo pelo novo e envia para o Repeater."""
        if not self.original_request_entry or not self.final_token_text.toPlainText():
            return

        new_token = self.final_token_text.toPlainText()
        old_token = self.jwt_editor.original_token

        # Cria uma cópia da entrada para modificação
        updated_entry = self.original_request_entry.copy()

        # 1. Substitui no header
        updated_headers = {}
        for k, v in updated_entry['request_headers'].items():
            updated_headers[k] = v.replace(old_token, new_token)
        updated_entry['request_headers'] = updated_headers

        # 2. Substitui no corpo
        if isinstance(updated_entry['request_body'], str):
            updated_entry['request_body'] = updated_entry['request_body'].replace(old_token, new_token)

        self.send_to_repeater_requested.emit(updated_entry)
