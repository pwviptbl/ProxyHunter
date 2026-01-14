# Import correto da classe Decoder
from src.core.decoder import Decoder
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QTextEdit, QPushButton, QLabel, QGridLayout
)
from PySide6.QtCore import Qt

class DecoderTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        # Layout principal vertical
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(10, 5, 10, 5)

        # Áreas de texto
        text_group = QGroupBox("Decoder")
        text_layout = QHBoxLayout()

        # Input
        input_group = QGroupBox("Input")
        input_layout = QVBoxLayout()
        self.decoder_input_text = QTextEdit()
        self.decoder_input_text.setPlaceholderText("Insira o texto para encode/decode...")
        input_layout.addWidget(self.decoder_input_text)
        input_group.setLayout(input_layout)

        # Output
        output_group = QGroupBox("Output")
        output_layout = QVBoxLayout()
        self.decoder_output_text = QTextEdit()
        self.decoder_output_text.setReadOnly(True)
        output_layout.addWidget(self.decoder_output_text)
        output_group.setLayout(output_layout)

        text_layout.addWidget(input_group)
        text_layout.addWidget(output_group)
        text_group.setLayout(text_layout)
        main_layout.addWidget(text_group, 4)

        # Botões de ação
        buttons_group = QGroupBox("Ações")
        buttons_layout = QGridLayout()

        # Base64
        buttons_layout.addWidget(QPushButton("Encode Base64", clicked=lambda: self._handle_decode_action(Decoder.b64_encode)), 0, 0)
        buttons_layout.addWidget(QPushButton("Decode Base64", clicked=lambda: self._handle_decode_action(Decoder.b64_decode)), 0, 1)

        # URL
        buttons_layout.addWidget(QPushButton("URL Encode", clicked=lambda: self._handle_decode_action(Decoder.url_encode)), 1, 0)
        buttons_layout.addWidget(QPushButton("URL Decode", clicked=lambda: self._handle_decode_action(Decoder.url_decode)), 1, 1)

        # HTML
        buttons_layout.addWidget(QPushButton("HTML Encode", clicked=lambda: self._handle_decode_action(Decoder.html_encode)), 0, 2)
        buttons_layout.addWidget(QPushButton("HTML Decode", clicked=lambda: self._handle_decode_action(Decoder.html_decode)), 0, 3)

        # Hex
        buttons_layout.addWidget(QPushButton("Hex Encode", clicked=lambda: self._handle_decode_action(Decoder.hex_encode)), 1, 2)
        buttons_layout.addWidget(QPushButton("Hex Decode", clicked=lambda: self._handle_decode_action(Decoder.hex_decode)), 1, 3)

        # Separador (Hash)
        hash_label = QLabel("Hashing:")
        buttons_layout.addWidget(hash_label, 2, 0, Qt.AlignLeft)

        buttons_layout.addWidget(QPushButton("MD5", clicked=lambda: self._handle_decode_action(Decoder.hash_md5)), 2, 1)
        buttons_layout.addWidget(QPushButton("SHA-1", clicked=lambda: self._handle_decode_action(Decoder.hash_sha1)), 2, 2)
        buttons_layout.addWidget(QPushButton("SHA-256", clicked=lambda: self._handle_decode_action(Decoder.hash_sha256)), 2, 3)

        buttons_group.setLayout(buttons_layout)
        main_layout.addWidget(buttons_group, 1)

    def _handle_decode_action(self, action_function):
        input_text = self.decoder_input_text.toPlainText().strip()
        if not input_text:
            return
        try:
            result = action_function(input_text)
            self.decoder_output_text.setPlainText(result)
        except Exception as e:
            self.decoder_output_text.setPlainText(f"Erro: {e}")