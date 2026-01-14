from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
                               QComboBox, QTextEdit, QPushButton, QMessageBox)
from src.core.config import load_ai_config, save_ai_config

class AIConfigDialog(QDialog):
    """
    Janela de diálogo para configurar a integração com a IA.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Configurar IA")
        self.setMinimumWidth(500)

        # Carrega a configuração atual
        self.current_config = load_ai_config()

        # Layout principal
        layout = QVBoxLayout(self)

        # Campo da API Key
        api_key_layout = QHBoxLayout()
        api_key_label = QLabel("Chave de API (Google Gemini):")
        self.api_key_input = QLineEdit()
        self.api_key_input.setEchoMode(QLineEdit.Password)
        self.api_key_input.setText(self.current_config.get("api_key", ""))
        api_key_layout.addWidget(api_key_label)
        api_key_layout.addWidget(self.api_key_input)
        layout.addLayout(api_key_layout)

        # Seleção do Modelo
        model_layout = QHBoxLayout()
        model_label = QLabel("Modelo Gemini:")
        self.model_combo = QComboBox()
        self.model_combo.addItems([
            "gemini-2.5-flash-lite",
            "gemini-2.5-flash",
            "gemini-2.5-pro"
        ])
        current_model = self.current_config.get("model")
        if current_model:
            self.model_combo.setCurrentText(current_model)
        model_layout.addWidget(model_label)
        model_layout.addWidget(self.model_combo)
        layout.addLayout(model_layout)

        # Campo do Prompt
        prompt_label = QLabel("Prompt para a IA:")
        self.prompt_input = QTextEdit()
        self.prompt_input.setText(self.current_config.get("prompt", "")) # Carrega do arquivo
        layout.addWidget(prompt_label)
        layout.addWidget(self.prompt_input)

        # Botões
        button_layout = QHBoxLayout()
        self.save_button = QPushButton("Salvar")
        self.cancel_button = QPushButton("Cancelar")
        button_layout.addStretch()
        button_layout.addWidget(self.save_button)
        button_layout.addWidget(self.cancel_button)
        layout.addLayout(button_layout)

        # Conexões
        self.save_button.clicked.connect(self.save_and_accept)
        self.cancel_button.clicked.connect(self.reject)

    def get_config(self):
        """Retorna a configuração inserida pelo usuário."""
        return {
            "api_key": self.api_key_input.text(),
            "model": self.model_combo.currentText(),
            "prompt": self.prompt_input.toPlainText()
        }

    def save_and_accept(self):
        """Salva a configuração e fecha o diálogo se for bem-sucedido."""
        new_config = self.get_config()
        if save_ai_config(new_config):
            self.accept()
        else:
            QMessageBox.critical(self, "Erro", "Não foi possível salvar a configuração da IA no arquivo 'config/ai_config.json'. Verifique as permissões do arquivo.")

if __name__ == '__main__':
    # Teste rápido
    from PySide6.QtWidgets import QApplication
    import sys

    app = QApplication(sys.argv)

    # O diálogo agora carrega a configuração sozinho
    dialog = AIConfigDialog()
    if dialog.exec():
        print("Configuração salva com sucesso!")
        # A configuração é obtida apenas para exibição no teste
        print("Configuração atual:", dialog.get_config())
    else:
        print("Configuração cancelada.")
    sys.exit(app.exec())
