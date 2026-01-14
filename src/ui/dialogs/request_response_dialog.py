from PySide6.QtWidgets import QDialog, QTabWidget, QVBoxLayout, QTextEdit

class RequestResponseDialog(QDialog):
    def __init__(self, request_text: str, response_text: str, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Detalhes da Requisição e Resposta")
        self.resize(700, 500)

        layout = QVBoxLayout(self)
        tabs = QTabWidget(self)

        # Aba Request
        request_edit = QTextEdit()
        request_edit.setReadOnly(True)
        request_edit.setPlainText(request_text)
        tabs.addTab(request_edit, "Request")

        # Aba Response
        response_edit = QTextEdit()
        response_edit.setReadOnly(True)
        response_edit.setPlainText(response_text)
        tabs.addTab(response_edit, "Response")

        layout.addWidget(tabs)
        self.setLayout(layout)
