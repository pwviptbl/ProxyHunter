from PySide6.QtWidgets import (QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
                               QPushButton, QFormLayout, QGroupBox, QCheckBox)

class GenerateReportDialog(QDialog):
    """
    Janela de diálogo para configurar a geração de um relatório.
    """
    def __init__(self, parent=None, scope_hosts=None, title="Gerar Relatório"):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(400)

        layout = QVBoxLayout(self)

        # Filtros
        form_layout = QFormLayout()

        self.domain_filter = QLineEdit()
        if scope_hosts:
            self.domain_filter.setText(", ".join(scope_hosts))
        else:
            self.domain_filter.setPlaceholderText("Ex: *.example.com, site.com")
        form_layout.addRow("Filtro de Domínio:", self.domain_filter)

        self.status_filter = QLineEdit()
        self.status_filter.setPlaceholderText("Ex: 200, 4xx, 500-599")
        form_layout.addRow("Filtro de Status Code:", self.status_filter)

        layout.addLayout(form_layout)

        # Filtro de Métodos HTTP
        methods_group = QGroupBox("Métodos HTTP")
        methods_layout = QHBoxLayout()
        self.method_checkboxes = {
            'GET': QCheckBox("GET"),
            'POST': QCheckBox("POST"),
            'PUT': QCheckBox("PUT"),
            'DELETE': QCheckBox("DELETE"),
            'OPTIONS': QCheckBox("OPTIONS"),
            'HEAD': QCheckBox("HEAD"),
            'PATCH': QCheckBox("PATCH"),
        }
        for checkbox in self.method_checkboxes.values():
            checkbox.setChecked(True) # Todos marcados por padrão
            methods_layout.addWidget(checkbox)
        methods_group.setLayout(methods_layout)
        layout.addWidget(methods_group)

        # Botões
        button_layout = QHBoxLayout()
        self.generate_button = QPushButton("Gerar")
        self.cancel_button = QPushButton("Cancelar")
        button_layout.addStretch()
        button_layout.addWidget(self.generate_button)
        button_layout.addWidget(self.cancel_button)
        layout.addLayout(button_layout)

        # Conexões
        self.generate_button.clicked.connect(self.accept)
        self.cancel_button.clicked.connect(self.reject)

    def get_filters(self):
        """Retorna os filtros de geração do relatório."""
        selected_methods = [method for method, checkbox in self.method_checkboxes.items() if checkbox.isChecked()]

        return {
            "domain": self.domain_filter.text(),
            "status_code": self.status_filter.text(),
            "methods": selected_methods
        }

if __name__ == '__main__':
    from PySide6.QtWidgets import QApplication
    import sys

    app = QApplication(sys.argv)
    dialog = GenerateReportDialog()
    if dialog.exec():
        print("Filtros selecionados:", dialog.get_filters())
    else:
        print("Geração cancelada.")
    sys.exit(app.exec())
