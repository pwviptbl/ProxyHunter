import os

from PySide6.QtWidgets import (
    QDoubleSpinBox,
    QCheckBox,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QSpinBox,
)

from src.ui.tabs.campaign_tab import PathPickerDialog


class BrowserAutomationTab(QWidget):
    """Aba para automacao de cadastro em lote usando o browser real do ProxyHunter."""

    def __init__(self, browser_manager):
        super().__init__()
        self.browser_manager = browser_manager
        self._pending_start = None
        self._pending_open_url = None

        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)

        box = QGroupBox("Cadastro em Lote no Navegador")
        form = QFormLayout(box)

        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://exemplo.local/cadastro")
        form.addRow("URL:", self.url_input)

        self.names_file_input = QLineEdit()
        self.names_file_input.setPlaceholderText("nomes.txt")
        file_row = QHBoxLayout()
        file_row.addWidget(self.names_file_input)
        self.names_file_button = QPushButton("Selecionar")
        self.names_file_button.clicked.connect(self.pick_names_file)
        file_row.addWidget(self.names_file_button)
        form.addRow("Arquivo:", file_row)

        self.input_selector_input = QLineEdit()
        self.input_selector_input.setPlaceholderText("#nome, .nome, input[name='nome']")
        form.addRow("Input CSS:", self.input_selector_input)

        self.button_selector_input = QLineEdit()
        self.button_selector_input.setPlaceholderText("#cadastrar, .btn-cadastrar")
        form.addRow("Botao CSS:", self.button_selector_input)

        self.use_current_page_checkbox = QCheckBox("Usar pagina atual sem navegar")
        self.use_current_page_checkbox.setChecked(True)
        self.use_current_page_checkbox.setToolTip(
            "Use quando a tela depende de uma acao manual antes da automacao, como em SPA."
        )
        form.addRow("", self.use_current_page_checkbox)

        self.delay_input = QDoubleSpinBox()
        self.delay_input.setRange(0.0, 10.0)
        self.delay_input.setSingleStep(0.1)
        self.delay_input.setValue(0.5)
        form.addRow("Delay (s):", self.delay_input)

        self.timeout_input = QSpinBox()
        self.timeout_input.setRange(1, 120)
        self.timeout_input.setValue(15)
        form.addRow("Timeout (s):", self.timeout_input)

        layout.addWidget(box)
        layout.addWidget(
            QLabel(
                "Use seletores CSS. Ex.: id = #campo, class = .campo, atributo = input[name='campo']."
            )
        )

        button_row = QHBoxLayout()
        self.open_button = QPushButton("Abrir Navegador")
        self.open_button.clicked.connect(self.open_browser)
        button_row.addWidget(self.open_button)

        self.start_button = QPushButton("Executar")
        self.start_button.clicked.connect(self.start_automation)
        button_row.addWidget(self.start_button)

        self.stop_button = QPushButton("Parar")
        self.stop_button.clicked.connect(self.stop_automation)
        self.stop_button.setEnabled(False)
        button_row.addWidget(self.stop_button)

        layout.addLayout(button_row)

        self.status_label = QLabel("Status: aguardando")
        layout.addWidget(self.status_label)

        self.summary_label = QLabel("Resumo: nenhum")
        layout.addWidget(self.summary_label)

        self.log_output = QTextEdit()
        self.log_output.setReadOnly(True)
        self.log_output.setMinimumHeight(220)
        layout.addWidget(self.log_output)

        layout.addStretch()

    def pick_names_file(self):
        initial_path = self.names_file_input.text().strip() or "nomes.txt"
        dialog = PathPickerDialog(self, "Selecionar arquivo de nomes", initial_path, ".txt", save_mode=False)
        if dialog.exec():
            selected = dialog.selected_path()
            if selected:
                self.names_file_input.setText(selected)

    def open_browser(self):
        target_url = self.url_input.text().strip()
        if not target_url:
            QMessageBox.warning(self, "Campo obrigatorio", "Informe a URL antes de abrir o navegador.")
            return
        if self.browser_manager.is_ready():
            future, reason = self.browser_manager.goto_url(target_url, timeout=self.timeout_input.value())
            if future:
                self._pending_open_url = None
                self.append_log(f"Abrindo URL inicial: {target_url}")
                self.status_label.setText("Status: abrindo URL inicial")
                self.summary_label.setText("Resumo: aguarde carregar")
                return
            QMessageBox.warning(self, "Nao foi possivel abrir", f"Falha ao navegar para a URL ({reason}).")
            return
        self._pending_open_url = target_url
        launched = self.browser_manager.launch_browser()
        self.status_label.setText("Status: abrindo navegador")
        self.summary_label.setText("Resumo: carregando URL inicial")
        self.append_log(f"Abrindo navegador e carregando {target_url}.")
        if not launched:
            self.append_log("O navegador ja esta abrindo ou ja esta em execucao.")

    def start_automation(self):
        target_url = self.url_input.text().strip()
        names_file = self.names_file_input.text().strip()
        input_selector = self.input_selector_input.text().strip()
        button_selector = self.button_selector_input.text().strip()
        use_current_page = self.use_current_page_checkbox.isChecked()

        if not target_url or not names_file or not input_selector or not button_selector:
            QMessageBox.warning(
                self,
                "Campos obrigatorios",
                "Informe URL, arquivo de nomes, selector do input e selector do botao.",
            )
            return

        if not os.path.exists(names_file):
            QMessageBox.warning(self, "Arquivo nao encontrado", f"Arquivo inexistente: {names_file}")
            return

        try:
            with open(names_file, "r", encoding="utf-8") as f:
                values = [line.strip() for line in f if line.strip()]
        except Exception as exc:
            QMessageBox.critical(self, "Erro ao ler arquivo", str(exc))
            return

        if not values:
            QMessageBox.warning(self, "Arquivo vazio", "O arquivo de nomes nao possui valores validos.")
            return

        if not self.browser_manager.is_ready():
            QMessageBox.warning(
                self,
                "Navegador indisponivel",
                "Clique em 'Abrir Navegador', faca a acao manual na pagina e depois clique em 'Executar'.",
            )
            return

        self._pending_start = {
            "target_url": target_url,
            "values": values,
            "input_selector": input_selector,
            "submit_selector": button_selector,
            "use_current_page": use_current_page,
            "timeout": self.timeout_input.value(),
            "delay": self.delay_input.value(),
        }

        self._start_pending_job()

    def stop_automation(self):
        self.browser_manager.stop_bulk_fill()
        self._pending_start = None
        self.append_log("Solicitada parada da automacao.")

    def handle_ui_update(self, message: dict):
        msg_type = message.get("type")
        data = message.get("data") or {}

        if msg_type == "automation_started":
            total = data.get("total", 0)
            self.status_label.setText(f"Status: executando {total} itens")
        elif msg_type == "automation_log":
            level = data.get("level", "info")
            message_text = data.get("message", "")
            self.append_log(f"[{level.upper()}] {message_text}")
        elif msg_type == "automation_finished":
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.status_label.setText("Status: concluido")
            self.summary_label.setText(
                f"Resumo: {data.get('success', 0)} sucesso(s), {data.get('failed', 0)} falha(s), total {data.get('total', 0)}"
            )
            self.append_log("Automacao concluida.")
        elif msg_type == "automation_stopped":
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.status_label.setText("Status: interrompido")
            self.summary_label.setText(
                f"Resumo: {data.get('success', 0)} sucesso(s), {data.get('failed', 0)} falha(s), total {data.get('total', 0)}"
            )
            self.append_log("Automacao interrompida.")
        elif msg_type == "automation_error":
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.status_label.setText("Status: erro")
            self.summary_label.setText(f"Resumo: {data}")
            self.append_log(f"[ERRO] {data}")
        elif msg_type in ("browser_launch_error", "browser_closed"):
            self._pending_start = None
            self._pending_open_url = None
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.open_button.setEnabled(True)
            if msg_type == "browser_launch_error":
                self.status_label.setText("Status: erro no navegador")
                self.summary_label.setText("Resumo: browser indisponivel")
            else:
                self.status_label.setText("Status: navegador fechado")
                self.summary_label.setText("Resumo: browser encerrado")
        elif msg_type == "browser_launch_ready":
            if self._pending_open_url:
                future, reason = self.browser_manager.goto_url(
                    self._pending_open_url,
                    timeout=self.timeout_input.value(),
                )
                if future:
                    self.append_log(f"Carregando URL inicial: {self._pending_open_url}")
                    self.status_label.setText("Status: carregando URL inicial")
                    self.summary_label.setText("Resumo: aguarde a pagina abrir")
                else:
                    self.append_log(f"[ERRO] Nao foi possivel carregar a URL inicial ({reason}).")
                    self.status_label.setText("Status: erro ao carregar URL")
                    self.summary_label.setText("Resumo: falha na navegacao inicial")
                self._pending_open_url = None
            else:
                self.status_label.setText("Status: navegador pronto")
                self.open_button.setEnabled(True)
        elif msg_type == "browser_navigation_ready":
            if self._pending_start:
                self.status_label.setText("Status: navegador pronto para etapa manual")
                self.summary_label.setText("Resumo: faça a acao manual e clique Executar")
                self.append_log("Browser pronto. Execute a acao manual antes de iniciar a automacao.")
            else:
                self.status_label.setText("Status: navegador pronto")
                self.summary_label.setText("Resumo: URL carregada")
            self.open_button.setEnabled(True)
        elif msg_type == "browser_navigation_error":
            self.status_label.setText("Status: erro ao carregar URL")
            self.summary_label.setText(f"Resumo: {data}")
            self.append_log(f"[ERRO] Falha ao carregar URL inicial: {data}")
            self.open_button.setEnabled(True)

    def _start_pending_job(self):
        pending = self._pending_start
        if not pending:
            return
        self._pending_start = None
        future, reason = self.browser_manager.start_bulk_fill(
            target_url=pending["target_url"],
            values=pending["values"],
            input_selector=pending["input_selector"],
            submit_selector=pending["submit_selector"],
            use_current_page=pending["use_current_page"],
            timeout=pending["timeout"],
            delay=pending["delay"],
        )
        if not future:
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.open_button.setEnabled(True)
            if reason == "automation_running":
                QMessageBox.information(self, "Automacao em andamento", "Ja existe uma automacao em execucao.")
            else:
                QMessageBox.warning(self, "Nao iniciado", "Nao foi possivel iniciar a automacao.")
            self.status_label.setText("Status: nao iniciado")
            self.summary_label.setText("Resumo: sem execucao")
            return
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.open_button.setEnabled(True)
        mode = "pagina atual" if pending["use_current_page"] else "navegando pela URL"
        self.status_label.setText(f"Status: executando {len(pending['values'])} itens ({mode})")
        self.summary_label.setText("Resumo: em andamento")
        if pending["use_current_page"]:
            self.append_log(
                f"Iniciando automacao na pagina atual com {len(pending['values'])} itens."
            )
        else:
            self.append_log(
                f"Iniciando automacao em {pending['target_url']} com {len(pending['values'])} itens."
            )

    def append_log(self, text: str):
        self.log_output.append(text)
