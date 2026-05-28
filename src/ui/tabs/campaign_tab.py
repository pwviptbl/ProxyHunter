import json
import os
from collections import Counter
from datetime import datetime

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, QThread, Signal, QTimer
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableView,
    QTextEdit,
    QVBoxLayout,
    QWidget,
    QMenu,
)
from PySide6.QtGui import QAction

from src.core.active_scanner import ActiveScanner
from src.core.campaign import build_campaign, campaign_routes
from src.core.history import RequestHistory
from src.core.scanner import VulnerabilityScanner


SCAN_TYPE_OPTIONS = {
    "SQLi": {
        "modules": ["SqlInjectionModule"],
        "builtin": ["SQLI"],
    },
    "XSS": {
        "modules": ["XssModule"],
        "builtin": ["XSS"],
    },
    "Command": {
        "modules": [],
        "builtin": ["COMMAND"],
    },
    "SSTI": {
        "modules": ["SstiModule"],
        "builtin": [],
    },
    "LFI": {
        "modules": ["LfiModule"],
        "builtin": ["LFI"],
    },
    "Open Redirect": {
        "modules": ["OpenRedirectModule"],
        "builtin": [],
    },
    "Header Injection": {
        "modules": ["HeaderInjectionModule"],
        "builtin": [],
    },
    "IDOR": {
        "modules": ["IdorModule"],
        "builtin": [],
    },
}

INSERTION_LOCATION_OPTIONS = {
    "Body": ["BODY"],
    "Body + Query": ["BODY", "QUERY"],
    "Todos": None,
}


class CampaignScanWorker(QThread):
    route_started = Signal(int, int, str)
    route_done = Signal(dict, list)
    log_message = Signal(str)
    finished_summary = Signal(int, int)

    def __init__(
        self,
        routes,
        active_scanner: ActiveScanner,
        run_passive=True,
        run_active=True,
        enabled_modules=None,
        enabled_builtin_checks=None,
        insertion_locations=None,
    ):
        super().__init__()
        self.routes = routes
        self.active_scanner = active_scanner
        self.run_passive = run_passive
        self.run_active = run_active
        self.enabled_modules = enabled_modules
        self.enabled_builtin_checks = enabled_builtin_checks
        self.insertion_locations = insertion_locations
        self.passive_scanner = VulnerabilityScanner() if run_passive else None

    def run(self):
        total_added = 0
        total = len(self.routes)
        old_callback = self.active_scanner.log_callback
        try:
            if self.run_active:
                self.active_scanner.log_callback = lambda msg: self.log_message.emit(msg)

            for index, route in enumerate(self.routes):
                if self.isInterruptionRequested():
                    break

                label = f"{route.get('method', '')} {route.get('url', '')}"
                self.route_started.emit(index + 1, total, label)
                vulnerabilities = []

                if self.passive_scanner:
                    vulnerabilities.extend(self.passive_scanner.scan_entry(route) or [])

                if self.run_active:
                    label = self._route_label(index + 1, total, route)
                    request_data = {
                        "id": route.get("id"),
                        "method": route.get("method"),
                        "url": route.get("url"),
                        "headers": route.get("request_headers", {}) or route.get("headers", {}) or {},
                        "body": route.get("request_body", "") or route.get("body", "") or "",
                        "_scan_label": label,
                        "_enabled_modules": self.enabled_modules,
                        "_enabled_builtin_checks": self.enabled_builtin_checks,
                        "_injection_locations": self.insertion_locations,
                    }
                    vulnerabilities.extend(self.active_scanner.scan_request(request_data) or [])

                added = self._merge_vulnerabilities(route, vulnerabilities)
                total_added += added
                self.route_done.emit(route, route.get("vulnerabilities", []))

        finally:
            self.active_scanner.log_callback = old_callback
            self.finished_summary.emit(total, total_added)

    @staticmethod
    def _merge_vulnerabilities(route, vulnerabilities):
        if not vulnerabilities:
            return 0
        existing = route.get("vulnerabilities") or []
        existing_set = {str(v) for v in existing}
        added = 0
        for vuln in vulnerabilities:
            if str(vuln) not in existing_set:
                existing.append(vuln)
                existing_set.add(str(vuln))
                added += 1
        route["vulnerabilities"] = existing
        return added

    @staticmethod
    def _route_label(index, total, route):
        metadata = route.get("campaign_metadata") or {}
        source_id = metadata.get("source_history_id") or route.get("id", "")
        return f"[Campanha {index}/{total} ID {source_id} {route.get('method', '')} {route.get('url', '')}]"


class CampaignTab(QWidget):
    """Aba para capturar, importar, exportar e escanear campanhas de rotas."""

    refresh_vulnerabilities_requested = Signal()

    def __init__(self, history: RequestHistory, active_scanner: ActiveScanner):
        super().__init__()
        self.history_manager = history
        self.active_scanner = active_scanner
        self.campaign = None
        self.capture_start_id = None
        self.captured_entries = []
        self.scan_worker = None
        self.auto_scan_queue = []
        self.auto_scan_signatures = set()
        self.auto_scan_running = False
        self.autosave_path = os.path.join("logs", "campaign_autosave.json")
        self.pending_log_lines = []

        layout = QVBoxLayout(self)
        self._setup_capture_section(layout)

        splitter = QSplitter(Qt.Orientation.Vertical)
        layout.addWidget(splitter)
        self._setup_table(splitter)
        self._setup_details(splitter)
        splitter.setSizes([430, 260])

        self.log_flush_timer = QTimer(self)
        self.log_flush_timer.timeout.connect(self._flush_log_lines)
        self.log_flush_timer.start(250)
        self._load_autosave_campaign()

    def _setup_capture_section(self, layout):
        group = QGroupBox("Campanha")
        box = QVBoxLayout()

        top = QHBoxLayout()
        top.addWidget(QLabel("Nome:"))
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("ex: ecidade-cliente")
        top.addWidget(self.name_input)
        top.addWidget(QLabel("Escopo:"))
        self.scope_input = QLineEdit()
        self.scope_input.setPlaceholderText("ex: alvo.local,/e-cidade")
        top.addWidget(self.scope_input)
        box.addLayout(top)

        actions = QHBoxLayout()
        self.capture_button = QPushButton("Iniciar Captura")
        self.capture_button.clicked.connect(self.toggle_capture)
        actions.addWidget(self.capture_button)

        build_button = QPushButton("Gerar do Histórico")
        build_button.clicked.connect(self.build_from_history)
        actions.addWidget(build_button)

        import_button = QPushButton("Importar")
        import_button.clicked.connect(self.import_campaign)
        actions.addWidget(import_button)

        export_button = QPushButton("Exportar")
        export_button.clicked.connect(self.export_campaign)
        actions.addWidget(export_button)

        report_button = QPushButton("Relatório")
        report_button.clicked.connect(self.generate_report)
        actions.addWidget(report_button)

        remove_button = QPushButton("Excluir Selecionado")
        remove_button.clicked.connect(self.remove_selected_route)
        actions.addWidget(remove_button)

        self.passive_checkbox = QCheckBox("Passivo")
        self.passive_checkbox.setChecked(True)
        actions.addWidget(self.passive_checkbox)

        self.active_checkbox = QCheckBox("Ativo")
        self.active_checkbox.setChecked(True)
        actions.addWidget(self.active_checkbox)

        self.auto_scan_checkbox = QCheckBox("Simultaneo")
        self.auto_scan_checkbox.setToolTip("Durante a captura, escaneia automaticamente cada rota testavel nova.")
        self.auto_scan_checkbox.stateChanged.connect(self._on_auto_scan_toggled)
        actions.addWidget(self.auto_scan_checkbox)

        scan_selected_button = QPushButton("Scan Selecionado")
        scan_selected_button.clicked.connect(self.scan_selected)
        actions.addWidget(scan_selected_button)

        scan_all_button = QPushButton("Scan Todos")
        scan_all_button.clicked.connect(self.scan_all)
        actions.addWidget(scan_all_button)

        actions.addStretch()
        box.addLayout(actions)

        scan_options = QHBoxLayout()
        scan_options.addWidget(QLabel("Tipos ativos:"))
        self.scan_type_checkboxes = {}
        for label in SCAN_TYPE_OPTIONS.keys():
            checkbox = QCheckBox(label)
            checkbox.setChecked(label in ("SQLi", "XSS"))
            self.scan_type_checkboxes[label] = checkbox
            scan_options.addWidget(checkbox)

        scan_options.addWidget(QLabel("Parametros:"))
        self.insertion_location_combo = QComboBox()
        self.insertion_location_combo.addItems(list(INSERTION_LOCATION_OPTIONS.keys()))
        self.insertion_location_combo.setCurrentText("Body")
        scan_options.addWidget(self.insertion_location_combo)

        scan_options.addStretch()
        box.addLayout(scan_options)

        self.status_label = QLabel("Sem campanha carregada.")
        box.addWidget(self.status_label)
        group.setLayout(box)
        layout.addWidget(group)

    def _setup_table(self, parent):
        group = QGroupBox("Rotas Testaveis")
        layout = QVBoxLayout()
        self.table = QTableView()
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setSortingEnabled(True)
        self.model = CampaignTableModel([])
        self.table.setModel(self.model)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.table.selectionModel().selectionChanged.connect(self._on_selection_changed)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_context_menu)
        layout.addWidget(self.table)
        group.setLayout(layout)
        parent.addWidget(group)

    def _setup_details(self, parent):
        group = QGroupBox("Detalhes")
        layout = QVBoxLayout()
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.details_text.setFontFamily("Monospace")
        layout.addWidget(self.details_text)
        group.setLayout(layout)
        parent.addWidget(group)

    def toggle_capture(self):
        if self.capture_start_id is None:
            entries = self.history_manager.get_history()
            self.capture_start_id = max([e.get("id", 0) for e in entries] or [0])
            self.captured_entries = []
            self.auto_scan_queue = []
            self.auto_scan_signatures = set()
            self.auto_scan_running = False
            self.campaign = build_campaign(
                self.captured_entries,
                name=self.name_input.text().strip() or "campanha-gui",
                scope=self._scope_terms(),
            )
            self._refresh_campaign_view()
            self._autosave_campaign()
            self.capture_button.setText("Finalizar Captura")
            self.status_label.setText(f"Capturando a partir do ID {self.capture_start_id + 1}. Navegue pelo sistema e finalize.")
            return

        start_id = self.capture_start_id
        self.capture_start_id = None
        self.capture_button.setText("Iniciar Captura")
        entries = self.captured_entries or [e for e in self.history_manager.get_history() if e.get("id", 0) > start_id]
        self._build_campaign(entries)
        self._autosave_campaign()

    def add_captured_entry(self, entry):
        """Atualiza a campanha em tempo real enquanto a captura esta ativa."""
        if self.capture_start_id is None:
            return
        if not entry or entry.get("id", 0) <= self.capture_start_id:
            return
        self.captured_entries.append(entry)
        self.campaign = build_campaign(
            self.captured_entries,
            name=self.name_input.text().strip() or "campanha-gui",
            scope=self._scope_terms(),
        )
        self._refresh_campaign_view(keep_details=True)
        self._autosave_campaign()
        if self.auto_scan_checkbox.isChecked():
            self._enqueue_auto_scan_routes()

    def build_from_history(self):
        self._build_campaign(self.history_manager.get_history())

    def _build_campaign(self, entries):
        name = self.name_input.text().strip() or "campanha-gui"
        scope = self._scope_terms()
        self.campaign = build_campaign(entries, name=name, scope=scope)
        self._refresh_campaign_view()
        self._autosave_campaign()
        if self.auto_scan_checkbox.isChecked():
            self._enqueue_auto_scan_routes()

    def import_campaign(self):
        path, _ = QFileDialog.getOpenFileName(self, "Importar campanha", "logs", "JSON (*.json);;Todos (*.*)")
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                campaign = json.load(f)
        except Exception as exc:
            QMessageBox.critical(self, "Importar", f"Falha ao importar campanha: {exc}")
            return
        if not isinstance(campaign, dict) or campaign.get("schema") != "proxyhunter.campaign":
            QMessageBox.warning(self, "Importar", "Arquivo nao parece ser uma campanha do ProxyHunter.")
            return
        self.campaign = campaign
        self.name_input.setText(str(campaign.get("name", "")))
        self.scope_input.setText(",".join(campaign.get("scope", []) or []))
        self._refresh_campaign_view()
        self._autosave_campaign()

    def export_campaign(self):
        if not self.campaign:
            QMessageBox.information(self, "Exportar", "Nao ha campanha para exportar.")
            return
        default_name = f"{self.campaign.get('name', 'campaign')}.json".replace("/", "_")
        path, _ = QFileDialog.getSaveFileName(self, "Exportar campanha", os.path.join("logs", default_name), "JSON (*.json)")
        if not path:
            return
        try:
            directory = os.path.dirname(path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                json.dump(self.campaign, f, indent=2, ensure_ascii=False)
        except Exception as exc:
            QMessageBox.critical(self, "Exportar", f"Falha ao exportar campanha: {exc}")
            return
        QMessageBox.information(self, "Exportar", f"Campanha exportada em:\n{path}")

    def generate_report(self):
        if not self.campaign:
            QMessageBox.information(self, "Relatório", "Nao ha campanha para gerar relatório.")
            return

        default_name = f"relatorio_{self.campaign.get('name', 'campanha')}.md".replace("/", "_")
        path, _ = QFileDialog.getSaveFileName(self, "Salvar relatório da campanha", os.path.join("reports", default_name), "Markdown (*.md)")
        if not path:
            return

        try:
            directory = os.path.dirname(path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            with open(path, "w", encoding="utf-8") as f:
                f.write(self._build_markdown_report())
        except Exception as exc:
            QMessageBox.critical(self, "Relatório", f"Falha ao gerar relatório: {exc}")
            return

        QMessageBox.information(self, "Relatório", f"Relatório salvo em:\n{path}")

    def _build_markdown_report(self):
        routes = campaign_routes(self.campaign or {})
        allowed_sources = self._report_allowed_sources()
        vulnerabilities = []
        for route in routes:
            for vuln in route.get("vulnerabilities", []) or []:
                if not self._vulnerability_source_allowed(vuln, allowed_sources):
                    continue
                item = dict(vuln)
                item.setdefault("url", route.get("url", "N/A"))
                item.setdefault("method", route.get("method", "N/A"))
                vulnerabilities.append(item)

        severity_counts = Counter(v.get("severity", "Unknown") for v in vulnerabilities)
        type_counts = Counter(v.get("type", "Unknown") for v in vulnerabilities)
        source_counts = Counter(v.get("source", "Unknown") for v in vulnerabilities)
        method_counts = Counter(route.get("method", "N/A") for route in routes)
        status_counts = Counter(str(route.get("status", "N/A")) for route in routes)

        lines = [
            "# Relatorio de Campanha - ProxyHunter",
            "",
            f"- Campanha: {self.campaign.get('name', 'N/A')}",
            f"- Gerado em: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            f"- Filtro de origem: {self._report_source_label()}",
            f"- Rotas testaveis: {len(routes)}",
            f"- Vulnerabilidades: {len(vulnerabilities)}",
            "",
            "## Resumo",
            "",
            f"- Metodos: {self._format_counter(method_counts)}",
            f"- Status: {self._format_counter(status_counts)}",
            f"- Origem dos achados: {self._format_counter(source_counts) if vulnerabilities else 'nenhuma'}",
            f"- Severidades: {self._format_counter(severity_counts) if vulnerabilities else 'nenhuma'}",
            f"- Tipos: {self._format_counter(type_counts) if vulnerabilities else 'nenhum'}",
            "",
            "## Achados",
            "",
        ]

        if not vulnerabilities:
            lines.append("Nenhuma vulnerabilidade registrada na campanha.")
        else:
            severity_order = ["Critical", "High", "Medium", "Low", "Info", "Unknown"]
            for severity in severity_order:
                items = [v for v in vulnerabilities if v.get("severity", "Unknown") == severity]
                if not items:
                    continue
                lines.extend([f"### {severity}", ""])
                for vuln in items:
                    lines.append(f"- **{vuln.get('type', 'Unknown')}**")
                    lines.append(f"  - Metodo: `{vuln.get('method', 'N/A')}`")
                    lines.append(f"  - URL: `{vuln.get('url', 'N/A')}`")
                    lines.append(f"  - Origem: `{vuln.get('source', 'N/A')}`")
                    if vuln.get("parameter") or vuln.get("location"):
                        lines.append(f"  - Parametro: `{vuln.get('parameter', 'N/A')}` (`{vuln.get('location', 'N/A')}`)")
                    if vuln.get("description"):
                        lines.append(f"  - Descricao: {vuln.get('description')}")
                    if vuln.get("evidence"):
                        lines.append(f"  - Evidencia: `{str(vuln.get('evidence'))[:500]}`")
                    lines.append("")

        lines.extend(["", "## Rotas Testadas", ""])
        for route in routes:
            vuln_count = len([
                vuln for vuln in (route.get("vulnerabilities", []) or [])
                if self._vulnerability_source_allowed(vuln, allowed_sources)
            ])
            lines.append(f"- `{route.get('method', '')}` `{route.get('url', '')}` | Status: `{route.get('status', '')}` | Achados: `{vuln_count}`")

        return "\n".join(lines).strip() + "\n"

    def _report_allowed_sources(self):
        sources = set()
        if self.active_checkbox.isChecked():
            sources.add("Active")
            # Compatibilidade com campanhas antigas geradas antes de normalizar
            # achados dos modulos ativos para source=Active.
            sources.add("Module")
        if self.passive_checkbox.isChecked():
            sources.add("Passive")
        return sources

    def _report_source_label(self):
        labels = []
        if self.active_checkbox.isChecked():
            labels.append("Active")
        if self.passive_checkbox.isChecked():
            labels.append("Passive")
        return ", ".join(labels) if labels else "nenhum"

    @staticmethod
    def _vulnerability_source_allowed(vuln, allowed_sources):
        if not allowed_sources:
            return False
        return (vuln.get("source") or "Unknown") in allowed_sources

    @staticmethod
    def _format_counter(counter):
        if not counter:
            return "nenhum"
        return ", ".join(f"{key}: {count}" for key, count in counter.most_common())

    def remove_selected_route(self):
        row = self._selected_source_row()
        if row is None:
            QMessageBox.information(self, "Excluir", "Selecione uma rota da campanha.")
            return
        self._remove_route(row)

    def _remove_route(self, row):
        if self.scan_worker and self.scan_worker.isRunning():
            QMessageBox.information(self, "Excluir", "Aguarde o scan atual finalizar antes de remover rotas.")
            return
        routes = campaign_routes(self.campaign or {})
        route = self.model.get_route(row)
        if not route or route not in routes:
            return
        routes.remove(route)
        signature = self._route_signature(route)
        self.auto_scan_queue = [item for item in self.auto_scan_queue if self._route_signature(item) != signature]
        self.auto_scan_signatures.discard(signature)
        self._update_campaign_route_stats()
        self._refresh_campaign_view()
        self._autosave_campaign()

    def _show_context_menu(self, pos):
        row = self._selected_source_row()
        if row is None:
            return
        menu = QMenu(self)
        remove_action = QAction("Excluir da campanha", self)
        remove_action.triggered.connect(lambda: self._remove_route(row))
        menu.addAction(remove_action)
        menu.exec_(self.table.viewport().mapToGlobal(pos))

    def scan_selected(self):
        row = self._selected_source_row()
        if row is None:
            QMessageBox.information(self, "Scan", "Selecione uma rota da campanha.")
            return
        self._start_scan([self.model.get_route(row)], automatic=False)

    def scan_all(self):
        routes = campaign_routes(self.campaign or {})
        if not routes:
            QMessageBox.information(self, "Scan", "Nao ha rotas testaveis na campanha.")
            return
        self._start_scan(routes, automatic=False)

    def _start_scan(self, routes, automatic=False):
        if self.scan_worker and self.scan_worker.isRunning():
            if not automatic:
                QMessageBox.information(self, "Scan", "Ja existe um scan de campanha em execucao.")
            return False
        run_passive = self.passive_checkbox.isChecked()
        run_active = self.active_checkbox.isChecked()
        if not run_passive and not run_active:
            if not automatic:
                QMessageBox.information(self, "Scan", "Habilite scan passivo ou ativo.")
            return False
        enabled_modules, enabled_builtin_checks = self._selected_scan_controls()
        if run_active and not enabled_modules and not enabled_builtin_checks:
            if not automatic:
                QMessageBox.information(self, "Scan", "Selecione ao menos um tipo ativo, como SQLi ou XSS.")
            else:
                self.status_label.setText("Scan simultaneo aguardando: selecione ao menos um tipo ativo.")
            return False

        self.auto_scan_running = automatic
        if not automatic:
            self.details_text.clear()
        insertion_locations = INSERTION_LOCATION_OPTIONS.get(self.insertion_location_combo.currentText())
        self.scan_worker = CampaignScanWorker(
            routes,
            self.active_scanner,
            run_passive,
            run_active,
            enabled_modules=enabled_modules,
            enabled_builtin_checks=enabled_builtin_checks,
            insertion_locations=insertion_locations,
        )
        self.scan_worker.route_started.connect(self._on_route_started)
        self.scan_worker.route_done.connect(self._on_route_done)
        self.scan_worker.log_message.connect(self._append_log)
        self.scan_worker.finished_summary.connect(self._on_scan_finished)
        self.scan_worker.finished.connect(self._on_worker_finished)
        self.scan_worker.start()
        return True

    def stop_scan(self):
        if self.scan_worker and self.scan_worker.isRunning():
            self.scan_worker.requestInterruption()
            self.scan_worker.wait(3000)
            if self.scan_worker.isRunning():
                self.scan_worker.terminate()
                self.scan_worker.wait(1000)

    def _on_route_started(self, index, total, label):
        self.status_label.setText(f"Escaneando {index}/{total}: {label}")
        self._append_log(f"\n=== {index}/{total} {label} ===")

    def _on_route_done(self, route, vulnerabilities):
        self._merge_route_into_current_campaign(route)
        self._refresh_campaign_view(keep_details=True)
        if route:
            self._sync_vulnerabilities_to_history(route, vulnerabilities)
        self._autosave_campaign()

    def _on_scan_finished(self, total, total_added):
        self.status_label.setText(f"Scan finalizado. Rotas processadas: {total}. Novos achados: {total_added}.")
        self._append_log(f"\nScan finalizado. Novos achados: {total_added}.")
        self._refresh_campaign_view(keep_details=True)

    def _on_worker_finished(self):
        if self.scan_worker:
            self.scan_worker.deleteLater()
            self.scan_worker = None
        if self.auto_scan_running:
            self.auto_scan_running = False
            self._start_next_auto_scan_batch()

    def _enqueue_auto_scan_routes(self):
        for route in campaign_routes(self.campaign or {}):
            signature = self._route_signature(route)
            if not signature or signature in self.auto_scan_signatures:
                continue
            self.auto_scan_signatures.add(signature)
            self.auto_scan_queue.append(route)
            self._append_log(f"[Auto] Rota enfileirada: {route.get('method')} {route.get('url')}")
        self._start_next_auto_scan_batch()

    def _start_next_auto_scan_batch(self):
        if not self.auto_scan_checkbox.isChecked():
            return
        if self.scan_worker and self.scan_worker.isRunning():
            return
        if not self.auto_scan_queue:
            return
        if not self.passive_checkbox.isChecked() and not self.active_checkbox.isChecked():
            self.status_label.setText("Scan simultaneo aguardando: habilite Passivo ou Ativo.")
            return
        routes = list(self.auto_scan_queue)
        self.auto_scan_queue = []
        self._start_scan(routes, automatic=True)

    def _on_auto_scan_toggled(self):
        if self.auto_scan_checkbox.isChecked():
            self._enqueue_auto_scan_routes()
        else:
            self.auto_scan_queue = []
            self.status_label.setText("Scan simultaneo desabilitado.")

    def _merge_route_into_current_campaign(self, scanned_route):
        if not scanned_route:
            return
        scanned_signature = self._route_signature(scanned_route)
        for route in campaign_routes(self.campaign or {}):
            if self._route_signature(route) == scanned_signature:
                route["vulnerabilities"] = scanned_route.get("vulnerabilities", []) or []
                return

    def _sync_vulnerabilities_to_history(self, route, vulnerabilities):
        if not vulnerabilities:
            return
        metadata = route.get("campaign_metadata") or {}
        candidate_ids = [metadata.get("source_history_id"), route.get("id")]
        for entry_id in candidate_ids:
            if entry_id and self.history_manager.add_vulnerabilities_to_entry(entry_id, vulnerabilities):
                return

        # Fallback para campanhas antigas/importadas sem source_history_id correto.
        route_url = route.get("url")
        route_method = route.get("method")
        route_body = route.get("request_body", "")
        for entry in reversed(self.history_manager.get_history()):
            if (
                entry.get("url") == route_url
                and entry.get("method") == route_method
                and entry.get("request_body", "") == route_body
            ):
                self.history_manager.add_vulnerabilities_to_entry(entry.get("id"), vulnerabilities)
                return

    @staticmethod
    def _route_signature(route):
        metadata = route.get("campaign_metadata") or {}
        return metadata.get("signature")

    def _selected_scan_controls(self):
        enabled_modules = []
        enabled_builtin_checks = []
        for label, checkbox in self.scan_type_checkboxes.items():
            if not checkbox.isChecked():
                continue
            option = SCAN_TYPE_OPTIONS[label]
            enabled_modules.extend(option["modules"])
            enabled_builtin_checks.extend(option["builtin"])
        return enabled_modules, enabled_builtin_checks

    def _append_log(self, text):
        self.pending_log_lines.append(text)
        if len(self.pending_log_lines) > 500:
            self.pending_log_lines = self.pending_log_lines[-500:]

    def _flush_log_lines(self):
        if not self.pending_log_lines:
            return
        chunk = "\n".join(self.pending_log_lines[:80])
        self.pending_log_lines = self.pending_log_lines[80:]
        self.details_text.append(chunk)
        sb = self.details_text.verticalScrollBar()
        sb.setValue(sb.maximum())

    def _autosave_campaign(self):
        if not self.campaign:
            return
        try:
            directory = os.path.dirname(self.autosave_path)
            if directory:
                os.makedirs(directory, exist_ok=True)
            payload = dict(self.campaign)
            payload["autosaved_at"] = datetime.now().isoformat(timespec="seconds")
            temp_path = f"{self.autosave_path}.tmp"
            with open(temp_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
            os.replace(temp_path, self.autosave_path)
        except Exception:
            pass

    def _load_autosave_campaign(self):
        if not os.path.exists(self.autosave_path):
            return
        try:
            with open(self.autosave_path, "r", encoding="utf-8") as f:
                campaign = json.load(f)
        except Exception:
            return
        if not isinstance(campaign, dict) or campaign.get("schema") != "proxyhunter.campaign":
            return
        self.campaign = campaign
        self.name_input.setText(str(campaign.get("name", "")))
        self.scope_input.setText(",".join(campaign.get("scope", []) or []))
        self._refresh_campaign_view()
        autosaved_at = campaign.get("autosaved_at")
        if autosaved_at:
            self.status_label.setText(f"Autosave restaurado de {autosaved_at}.")

    def _on_selection_changed(self, selected, deselected):
        row = self._selected_source_row()
        if row is None:
            return
        route = self.model.get_route(row)
        if not route:
            return
        request_headers = route.get("request_headers", {}) or {}
        response_headers = route.get("response_headers", {}) or {}
        vulns = route.get("vulnerabilities", []) or []
        text = [
            f"{route.get('method', '')} {route.get('url', '')}",
            f"Status: {route.get('status', '')}",
            f"Vulnerabilidades: {len(vulns)}",
            "",
            "Request headers:",
            "\n".join(f"{k}: {v}" for k, v in request_headers.items()),
            "",
            "Request body:",
            str(route.get("request_body", ""))[:4000],
            "",
            "Response headers:",
            "\n".join(f"{k}: {v}" for k, v in response_headers.items()),
        ]
        if vulns:
            text.extend(["", "Achados:"])
            for vuln in vulns:
                text.append(f"- [{vuln.get('severity')}] {vuln.get('type')}")
                if vuln.get("parameter") or vuln.get("location"):
                    text.append(f"  Parametro: {vuln.get('parameter', 'N/A')} ({vuln.get('location', 'N/A')})")
                if vuln.get("description"):
                    text.append(f"  Descricao: {vuln.get('description')}")
                if vuln.get("evidence"):
                    text.append(f"  Evidencia/Payload: {vuln.get('evidence')}")
        self.details_text.setPlainText("\n".join(text))

    def _refresh_campaign_view(self, keep_details=False):
        routes = campaign_routes(self.campaign or {})
        self.model.update_data(routes)
        stats = (self.campaign or {}).get("stats", {})
        self.status_label.setText(
            f"Rotas testaveis: {len(routes)} | Entrada: {stats.get('input', 0)} | "
            f"Estaticos ignorados: {stats.get('ignored_static', 0)} | "
            f"Sem superficie: {stats.get('ignored_no_surface', 0)} | "
            f"Duplicadas: {stats.get('ignored_duplicate', 0)}"
        )
        if self.capture_start_id is not None:
            self.status_label.setText(
                f"Capturando | Rotas testaveis: {len(routes)} | Capturadas: {stats.get('input', 0)} | "
                f"Estaticos: {stats.get('ignored_static', 0)} | "
                f"Sem superficie: {stats.get('ignored_no_surface', 0)} | "
                f"Duplicadas: {stats.get('ignored_duplicate', 0)}"
            )
        if not keep_details:
            self.details_text.clear()

    def _update_campaign_route_stats(self):
        if not self.campaign:
            return
        stats = self.campaign.setdefault("stats", {})
        stats["routes"] = len(campaign_routes(self.campaign))

    def _scope_terms(self):
        return [item.strip() for item in self.scope_input.text().split(",") if item.strip()]

    def _selected_source_row(self):
        selected = self.table.selectionModel().selectedRows()
        if not selected:
            return None
        return selected[0].row()


class CampaignTableModel(QAbstractTableModel):
    def __init__(self, data=None):
        super().__init__()
        self._data = data or []
        self._headers = ["ID", "Metodo", "Status", "Achados", "URL"]

    def data(self, index, role):
        if role == Qt.ItemDataRole.DisplayRole:
            route = self._data[index.row()]
            col = index.column()
            if col == 0:
                return route.get("id", "")
            if col == 1:
                return route.get("method", "")
            if col == 2:
                return route.get("status", "")
            if col == 3:
                return len(route.get("vulnerabilities", []) or [])
            if col == 4:
                return route.get("url", "")
        return None

    def rowCount(self, index=QModelIndex()):
        return len(self._data)

    def columnCount(self, index=QModelIndex()):
        return len(self._headers)

    def headerData(self, section, orientation, role):
        if role == Qt.ItemDataRole.DisplayRole and orientation == Qt.Orientation.Horizontal:
            return self._headers[section]
        return None

    def get_route(self, row):
        if 0 <= row < len(self._data):
            return self._data[row]
        return None

    def update_data(self, data):
        self.beginResetModel()
        self._data = data or []
        self.endResetModel()
