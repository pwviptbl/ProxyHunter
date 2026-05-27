import json
import os

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt, QThread, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
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
)

from src.core.active_scanner import ActiveScanner
from src.core.campaign import build_campaign, campaign_routes
from src.core.history import RequestHistory
from src.core.scanner import VulnerabilityScanner


class CampaignScanWorker(QThread):
    route_started = Signal(int, int, str)
    route_done = Signal(dict, list)
    log_message = Signal(str)
    finished_summary = Signal(int, int)

    def __init__(self, routes, active_scanner: ActiveScanner, run_passive=True, run_active=True):
        super().__init__()
        self.routes = routes
        self.active_scanner = active_scanner
        self.run_passive = run_passive
        self.run_active = run_active
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
                    request_data = {
                        "id": route.get("id"),
                        "method": route.get("method"),
                        "url": route.get("url"),
                        "headers": route.get("request_headers", {}) or route.get("headers", {}) or {},
                        "body": route.get("request_body", "") or route.get("body", "") or "",
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

        layout = QVBoxLayout(self)
        self._setup_capture_section(layout)

        splitter = QSplitter(Qt.Orientation.Vertical)
        layout.addWidget(splitter)
        self._setup_table(splitter)
        self._setup_details(splitter)
        splitter.setSizes([430, 260])

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

        self.passive_checkbox = QCheckBox("Passivo")
        self.passive_checkbox.setChecked(True)
        actions.addWidget(self.passive_checkbox)

        self.active_checkbox = QCheckBox("Ativo")
        self.active_checkbox.setChecked(True)
        actions.addWidget(self.active_checkbox)

        scan_selected_button = QPushButton("Scan Selecionado")
        scan_selected_button.clicked.connect(self.scan_selected)
        actions.addWidget(scan_selected_button)

        scan_all_button = QPushButton("Scan Todos")
        scan_all_button.clicked.connect(self.scan_all)
        actions.addWidget(scan_all_button)

        actions.addStretch()
        box.addLayout(actions)

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
            self.campaign = build_campaign(
                self.captured_entries,
                name=self.name_input.text().strip() or "campanha-gui",
                scope=self._scope_terms(),
            )
            self._refresh_campaign_view()
            self.capture_button.setText("Finalizar Captura")
            self.status_label.setText(f"Capturando a partir do ID {self.capture_start_id + 1}. Navegue pelo sistema e finalize.")
            return

        start_id = self.capture_start_id
        self.capture_start_id = None
        self.capture_button.setText("Iniciar Captura")
        entries = self.captured_entries or [e for e in self.history_manager.get_history() if e.get("id", 0) > start_id]
        self._build_campaign(entries)

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

    def build_from_history(self):
        self._build_campaign(self.history_manager.get_history())

    def _build_campaign(self, entries):
        name = self.name_input.text().strip() or "campanha-gui"
        scope = self._scope_terms()
        self.campaign = build_campaign(entries, name=name, scope=scope)
        self._refresh_campaign_view()

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

    def scan_selected(self):
        row = self._selected_source_row()
        if row is None:
            QMessageBox.information(self, "Scan", "Selecione uma rota da campanha.")
            return
        self._start_scan([self.model.get_route(row)])

    def scan_all(self):
        routes = campaign_routes(self.campaign or {})
        if not routes:
            QMessageBox.information(self, "Scan", "Nao ha rotas testaveis na campanha.")
            return
        self._start_scan(routes)

    def _start_scan(self, routes):
        if self.scan_worker and self.scan_worker.isRunning():
            QMessageBox.information(self, "Scan", "Ja existe um scan de campanha em execucao.")
            return
        run_passive = self.passive_checkbox.isChecked()
        run_active = self.active_checkbox.isChecked()
        if not run_passive and not run_active:
            QMessageBox.information(self, "Scan", "Habilite scan passivo ou ativo.")
            return

        self.details_text.clear()
        self.scan_worker = CampaignScanWorker(routes, self.active_scanner, run_passive, run_active)
        self.scan_worker.route_started.connect(self._on_route_started)
        self.scan_worker.route_done.connect(self._on_route_done)
        self.scan_worker.log_message.connect(self._append_log)
        self.scan_worker.finished_summary.connect(self._on_scan_finished)
        self.scan_worker.finished.connect(self._on_worker_finished)
        self.scan_worker.start()

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
        self._refresh_campaign_view(keep_details=True)
        if route:
            metadata = route.get("campaign_metadata") or {}
            history_id = metadata.get("source_history_id") or route.get("id")
            self.history_manager.add_vulnerabilities_to_entry(history_id, vulnerabilities)
        self.refresh_vulnerabilities_requested.emit()

    def _on_scan_finished(self, total, total_added):
        self.status_label.setText(f"Scan finalizado. Rotas processadas: {total}. Novos achados: {total_added}.")
        self._append_log(f"\nScan finalizado. Novos achados: {total_added}.")
        self._refresh_campaign_view(keep_details=True)

    def _on_worker_finished(self):
        if self.scan_worker:
            self.scan_worker.deleteLater()
            self.scan_worker = None

    def _append_log(self, text):
        self.details_text.append(text)
        sb = self.details_text.verticalScrollBar()
        sb.setValue(sb.maximum())

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
                text.append(f"- [{vuln.get('severity')}] {vuln.get('type')} - {vuln.get('evidence', '')}")
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
