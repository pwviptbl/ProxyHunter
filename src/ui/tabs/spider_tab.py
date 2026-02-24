from PySide6.QtCore import Qt, Signal, QTimer
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QPushButton, QLabel, QLineEdit,
                               QGroupBox, QHBoxLayout, QListWidget, QTextEdit,
                               QTabWidget, QTreeWidget, QTreeWidgetItem, QHeaderView,
                               QMessageBox, QFileDialog, QGridLayout)

from src.core.spider import Spider
from src.core.logger_config import log


class SpiderTab(QWidget):
    """Aba de UI para o Spider/Crawler."""

    def __init__(self, spider: Spider, config):
        super().__init__()
        self.spider = spider
        self.config = config
        self._last_discovered = 0
        self._last_forms = 0

        layout = QVBoxLayout(self)

        # Frame de controle
        self._setup_control_section(layout)

        # Configurações
        self._setup_config_section(layout)

        # Estatísticas
        self._setup_stats_section(layout)

        # Resultados
        self._setup_results_section(layout)

        # Timer para atualizar estatísticas
        self.stats_timer = QTimer()
        self.stats_timer.timeout.connect(self._update_stats)
        self.stats_timer.start(2000)  # Atualiza a cada 2 segundos

        # Set initial URL from scope
        scope = self.config.get_scope()
        if scope:
            self.set_initial_url(scope[0])

    def _setup_control_section(self, layout):
        """Configura a seção de controle do Spider."""
        control_group = QGroupBox("Controle do Spider")
        control_layout = QVBoxLayout()

        # Status
        status_layout = QHBoxLayout()
        status_layout.addWidget(QLabel("Status:"))
        self.status_label = QLabel("Parado")
        self.status_label.setStyleSheet("color: red;")
        status_layout.addWidget(self.status_label)
        status_layout.addStretch()
        control_layout.addLayout(status_layout)

        # Botões de controle
        buttons_layout = QHBoxLayout()
        
        self.start_button = QPushButton("▶ Iniciar Spider")
        self.start_button.clicked.connect(self._start_spider)
        buttons_layout.addWidget(self.start_button)

        self.stop_button = QPushButton("⏹ Parar Spider")
        self.stop_button.clicked.connect(self._stop_spider)
        self.stop_button.setEnabled(False)
        buttons_layout.addWidget(self.stop_button)

        self.clear_button = QPushButton("🗑 Limpar Dados")
        self.clear_button.clicked.connect(self._clear_spider)
        buttons_layout.addWidget(self.clear_button)

        buttons_layout.addStretch()
        control_layout.addLayout(buttons_layout)

        control_group.setLayout(control_layout)
        layout.addWidget(control_group)

    def _setup_config_section(self, layout):
        """Configura a seção de configurações."""
        config_group = QGroupBox("Configurações")
        config_layout = QGridLayout()

        # URL inicial
        config_layout.addWidget(QLabel("URL Inicial (escopo):"), 0, 0)
        self.url_entry = QLineEdit()
        self.url_entry.setPlaceholderText("URLs base para inciar o crawling (separadas por vírgula)")
        config_layout.addWidget(self.url_entry, 0, 1)

        # Profundidade máxima
        config_layout.addWidget(QLabel("Profundidade Máxima:"), 1, 0)
        self.depth_entry = QLineEdit()
        self.depth_entry.setText("3")
        self.depth_entry.setPlaceholderText("Número máximo de níveis de links")
        config_layout.addWidget(self.depth_entry, 1, 1)

        # Máximo de URLs
        config_layout.addWidget(QLabel("Máximo de URLs:"), 2, 0)
        self.max_urls_entry = QLineEdit()
        self.max_urls_entry.setText("1000")
        self.max_urls_entry.setPlaceholderText("Número máximo de URLs a descobrir")
        config_layout.addWidget(self.max_urls_entry, 2, 1)

        config_layout.setColumnStretch(1, 1)
        config_group.setLayout(config_layout)
        layout.addWidget(config_group)

    def _setup_stats_section(self, layout):
        """Configura a seção de estatísticas."""
        stats_group = QGroupBox("Estatísticas")
        stats_layout = QVBoxLayout()

        self.stats_label = QLabel("URLs Descobertas: 0 | Na Fila: 0 | Visitadas: 0 | Formulários: 0")
        stats_layout.addWidget(self.stats_label)

        stats_group.setLayout(stats_layout)
        layout.addWidget(stats_group)

    def _setup_results_section(self, layout):
        """Configura a seção de resultados com abas."""
        results_tabs = QTabWidget()

        # Tab 1: URLs Descobertas
        urls_widget = self._create_urls_tab()
        results_tabs.addTab(urls_widget, "URLs Descobertas")

        # Tab 2: Formulários
        forms_widget = self._create_forms_tab()
        results_tabs.addTab(forms_widget, "Formulários")

        # Tab 3: Sitemap
        sitemap_widget = self._create_sitemap_tab()
        results_tabs.addTab(sitemap_widget, "Sitemap")

        layout.addWidget(results_tabs)

    def _create_urls_tab(self):
        """Cria a aba de URLs descobertas."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Barra de ferramentas
        toolbar = QHBoxLayout()
        
        refresh_button = QPushButton("↻ Atualizar")
        refresh_button.clicked.connect(self._refresh_urls)
        toolbar.addWidget(refresh_button)

        copy_button = QPushButton("📋 Copiar Todas")
        copy_button.clicked.connect(self._copy_all_urls)
        toolbar.addWidget(copy_button)

        toolbar.addStretch()
        layout.addLayout(toolbar)

        # Lista de URLs
        self.urls_list = QListWidget()
        layout.addWidget(self.urls_list)

        return widget

    def _create_forms_tab(self):
        """Cria a aba de formulários."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Barra de ferramentas
        toolbar = QHBoxLayout()
        
        refresh_button = QPushButton("↻ Atualizar")
        refresh_button.clicked.connect(self._refresh_forms)
        toolbar.addWidget(refresh_button)

        toolbar.addStretch()
        layout.addLayout(toolbar)

        # TreeView para formulários
        self.forms_tree = QTreeWidget()
        self.forms_tree.setHeaderLabels(["Método", "URL do Formulário", "Campos"])
        self.forms_tree.header().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self.forms_tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.forms_tree)

        return widget

    def _create_sitemap_tab(self):
        """Cria a aba de sitemap."""
        widget = QWidget()
        layout = QVBoxLayout(widget)

        # Barra de ferramentas
        toolbar = QHBoxLayout()
        
        refresh_button = QPushButton("↻ Atualizar")
        refresh_button.clicked.connect(self._refresh_sitemap)
        toolbar.addWidget(refresh_button)

        export_button = QPushButton("💾 Exportar")
        export_button.clicked.connect(self._export_sitemap)
        toolbar.addWidget(export_button)

        toolbar.addStretch()
        layout.addLayout(toolbar)

        # Área de texto para sitemap
        self.sitemap_text = QTextEdit()
        self.sitemap_text.setReadOnly(True)
        self.sitemap_text.setFontFamily("Courier")
        layout.addWidget(self.sitemap_text)

        return widget

    def set_initial_url(self, host: str):
        """Define ou adiciona a URL inicial no campo de entrada."""
        current_text = self.url_entry.text().strip()
        new_url = f"http://{host}"
        
        if not current_text:
            self.url_entry.setText(new_url)
        else:
            # Check if it's already in the list to avoid duplicates
            urls = [u.strip() for u in current_text.split(',')]
            if new_url not in urls:
                self.url_entry.setText(f"{current_text}, {new_url}")

    def _start_spider(self):
        """Inicia o Spider."""
        # Validação: precisa ter proxy rodando (assumindo que já está)
        # Esta validação seria feita pela GUI principal se necessário
        
        if self.spider.is_running():
            QMessageBox.warning(self, "Aviso", "Spider já está em execução!")
            return

        # Obtém configurações
        urls_text = self.url_entry.text().strip()
        if not urls_text:
            QMessageBox.critical(self, "Erro", "Digite pelo menos uma URL inicial!")
            return
            
        target_urls = [u.strip() for u in urls_text.split(',') if u.strip()]

        try:
            max_depth = int(self.depth_entry.text())
            max_urls = int(self.max_urls_entry.text())
        except ValueError:
            QMessageBox.critical(self, "Erro", "Valores numéricos inválidos!")
            return

        # Inicia o spider
        self.spider.start(target_urls=target_urls, max_depth=max_depth, max_urls=max_urls)

        # Atualiza UI
        self.status_label.setText("Em Execução")
        self.status_label.setStyleSheet("color: green;")
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)

        log.info(f"Spider iniciado com URLs: {target_urls}")
        #QMessageBox.information( self,  "Spider",   f"Spider iniciado!\nURLs: {target_urls}\nNavegue no site para descobrir páginas." )

    def _stop_spider(self):
        """Para o Spider."""
        self.spider.stop()

        # Atualiza UI
        self.status_label.setText("Parado")
        self.status_label.setStyleSheet("color: red;")
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)

        log.info("Spider parado")
        QMessageBox.information(self, "Spider", "Spider parado!")

    def _clear_spider(self):
        """Limpa os dados do Spider."""
        reply = QMessageBox.question(
            self,
            "Confirmar",
            "Deseja limpar todos os dados do Spider?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            self.spider.clear()

            # Limpa UI
            self.urls_list.clear()
            self.forms_tree.clear()
            self.sitemap_text.clear()
            self._last_discovered = 0
            self._last_forms = 0

            self.status_label.setText("Parado")
            self.status_label.setStyleSheet("color: red;")
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)

            log.info("Dados do Spider limpos")

    def _update_stats(self):
        """Atualiza as estatísticas do Spider."""
        stats = self.spider.get_stats()
        self.apply_stats(stats)

    def apply_stats(self, stats: dict):
        """Aplica estatísticas e atualiza a UI quando necessário."""
        if not stats:
            return
        self.stats_label.setText(
            f"URLs Descobertas: {stats.get('discovered_urls', 0)} | "
            f"Na Fila: {stats.get('queue_size', 0)} | "
            f"Visitadas: {stats.get('visited', 0)} | "
            f"Formulários: {stats.get('forms', 0)}"
        )
        discovered = stats.get('discovered_urls', 0)
        forms = stats.get('forms', 0)
        if discovered != self._last_discovered:
            self._refresh_urls()
            self._refresh_sitemap()
            self._last_discovered = discovered
        if forms != self._last_forms:
            self._refresh_forms()
            self._last_forms = forms

    def _refresh_urls(self):
        """Atualiza a lista de URLs descobertas."""
        self.urls_list.clear()

        urls = self.spider.get_discovered_urls()
        for url in urls:
            self.urls_list.addItem(url)

        log.info(f"Lista de URLs atualizada: {len(urls)} URLs")

    def _copy_all_urls(self):
        """Copia todas as URLs para a área de transferência."""
        urls = self.spider.get_discovered_urls()
        if urls:
            from PySide6.QtWidgets import QApplication
            urls_text = "\n".join(urls)
            clipboard = QApplication.clipboard()
            clipboard.setText(urls_text)
            QMessageBox.information(
                self,
                "Copiado",
                f"{len(urls)} URLs copiadas para a área de transferência!"
            )
        else:
            QMessageBox.warning(self, "Aviso", "Nenhuma URL descoberta ainda!")

    def _refresh_forms(self):
        """Atualiza a lista de formulários."""
        self.forms_tree.clear()

        forms = self.spider.get_forms()
        for form in forms:
            inputs_str = ", ".join([
                f"{inp['name']}({inp['type']})" 
                for inp in form['inputs'] 
                if inp['name']
            ])
            
            item = QTreeWidgetItem([
                form['method'],
                form['url'],
                inputs_str
            ])
            self.forms_tree.addTopLevelItem(item)

        log.info(f"Lista de formulários atualizada: {len(forms)} formulários")

    def _refresh_sitemap(self):
        """Atualiza o sitemap."""
        self.sitemap_text.clear()
        sitemap_text = self.spider.export_sitemap_text()
        self.sitemap_text.setPlainText(sitemap_text)

        log.info("Sitemap atualizado")

    def _export_sitemap(self):
        """Exporta o sitemap para arquivo."""
        filename, _ = QFileDialog.getSaveFileName(
            self,
            "Exportar Sitemap",
            "",
            "Text Files (*.txt);;All Files (*)"
        )

        if filename:
            try:
                sitemap_text = self.spider.export_sitemap_text()
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(sitemap_text)
                QMessageBox.information(
                    self,
                    "Sucesso",
                    f"Sitemap exportado para:\n{filename}"
                )
                log.info(f"Sitemap exportado para: {filename}")
            except Exception as e:
                QMessageBox.critical(
                    self,
                    "Erro",
                    f"Erro ao exportar sitemap:\n{str(e)}"
                )
                log.error(f"Erro ao exportar sitemap: {e}")
