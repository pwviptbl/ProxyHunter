import asyncio
import queue
import sys
import threading
from urllib.parse import urlparse

from PySide6.QtCore import Signal, QAbstractTableModel, Qt, QTimer
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                               QPushButton, QLabel, QLineEdit, QGroupBox, QMessageBox, QTabWidget,
                               QTableView, QAbstractItemView, QGridLayout, QHeaderView, QDialog,
                               QScrollArea)

from mitmproxy import options
from mitmproxy.tools.dump import DumpMaster

from src.core.addon import InterceptAddon
from src.core.config import InterceptConfig, load_ai_config
from src.core.history import RequestHistory
from src.core.cookie_manager import CookieManager
from src.core.spider import Spider
from src.core.websocket_history import WebSocketHistory
from src.core.technology_manager import TechnologyManager
from src.core.active_scanner import ActiveScanner
from src.core.browser_manager import BrowserManager
from src.core.logger_config import log
from src.ui.widgets.proxy_control_widget import ProxyControlWidget
from src.ui.tabs.rules_tab import RulesTab
from src.ui.tabs.intercept_tab import InterceptTab
from src.ui.tabs.history_tab import HistoryTab
from src.ui.tabs.repeater_tab import RepeaterTab
from src.ui.tabs.attacker_tab import AttackerTab
from src.ui.tabs.decoder_tab import DecoderTab
from src.ui.tabs.jwt_editor_tab import JWTEditorTab
from src.ui.tabs.comparator_tab import ComparatorTab
from src.ui.tabs.cookie_jar_tab import CookieJarTab
from src.ui.tabs.scanner_tab import ScannerTab
from src.ui.tabs.spider_tab import SpiderTab
from src.ui.tabs.websocket_tab import WebSocketTab
from src.ui.tabs.technologies_tab import TechnologiesTab

from src.ui.dialogs.ai_config_dialog import AIConfigDialog
from src.ui.dialogs.generate_report_dialog import GenerateReportDialog
from src.ui.workers.report_worker import ReportWorker
from src.core.ai_reporter import AIReportGenerator
from src.core.local_reporter import LocalReportGenerator
from src.core.database import DatabaseManager

class ProxyGUI(QMainWindow):
    """Interface gráfica em PySide6 para o proxy interceptador."""

    proxy_stopped_signal = Signal()
    ui_update_signal = Signal(dict)
    browser_install_start_signal = Signal()
    browser_install_finish_signal = Signal()

    def __init__(self):
        super().__init__()

        self.proxy_stopped_signal.connect(self._set_proxy_stopped_state)
        self.ui_update_signal.connect(self._handle_ui_update)
        self.browser_install_start_signal.connect(self._on_browser_install_start)
        self.browser_install_finish_signal.connect(self._on_browser_install_finish)

        # Inicializa a lógica de negócio (backend)
        self.config = InterceptConfig()
        self.history = RequestHistory()
        self.cookie_manager = CookieManager()
        self.spider = Spider()
        self.websocket_history = WebSocketHistory()
        self.technology_manager = TechnologyManager()
        self.active_scanner = ActiveScanner(
            use_tor=self.config.get_tor_enabled(),
            tor_port=self.config.get_tor_port()
        )
        self.browser_manager = BrowserManager(
            proxy_port=self.config.get_port(),
            on_install_start=self.browser_install_start_signal.emit,
            on_install_finish=self.browser_install_finish_signal.emit
        )

        # Estado da aplicação
        self.proxy_thread = None
        self.proxy_running = False
        self.proxy_master = None
        self.proxy_loop = None
        self.ui_queue = queue.Queue()
        # Registra a fila de UI na configuração para que o addon possa enviar notificações
        self.config.set_ui_queue(self.ui_queue)
        self.websocket_history.set_ui_queue(self.ui_queue)
        # Também registra a fila no Spider para atualizações de estatísticas
        self.spider.set_ui_queue(self.ui_queue)

        self.setWindowTitle("ProxyHunter")
        screen = QGuiApplication.primaryScreen()
        if screen:
            available = screen.availableGeometry()
            self.resize(min(1200, available.width()), min(800, available.height()))
        else:
            self.resize(1200, 800)
        self.move(100, 100)

        # Configura o widget central e o layout principal
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)

        self.setup_ui()
        self.update_ui_state()

        # Inicia o timer para processar a fila de eventos da UI
        self.ui_queue_timer = QTimer()
        self.ui_queue_timer.timeout.connect(self._process_ui_queue)
        self.ui_queue_timer.start(100) # Verifica a cada 100ms

        # Timer para atualizar a aba de tecnologias
        self.tech_update_timer = QTimer(self)
        self.tech_update_timer.timeout.connect(self._update_technologies_tab)
        self.tech_update_timer.start(3000) # Atualiza a cada 3 segundos

    def _update_technologies_tab(self):
        """Busca os dados de tecnologias e atualiza a aba correspondente."""
        if self.proxy_running and hasattr(self, 'technologies_tab'):
            all_data = self.technology_manager.get_all_data()
            if all_data:
                self.technologies_tab.update_technologies(all_data)

    def setup_ui(self):
        """Configura os elementos da UI."""
        # 1. Configura a barra de menus
        self._setup_menu()

        # 2. Cria e adiciona o widget de controle do proxy
        self.control_widget = ProxyControlWidget(str(self.config.get_port()))
        self.control_widget.set_tor_enabled(self.config.get_tor_enabled())
        self.main_layout.addWidget(self.control_widget)

        # Conecta os sinais do widget aos slots da janela principal
        self.control_widget.start_proxy_requested.connect(self.start_proxy)
        self.control_widget.stop_proxy_requested.connect(self.stop_proxy)
        self.control_widget.toggle_pause_requested.connect(self.toggle_pause_proxy)
        self.control_widget.save_port_requested.connect(self.save_port)
        self.control_widget.launch_browser_requested.connect(self.launch_browser)
        self.control_widget.tor_toggled.connect(self.toggle_tor)

        # 3. Notebook com as abas
        self._setup_tabs()

    def _setup_menu(self):
        """Cria a barra de menus da aplicação."""
        self.menu_bar = self.menuBar()
        
        # Menu de Relatório
        report_menu = self.menu_bar.addMenu("Relatório")

        # Ação para gerar o relatório local
        generate_report_action = report_menu.addAction("Gerar local")
        generate_report_action.triggered.connect(lambda: self._open_generate_report_dialog(use_ai=False))

        # Ação para gerar o relatório com IA
        generate_ai_report_action = report_menu.addAction("Gerar com IA")
        generate_ai_report_action.triggered.connect(lambda: self._open_generate_report_dialog(use_ai=True))

        # Ação para configurar a IA
        config_ai_action = report_menu.addAction("Configurar IA")
        config_ai_action.triggered.connect(self._open_ai_config_dialog)

        # Menu de Sobre (ao lado do menu de Relatório)
        about_menu = self.menu_bar.addMenu("Sobre")
        
        # Ação para mostrar informações sobre o software
        about_action = about_menu.addAction("ProxyHunter")
        about_action.triggered.connect(self._show_about_dialog)

        # Menu de Banco (limpeza rápida)
        db_menu = self.menu_bar.addMenu("Banco")
        clear_db_action = db_menu.addAction("Limpar Banco")
        clear_db_action.triggered.connect(self._clear_database)

    def _setup_tabs(self):
        """Cria o sistema de abas."""
        self.tab_widget = QTabWidget()
        self.main_layout.addWidget(self.tab_widget)
        self._tab_wrappers = {}

        def wrap_tab(widget: QWidget) -> QWidget:
            scroll = QScrollArea()
            scroll.setWidgetResizable(True)
            scroll.setWidget(widget)
            self._tab_wrappers[widget] = scroll
            return scroll

        def add_tab(widget: QWidget, label: str):
            self.tab_widget.addTab(wrap_tab(widget), label)

        # Cria e adiciona a aba de regras
        rules_tab = RulesTab(self.config)
        add_tab(rules_tab, "Regras")

        # Cria e adiciona a aba de interceptação
        self.intercept_tab = InterceptTab()
        self.intercept_tab.toggle_intercept_requested.connect(self.toggle_intercept)
        self.intercept_tab.forward_requested.connect(self.forward_request)
        self.intercept_tab.drop_requested.connect(self.drop_request)
        add_tab(self.intercept_tab, "Intercept")

        # Cria e adiciona a aba de histórico
        self.history_tab = HistoryTab(self.history, self.config)
        self.history_tab.send_to_repeater_requested.connect(self.send_to_repeater)
        self.history_tab.send_to_attacker_requested.connect(self.send_to_attacker)
        self.history_tab.set_comparator_request_1_requested.connect(self.set_comparator_request_1)
        self.history_tab.set_comparator_request_2_requested.connect(self.set_comparator_request_2)
        self.history_tab.clear_history_requested.connect(self._clear_history)
        self.history_tab.add_host_to_scope_requested.connect(self._add_host_to_scope)
        self.history_tab.send_to_jwt_editor_requested.connect(self.send_to_jwt_editor)
        add_tab(self.history_tab, "Histórico")

        # Cria e adiciona a aba de repetição
        self.repeater_tab = RepeaterTab(self.cookie_manager)
        add_tab(self.repeater_tab, "Repetição")

        # Cria e adiciona a aba de attacker
        self.attacker_tab = AttackerTab(self.cookie_manager, self.history)
        add_tab(self.attacker_tab, "Attacker")
        
        # Cria e adiciona a aba de decoder
        self.decoder_tab = DecoderTab()
        add_tab(self.decoder_tab, "Decoder")
        
        # Cria e adiciona a aba do Editor de JWT
        self.jwt_editor_tab = JWTEditorTab()
        self.jwt_editor_tab.send_to_repeater_requested.connect(self.send_to_repeater)
        add_tab(self.jwt_editor_tab, "JWT Editor")

        # Cria e adiciona a aba de comparador
        self.comparator_tab = ComparatorTab()
        add_tab(self.comparator_tab, "Comparador")
        
        # Cria e adiciona a aba do Cookie Jar
        self.cookie_jar_tab = CookieJarTab(self.cookie_manager)
        add_tab(self.cookie_jar_tab, "Cookie")
        
        # Cria e adiciona a aba do Scanner
        self.scanner_tab = ScannerTab(self.history, self.active_scanner)
        add_tab(self.scanner_tab, "Scanner")
        
        # Cria e adiciona a aba do Spider/Crawler
        self.spider_tab = SpiderTab(self.spider, self.config)
        add_tab(self.spider_tab, "Spider")
        
        # Cria e adiciona a aba de WebSocket
        self.websocket_tab = WebSocketTab(self.websocket_history)
        add_tab(self.websocket_tab, "WebSocket")
        


        # Cria e adiciona a aba de Tecnologias
        self.technologies_tab = TechnologiesTab()
        add_tab(self.technologies_tab, "Tecnologias")

        # Conecta os sinais entre as abas após todas terem sido criadas
        self.history_tab.scan_requested.connect(self.scanner_tab.start_scan_from_request)

    def _show_tab(self, widget: QWidget):
        """Exibe a aba correta mesmo quando está envolvida por QScrollArea."""
        tab_widget = self._tab_wrappers.get(widget, widget)
        self.tab_widget.setCurrentWidget(tab_widget)

    def start_proxy(self):
        """Inicia o servidor proxy em uma thread separada."""
        if self.proxy_running:
            QMessageBox.warning(self, "Aviso", "Proxy já está em execução!")
            return

        log.info("Proxy (PySide6) iniciando...")

        def run_proxy():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            async def runner():
                try:
                    port = self.config.get_port()
                    proxy_options = options.Options(listen_host='127.0.0.1', listen_port=port)
                    master = DumpMaster(proxy_options, with_termlog=False, with_dumper=False)

                    addon = InterceptAddon(
                        self.config, self.history, self.cookie_manager,
                        self.spider, self.websocket_history, self.technology_manager
                    )
                    master.addons.add(addon)

                    self.proxy_master = master
                    self.proxy_loop = loop
                    await master.run()
                except Exception as err:
                    log.error(f"Falha ao iniciar o proxy (PySide6): {err}", exc_info=True)
                finally:
                    self.proxy_master = None
                    self.proxy_loop = None
                    # Emite o sinal para a thread principal atualizar a UI
                    self.proxy_stopped_signal.emit()

            loop.run_until_complete(runner())

        self.proxy_thread = threading.Thread(target=run_proxy, daemon=True)
        self.proxy_thread.start()
        self.proxy_running = True
        self.update_ui_state()

        #QMessageBox.information(self, "Proxy Iniciado", f"Proxy iniciado na porta {self.config.get_port()}")

    def stop_proxy(self):
        """Para o servidor proxy."""
        if not self.proxy_running or not self.proxy_master:
            QMessageBox.information(self, "Proxy", "Proxy já está parado.")
            return

        log.info("Proxy (PySide6) finalizando...")
        if self.proxy_master and self.proxy_loop:
            self.proxy_loop.call_soon_threadsafe(self.proxy_master.shutdown)

        # A UI será atualizada quando a thread do proxy terminar e chamar _set_proxy_stopped_state

    def _set_proxy_stopped_state(self):
        """Atualiza a UI para o estado de proxy parado."""
        self.proxy_running = False
        self.update_ui_state()

    def toggle_pause_proxy(self):
        """Alterna o estado de pausa do proxy."""
        is_paused = self.config.toggle_pause()
        log.info(f"Proxy pausado: {is_paused}")
        self.update_ui_state()

    def save_port(self, port_str: str):
        """Salva a porta configurada."""
        success, message = self.config.set_port(port_str)
        if success:
            QMessageBox.information(self, "Sucesso", message)
        else:
            QMessageBox.warning(self, "Erro", message)
            self.control_widget.set_port_text(str(self.config.get_port()))

    def toggle_tor(self, enabled: bool):
        """Habilita/desabilita o uso do TOR."""
        self.config.set_tor_enabled(enabled)
        status = "habilitado" if enabled else "desabilitado"
        log.info(f"TOR {status}")
        QMessageBox.information(self, "TOR", f"TOR {status} com sucesso!")

    def launch_browser(self):
        """Abre o navegador pré-configurado."""
        if not self.proxy_running:
            QMessageBox.warning(self, "Aviso", "O proxy precisa estar em execução para abrir o navegador.")
            return

        log.info("PySide6 GUI: Solicitando abertura do navegador...")
        self.browser_manager.launch_browser()

    def _clear_database(self):
        """Limpa as tabelas do banco (RequestNodes e InjectionPoints)."""
        reply = QMessageBox.question(
            self,
            "Confirmar",
            "Deseja limpar todas as tabelas do banco (RequestNodes e InjectionPoints)?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            try:
                db = DatabaseManager('data/target.db')
                db.clear_all()
                QMessageBox.information(self, "Banco", "Tabelas limpas com sucesso!")
            except Exception as e:
                QMessageBox.critical(self, "Erro", f"Falha ao limpar banco: {e}")

    def update_ui_state(self):
        """Atualiza o estado dos widgets da UI."""
        self.control_widget.set_proxy_running(self.proxy_running)
        if self.proxy_running:
            self.control_widget.set_proxy_paused(self.config.is_paused())

    def closeEvent(self, event):
        """Handler para o fechamento da janela."""
        log.info("PySide6 GUI: Fechando aplicação...")
        # Adicionar lógica para parar o proxy se estiver rodando
        if self.proxy_running:
            self.stop_proxy()
        if hasattr(self, 'scanner_tab'):
            self.scanner_tab.stop_active_scan()
        event.accept()

    # --- Slots para Sinais do Navegador ---
    def _on_browser_install_start(self):
        """Atualiza a UI quando a instalação do navegador começa."""
        self.control_widget.set_browser_installing()

    def _on_browser_install_finish(self):
        """Atualiza a UI quando a instalação do navegador termina."""
        self.control_widget.set_browser_installed()

    # --- Processamento de Eventos da UI ---
    def _process_ui_queue(self):
        """Verifica a fila de eventos e emite um sinal para a thread principal."""
        try:
            while not self.ui_queue.empty():
                message = self.ui_queue.get_nowait()
                self.ui_update_signal.emit(message)
        except queue.Empty:
            pass

    def _handle_ui_update(self, message):
        """Recebe o sinal e atualiza a UI na thread principal."""
        msg_type = message.get("type")
        data = message.get("data")

        if msg_type == "new_history_entry":
            self.history_tab.add_history_entry(data)
            # Atualiza a lista de vulnerabilidades se houver vulnerabilidades detectadas
            if data.get('vulnerabilities'):
                self.scanner_tab.refresh_vulnerabilities()
        elif msg_type == "intercepted_request":
            self.intercept_tab.display_request(data)
            self._show_tab(self.intercept_tab)
        elif msg_type == "update_spider_stats":
            if hasattr(self, 'spider_tab'):
                self.spider_tab.apply_stats(data)
        elif msg_type == "update_websocket_list":
            # WebSocket tab has auto-refresh timer, but we can also manually trigger update
            if hasattr(self, 'websocket_tab'):
                self.websocket_tab._update_websocket_list()

    # --- Lógica da Aba de Interceptação ---
    def toggle_intercept(self):
        """Alterna o estado de interceptação manual."""
        if not self.proxy_running:
            QMessageBox.warning(self, "Aviso", "Inicie o proxy primeiro.")
            self.intercept_tab.set_intercept_state(False)
            return

        is_enabled = self.config.toggle_intercept()
        self.intercept_tab.set_intercept_state(is_enabled)
        log.info(f"Interceptação manual alterada para: {is_enabled}")

    def forward_request(self, modified_data: dict):
        """Envia a requisição interceptada (com possíveis modificações)."""
        response_data = {
            'action': 'forward',
            **modified_data
        }
        self.config.add_intercept_response(response_data)
        self.intercept_tab.reset_ui()
        log.info("Requisição interceptada enviada (forward).")

    def drop_request(self):
        """Cancela a requisição interceptada."""
        response_data = {'action': 'drop'}
        self.config.add_intercept_response(response_data)
        self.intercept_tab.reset_ui()
        log.info("Requisição interceptada cancelada (drop).")

    # --- Lógica da Aba de Histórico ---
    def send_to_repeater(self, entry: dict):
        """Envia uma requisição do histórico para a aba de repetição."""
        log.info(f"Enviando requisição {entry['id']} para o Repeater.")
        self.repeater_tab.set_request_data(entry)
        self._show_tab(self.repeater_tab)

    def send_to_attacker(self, entry: dict):
        """Envia uma requisição do histórico para a aba de attacker."""
        log.info(f"Enviando requisição {entry['id']} para o Attacker.")
        self.attacker_tab.set_request_data(entry)
        self._show_tab(self.attacker_tab)

    def send_to_jwt_editor(self, token: str, entry: dict):
        """Envia um JWT e a entrada da requisição para o editor de JWT."""
        log.info(f"Enviando JWT da requisição {entry['id']} para o Editor de JWT.")
        self.jwt_editor_tab.set_request_data(token, entry)
        self._show_tab(self.jwt_editor_tab)

    def _add_host_to_scope(self, host: str):
        """Adiciona um host à lista de escopo."""
        parsed = urlparse(host) if "://" in host else urlparse(f"//{host}")
        host_only = parsed.hostname or host
        host_with_port = parsed.netloc or host_only
        if not host_only:
            log.warning("Host inválido para escopo.")
            return

        if self.config.add_to_scope(host_only):
            log.info(f"Host '{host_only}' adicionado ao escopo.")
            QMessageBox.information(self, "Escopo", f"Host '{host_only}' adicionado ao escopo.")
        else:
            log.info(f"Host '{host_only}' já está no escopo.")

        # Sempre atualiza a URL inicial do Spider, preservando a porta se existir.
        if hasattr(self, 'spider_tab'):
            self.spider_tab.set_initial_url(host_with_port)

    def _clear_history(self):
        """Limpa o histórico de requisições."""
        # Esvazia a fila de eventos para evitar race conditions
        while not self.ui_queue.empty():
            try:
                self.ui_queue.get_nowait()
            except queue.Empty:
                break

        self.history.clear_history()
        self.history_tab.clear_display()
        log.info("Histórico de requisições limpo.")
        #QMessageBox.information(self, "Sucesso", "Histórico limpo com sucesso!")

    # --- Lógica da Aba de Comparador ---
    def set_comparator_request_1(self, entry: dict):
        """Define a primeira requisição para comparação."""
        log.info(f"Definindo requisição {entry['id']} como Requisição 1 no Comparador.")
        self.comparator_tab.set_comparator_request_1(entry)
        self._show_tab(self.comparator_tab)

    def set_comparator_request_2(self, entry: dict):
        """Define a segunda requisição para comparação."""
        log.info(f"Definindo requisição {entry['id']} como Requisição 2 no Comparador.")
        self.comparator_tab.set_comparator_request_2(entry)
        self._show_tab(self.comparator_tab)

    # --- Lógica do Menu de Relatório ---
    def _open_ai_config_dialog(self):
        """Abre a janela de diálogo para configurar a IA."""
        dialog = AIConfigDialog(self)
        if dialog.exec():
            # A configuração agora é salva pelo próprio diálogo.
            QMessageBox.information(self, "Sucesso", "Configuração da IA salva com sucesso!")
            log.info("Configuração da IA salva com sucesso.")

    def _open_generate_report_dialog(self, use_ai=False):
        """Abre o diálogo para configurar e iniciar a geração de relatórios."""
        # Verifica se há dados para gerar o relatório
        history_count = len(self.history.get_history())
        
        if history_count == 0:
            QMessageBox.warning(
                self, 
                "Aviso", 
                "Não há dados no histórico para gerar um relatório.\n\n"
                "Certifique-se de que:\n"
                "1. O proxy está em execução\n"
                "2. Você capturou algumas requisições HTTP\n"
                "3. Há entradas na aba 'Histórico'"
            )
            return
        
        # Verifica configuração da IA quando solicitado
        if use_ai:
            ai_config = load_ai_config()
            if not ai_config.get("api_key"):
                QMessageBox.warning(
                    self,
                    "Aviso",
                    "A chave de API da IA não está configurada.\n\n"
                    "Por favor, configure-a no menu 'Relatório -> Configurar IA'."
                )
                return

        log.info(f"Abrindo diálogo de geração de relatório ({history_count} entradas no histórico)")
        
        scope_hosts = self.config.get_scope()
        dialog_title = "Gerar Relatório com IA" if use_ai else "Gerar Relatório"
        dialog = GenerateReportDialog(self, scope_hosts=scope_hosts, title=dialog_title)
        if dialog.exec():
            filters = dialog.get_filters()
            self._start_report_generation(filters, use_ai=use_ai)

    def _start_report_generation(self, filters, use_ai=False):
        """Inicia a geração do relatório em uma thread separada."""
        log.info("Iniciando geração de relatório...")
        log.info(f"Filtros aplicados: {filters}")
        
        # 1. Coletar e filtrar os dados
        all_history = self.history.get_history()
        log.info(f"Total de entradas no histórico: {len(all_history)}")
        
        filtered_history = self._filter_history(all_history, filters)
        log.info(f"Entradas após filtro: {len(filtered_history)}")

        if not filtered_history:
            QMessageBox.warning(self, "Aviso", "Nenhum dado do histórico corresponde aos filtros selecionados. Nenhum relatório será gerado.")
            return

        # Dados para o prompt, agora com o histórico filtrado
        vulnerabilities = self._collect_vulnerabilities()
        technologies = self.technology_manager.get_all_data()
        
        log.info(f"Vulnerabilidades coletadas: {len(vulnerabilities)}")
        log.info(f"Tecnologias coletadas: {len(technologies)}")
        
        report_data = {
            "history": filtered_history,
            "vulnerabilities": vulnerabilities,
            "technologies": technologies
        }

        # 2. Configurar e iniciar o worker
        if use_ai:
            ai_config = load_ai_config()
            log.info(f"API Key configurada: {'Sim' if ai_config.get('api_key') else 'Não'}")
            log.info(f"Modelo: {ai_config.get('model')}")

            report_generator = AIReportGenerator(api_key=ai_config['api_key'], model_name=ai_config['model'])
            prompt = ai_config['prompt']
        else:
            report_generator = LocalReportGenerator()
            prompt = ""

        self.report_worker = ReportWorker(report_generator, report_data, prompt)
        self.report_worker.report_finished.connect(self._on_report_finished)
        self.report_worker.report_error.connect(self._on_report_error)
        self.report_worker.start()
        
        QMessageBox.information(self, "Gerando Relatório", "A geração do relatório foi iniciada. Você será notificado quando estiver concluída.")
        log.info("Worker de geração iniciado.")

    def _on_report_finished(self, filepath):
        """Chamado quando o relatório é gerado com sucesso."""
        log.info(f"Relatório salvo em: {filepath}")
        QMessageBox.information(self, "Sucesso", f"Relatório gerado e salvo com sucesso em:\n{filepath}")

    def _on_report_error(self, error_message):
        """Chamado quando ocorre um erro na geração do relatório."""
        log.error(f"Erro ao gerar relatório: {error_message}")
        QMessageBox.critical(self, "Erro", f"Ocorreu um erro ao gerar o relatório:\n{error_message}")

    def _filter_history(self, history, filters):
        """Filtra o histórico de requisições com base nos critérios fornecidos."""
        from urllib.parse import urlparse
        import fnmatch

        domain_pattern = filters.get('domain')
        status_patterns = filters.get('status_code', '').replace('x', '*').split(',')
        methods = filters.get('methods', [])

        filtered_entries = []
        for entry in history:
            # 1. Filtro de Método
            if entry['method'] not in methods:
                continue

            # 2. Filtro de Domínio
            if domain_pattern:
                hostname = urlparse(entry['url']).hostname
                if not hostname or not fnmatch.fnmatch(hostname, domain_pattern.strip()):
                    continue

            # 3. Filtro de Status Code
            status_match = False
            if not any(p.strip() for p in status_patterns):
                 status_match = True # Se o filtro de status estiver vazio, corresponde a tudo
            else:
                for pattern in status_patterns:
                    if fnmatch.fnmatch(str(entry['status']), pattern.strip()):
                        status_match = True
                        break

            if not status_match:
                continue

            filtered_entries.append(entry)

        return filtered_entries

    def _collect_vulnerabilities(self):
        """Coleta todas as vulnerabilidades do histórico de requisições."""
        vulnerabilities_dict = {}
        
        for entry in self.history.get_history():
            if entry.get('vulnerabilities'):
                for vuln in entry['vulnerabilities']:
                    vuln_type = vuln.get('type', 'Unknown')
                    
                    # Agrupa por tipo de vulnerabilidade
                    if vuln_type not in vulnerabilities_dict:
                        vulnerabilities_dict[vuln_type] = []
                    
                    # Adiciona detalhes da vulnerabilidade
                    vuln_detail = {
                        'url': vuln.get('url', entry.get('url', 'N/A')),
                        'method': vuln.get('method', entry.get('method', 'N/A')),
                        'severity': vuln.get('severity', 'Unknown'),
                        'source': vuln.get('source', 'Unknown'),
                        'evidence': vuln.get('evidence', 'N/A'),
                        'description': vuln.get('description', 'N/A')
                    }
                    
                    vulnerabilities_dict[vuln_type].append(vuln_detail)
        
        log.info(f"Vulnerabilidades agrupadas por tipo: {list(vulnerabilities_dict.keys())}")
        return vulnerabilities_dict

    def _show_about_dialog(self):
        """Mostra o diálogo com informações sobre o software."""
        # Importar o AboutTab aqui para evitar problemas de ciclo de importação
        from src.ui.tabs.about_tab import AboutTab
        
        # Criar um diálogo com o conteúdo do AboutTab
        dialog = QDialog(self)
        dialog.setWindowTitle("Sobre o ProxyHunter")
        dialog.setGeometry(200, 200, 800, 600)
        
        # Criar uma instância do AboutTab e adicioná-la ao diálogo
        about_tab = AboutTab()
        
        # Layout para o diálogo
        layout = QVBoxLayout(dialog)
        layout.addWidget(about_tab)
        
        # Botão de fechar
        close_button = QPushButton("Fechar")
        close_button.clicked.connect(dialog.close)
        layout.addWidget(close_button)
        
        dialog.exec()
