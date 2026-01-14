from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QGroupBox, QTextEdit, QLabel, QScrollArea
)
from PySide6.QtCore import Qt

class AboutTab(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)

        # Layout principal vertical
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(10, 5, 10, 5)

        # Área de scroll para conteúdo longo
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
        scroll_area.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)

        # Widget container para o conteúdo
        content_widget = QWidget()
        content_layout = QVBoxLayout(content_widget)

        # Resumo Executivo
        executive_summary_group = QGroupBox("Resumo Executivo")
        executive_layout = QVBoxLayout()

        executive_text = QTextEdit()
        executive_text.setReadOnly(True)
        executive_text.setPlainText(
            "O ProxyHunter é uma ferramenta avançada de proxy de interceptação HTTP desenvolvida para profissionais de segurança da informação, "
            "testadores de penetração e desenvolvedores que necessitam de controle granular sobre o tráfego HTTP/S entre aplicações cliente e servidores.\n\n"
            "A ferramenta permite interceptar, modificar e analisar requisições e respostas HTTP em tempo real, oferecendo um conjunto completo de "
            "funcionalidades para testes de segurança, depuração de aplicações web e análise de protocolos de comunicação.\n\n"
            "Com uma interface gráfica intuitiva construída em PySide6, o ProxyHunter combina a potência de ferramentas como Burp Suite com a "
            "flexibilidade de uma solução open-source, permitindo aos usuários configurar regras personalizadas de interceptação, executar "
            "varreduras automatizadas de vulnerabilidades, realizar crawling de aplicações web e muito mais.\n\n"
            "Ideal para:\n"
            "• Testes de penetração e avaliação de segurança\n"
            "• Desenvolvimento e depuração de aplicações web\n"
            "• Análise de protocolos e APIs\n"
            "• Ensino e treinamento em segurança da informação"
        )
        executive_layout.addWidget(executive_text)
        executive_summary_group.setLayout(executive_layout)
        content_layout.addWidget(executive_summary_group)

        # Parte Técnica
        technical_group = QGroupBox("Aspectos Técnicos do Software")
        technical_layout = QVBoxLayout()

        technical_text = QTextEdit()
        technical_text.setReadOnly(True)
        technical_text.setPlainText(
            "ARQUITETURA DO SISTEMA\n\n"
            "O ProxyHunter opera como um proxy man-in-the-middle (MITM) baseado no framework mitmproxy, interceptando todo o tráfego HTTP/S "
            "entre o cliente (navegador) e o servidor alvo. A arquitetura é composta por três camadas principais:\n\n"
            "1. Camada de Interceptação: Utiliza mitmproxy como engine principal para captura e manipulação de pacotes HTTP/S\n"
            "2. Camada de Processamento: Addon personalizado que implementa a lógica de regras de interceptação e modificação\n"
            "3. Camada de Interface: GUI em PySide6 que fornece controle visual sobre todas as operações\n\n"
            "MECANISMO DE INTERCEPTAÇÃO\n\n"
            "• Interceptação Baseada em Regras: O sistema permite configurar regras específicas por domínio, caminho e parâmetro\n"
            "• Suporte a Múltiplos Métodos: Compatível com GET (query strings) e POST (form data e JSON)\n"
            "• Modificação Seletiva: Altera apenas os parâmetros especificados, preservando a integridade da requisição\n"
            "• Controle de Fluxo: Forward/Drop manual para análise detalhada de requisições interceptadas\n\n"
            "FUNCIONALIDADES AVANÇADAS\n\n"
            "Scanner de Vulnerabilidades:\n"
            "• Scanner Passivo: Análise de respostas HTTP para detecção de vulnerabilidades comuns\n"
            "• Scanner Ativo: Injeção de payloads para testes de SQL Injection, XSS e outras vulnerabilidades\n"
            "• Detecção de CVEs: Identificação de vulnerabilidades conhecidas em componentes web\n\n"
            "Spider/Crawler:\n"
            "• Descoberta Automática: Mapeamento completo da estrutura da aplicação web\n"
            "• Extração de Formulários: Identificação de pontos de entrada para dados do usuário\n"
            "• Análise de Parâmetros: Detecção de query strings e parâmetros ocultos\n\n"
            "WebSocket Support:\n"
            "• Monitoramento em Tempo Real: Captura de mensagens WebSocket bidirecionais\n"
            "• Suporte a Protocolos: Compatível com texto e dados binários\n"
            "• Histórico Completo: Armazenamento de conversas WebSocket por conexão\n\n"
            "Intruder (Ataques Automatizados):\n"
            "• Múltiplos Vetores: Sniper, Battering Ram, Pitchfork e Cluster Bomb\n"
            "• Processamento de Payloads: Codificação, hashing e manipulação de dados\n"
            "• Extração via Regex: Grep extraction para análise de respostas\n"
            "• Controle de Recursos: Gerenciamento de pool de threads para performance\n\n"
            "PERSISTÊNCIA E CONFIGURAÇÃO\n\n"
            "• Configuração JSON: Todas as regras e configurações são armazenadas em formato JSON\n"
            "• Porta Configurável: Flexibilidade para escolher a porta de escuta do proxy\n"
            "• Gerenciamento de Cookies: Jar de cookies para manutenção de sessões\n"
            "• Histórico Estruturado: Armazenamento organizado de requisições e respostas\n\n"
            "SEGURANÇA E PERFORMANCE\n\n"
            "• Isolamento de Ambiente: Recomendação de uso em ambiente virtual Python\n"
            "• Executável Standalone: Distribuição como binário autocontido via PyInstaller\n"
            "• Interface Multi-plataforma: Compatível com Windows, Linux e macOS\n"
            "• Gerenciamento de Recursos: Controle eficiente de memória e processamento"
        )
        technical_layout.addWidget(technical_text)
        technical_group.setLayout(technical_layout)
        content_layout.addWidget(technical_group)

        # Configurar o scroll area
        scroll_area.setWidget(content_widget)
        main_layout.addWidget(scroll_area)