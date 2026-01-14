#!/usr/bin/env python3
import sys
import os

# Adiciona o diretório raiz do projeto ao path para importações corretas
project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, project_root)

def get_resource_path(filename):
    """Retorna o caminho correto para um recurso dependendo se está rodando como executável ou script."""
    # Verifica se está rodando como executável PyInstaller
    if hasattr(sys, '_MEIPASS'):
        # Caminho para o arquivo extraído pelo PyInstaller
        path = os.path.join(sys._MEIPASS, "imagens", filename)
        print(f"[DEBUG] PyInstaller mode: looking for {filename} at {path}")
        if not os.path.exists(path):
            print(f"[DEBUG] File not found at {path}, falling back to project path")
            # Fallback para o caminho do projeto
            path = os.path.join(project_root, "imagens", filename)
        return path
    else:
        # Caminho normal para desenvolvimento
        path = os.path.join(project_root, "imagens", filename)
        print(f"[DEBUG] Development mode: looking for {filename} at {path}")
        return path

def parse_env_flag(name, default=False):
    """Parse simple true/false env flags."""
    value = os.getenv(name)
    if value is None:
        return default
    value = value.strip().lower()
    if value in ("1", "true", "yes", "on"):
        return True
    if value in ("0", "false", "no", "off"):
        return False
    return default

def is_safe_mode():
    """Enable safe mode to avoid unstable splash/GL paths."""
    return parse_env_flag("PROXYHUNTER_SAFE_MODE", default=False)

if is_safe_mode():
    os.environ.setdefault("QT_OPENGL", "software")
    os.environ.setdefault("LIBGL_ALWAYS_SOFTWARE", "1")

from PySide6.QtWidgets import QApplication, QSplashScreen, QWidget, QVBoxLayout
from PySide6.QtGui import QIcon, QPixmap
from PySide6.QtCore import QTimer, Qt, QUrl

from src.ui.pyside_gui import ProxyGUI

def should_use_video_splash():
    """Disable video splash on Linux by default; override via env flag."""
    if is_safe_mode():
        return False
    default = sys.platform not in ("linux", "linux2")
    return parse_env_flag("PROXYHUNTER_SPLASH_VIDEO", default=default)

def show_static_splash(app, window):
    """Show a static splash if possible; otherwise show the main window."""
    if is_safe_mode():
        window.show()
        return
    splash_image_path = get_resource_path("Limpo.png")
    if not os.path.exists(splash_image_path):
        splash_image_path = get_resource_path("Principal.png")
    if not os.path.exists(splash_image_path):
        window.show()
        return
    pixmap = QPixmap(splash_image_path)
    if pixmap.isNull():
        window.show()
        return
    splash = QSplashScreen(pixmap, Qt.WindowStaysOnTopHint | Qt.FramelessWindowHint)
    splash.show()
    splash.raise_()
    app.processEvents()
    QTimer.singleShot(1500, lambda: show_main_window(splash, window))

def main():
    """Inicia a aplicação GUI com PySide6."""
    app = QApplication(sys.argv)
    
    # Define o ícone da aplicação
    icon_path = get_resource_path("icone_sfundo.png")
    print(f"[DEBUG] Icon path: {icon_path}")
    if os.path.exists(icon_path):
        print("[DEBUG] Icon file exists")
        app.setWindowIcon(QIcon(icon_path))
    else:
        print("[DEBUG] Icon file does not exist")
    
    # Cria a janela principal primeiro
    window = ProxyGUI()
    if os.path.exists(icon_path):
        window.setWindowIcon(QIcon(icon_path))

    if is_safe_mode():
        print("[DEBUG] Safe mode enabled; skipping splash screen")
        window.show()
        sys.exit(app.exec())

    # Cria e mostra a splash screen com vídeo
    splash_video_path = get_resource_path("CTela_de_Carregamento.mp4")
    print(f"[DEBUG] Splash video path: {splash_video_path}")
    if should_use_video_splash() and os.path.exists(splash_video_path):
        print("[DEBUG] Splash video file exists")
        try:
            from PySide6.QtMultimedia import QMediaPlayer
            from PySide6.QtMultimediaWidgets import QVideoWidget
        except Exception as exc:
            print(f"[DEBUG] QtMultimedia import failed: {exc}")
            show_static_splash(app, window)
            sys.exit(app.exec())

        # Criar uma janela temporária para o vídeo
        splash_window = QWidget()
        splash_window.setWindowFlags(Qt.WindowStaysOnTopHint | Qt.FramelessWindowHint)
        splash_window.setAttribute(Qt.WA_TranslucentBackground)
        splash_window.resize(716, 694)  # Tamanho do vídeo para evitar barras pretas

        layout = QVBoxLayout(splash_window)
        layout.setContentsMargins(0, 0, 0, 0)

        video_widget = QVideoWidget(splash_window)
        video_widget.setAspectRatioMode(Qt.AspectRatioMode.KeepAspectRatio)
        layout.addWidget(video_widget)

        player = QMediaPlayer(splash_window)
        player.setVideoOutput(video_widget)
        player.setSource(QUrl.fromLocalFile(splash_video_path))

        timer = QTimer(splash_window)
        timer.setSingleShot(True)

        # Conectar ao sinal para fechar quando o vídeo terminar
        def on_media_status_changed(status):
            print(f"[DEBUG] Media status changed: {status}")
            if status == QMediaPlayer.EndOfMedia:
                print("[DEBUG] Video ended, closing splash")
                show_main_window(splash_window, window, player, timer)

        player.mediaStatusChanged.connect(on_media_status_changed)

        splash_window.show()
        splash_window.raise_()
        splash_window.activateWindow()
        player.play()

        app.processEvents()  # Processa eventos para mostrar a janela imediatamente

        # Timer de backup para fechar após 10 segundos se o vídeo não terminar
        timer.timeout.connect(lambda: show_main_window(splash_window, window, player, timer))
        timer.start(10000)  # 10 segundos
    else:
        print("[DEBUG] Splash video disabled or missing; using static splash")
        show_static_splash(app, window)
    
    sys.exit(app.exec())

def show_main_window(splash, window, player=None, timer=None):
    """Função chamada após o timer da splash screen."""
    if splash is not None and not splash.isVisible():
        return
    if timer is not None:
        timer.stop()
    if player is not None:
        player.stop()
        player.setVideoOutput(None)
        player.deleteLater()
    window.show()
    if splash is not None:
        if hasattr(splash, "finish"):
            splash.finish(window)
        else:
            splash.close()

if __name__ == "__main__":
    main()
