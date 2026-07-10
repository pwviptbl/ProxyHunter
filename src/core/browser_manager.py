import asyncio
import os
import subprocess
import sys
import traceback
from playwright.async_api import async_playwright, Playwright, Browser, Page
from threading import Lock, Thread
import ctypes
import platform
from PySide6.QtCore import QThread

class PlaywrightThread(QThread):
    def __init__(self, run_fn):
        super().__init__()
        self.run_fn = run_fn

    def run(self):
        self.run_fn()

class BrowserManager:
    """
    Gerencia a instalação e o lançamento de um navegador Chromium pré-configurado.
    """
    def __init__(self, proxy_port: int = 9507, ui_queue=None):
        self.proxy_port = proxy_port
        self.browser: Browser | None = None
        self.page: Page | None = None
        self.playwright: Playwright | None = None
        self.ui_queue = ui_queue
        self.playwright_loop = None
        self.browser_thread = None
        self._lock = Lock()
        self._launching = False

    def _get_screen_dimensions(self):
        """Obtém a largura e altura da tela principal."""
        try:
            if platform.system() == 'Windows':
                user32 = ctypes.windll.user32
                screen_width = user32.GetSystemMetrics(0)
                screen_height = user32.GetSystemMetrics(1)
                return screen_width, screen_height
            else:
                # Para Linux, tenta xrandr primeiro
                try:
                    import subprocess
                    result = subprocess.run(['xrandr'], capture_output=True, text=True, check=False)
                    if result.returncode == 0:
                        lines = result.stdout.split('\n')
                        for line in lines:
                            if ' connected ' in line and 'primary' in line:
                                parts = line.split()
                                for part in parts:
                                    if 'x' in part and '+' in part:
                                        res = part.split('+')[0]
                                        width, height = map(int, res.split('x'))
                                        return width, height
                        # Se não há primary, pega a primeira conectada
                        for line in lines:
                            if ' connected ' in line:
                                parts = line.split()
                                for part in parts:
                                    if 'x' in part and '+' in part:
                                        res = part.split('+')[0]
                                        width, height = map(int, res.split('x'))
                                        return width, height
                except Exception as e:
                    print(f"[DEBUG] xrandr failed: {e}")

                # Evita tkinter em Linux se estiver usando PySide6 (conhecido por causar segfaults)
                # Verifica se PROXYHUNTER_SAFE_MODE está ativo ou se PySide6 já está carregado
                if os.getenv("PROXYHUNTER_SAFE_MODE") == "1" or "PySide6" in sys.modules:
                    print("[DEBUG] Skipping tkinter to avoid segfault with PySide6. Using default resolution.")
                    return 1920, 1080

                try:
                    import tkinter as tk
                    root = tk.Tk()
                    screen_width = root.winfo_screenwidth()
                    screen_height = root.winfo_screenheight()
                    root.destroy()
                    return screen_width, screen_height
                except Exception as tk_e:
                    print(f"[DEBUG] tkinter fallback failed: {tk_e}")
                    return 1920, 1080
        except Exception as e:
            print(f"[WARNING] Falha ao obter dimensões da tela: {e}. Usando valores padrão.")
            return 1920, 1080  # Valores padrão

    def _is_chromium_installed(self):
        """Verifica se o Chromium está instalado."""
        try:
            # O Playwright usa um comando 'npx' ou similar para verificar,
            # mas uma forma programática é verificar os executáveis.
            # Uma maneira mais simples é tentar lançar e capturar o erro.
            # Por agora, vamos usar o método de verificação de instalação do Playwright.
            proc = subprocess.run(
                [sys.executable, "-m", "playwright", "install", "--dry-run", "chromium"],
                capture_output=True, text=True, check=False
            )
            return "chromium is already installed" in proc.stdout.lower()
        except FileNotFoundError:
            return False

    def _install_chromium(self):
        """Instala o Chromium usando o comando do Playwright."""
        self._notify_ui("browser_install_start")
        try:
            subprocess.run(
                [sys.executable, "-m", "playwright", "install", "chromium"],
                check=True, capture_output=True, text=True
            )
        finally:
            self._notify_ui("browser_install_finish")

    async def _launch_browser_async(self):
        """Lança o navegador de forma assíncrona."""
        if not self._is_chromium_installed():
            # Executa a instalação de forma assíncrona em thread para não bloquear a UI
            print("[DEBUG] Chromium não está instalado. Iniciando instalação...")
            await asyncio.to_thread(self._install_chromium)
            print("[DEBUG] Instalação do Chromium finalizada. Continuando tentativa de lançamento...")

        # Inicia o playwright e lança o browser dentro do bloco try abaixo.
        try:
            print("[DEBUG] Playwright: iniciando playwright...")
            self.playwright = self.playwright or await async_playwright().start()
            print("[DEBUG] Playwright: playwright iniciado.")
            print("[DEBUG] Playwright: lançando chromium...")
            screen_width, screen_height = self._get_screen_dimensions()
            print(f"[DEBUG] Screen dimensions: {screen_width}x{screen_height}")

            # Desconta o chrome do browser da altura do viewport:
            #   taskbar Linux: ~40px, tab bar: ~36px, URL bar: ~46px, bookmarks bar: ~36px = ~158px
            # Sem esse desconto o conteúdo vaza para baixo da janela sem scroll.
            viewport_w = screen_width
            viewport_h = max(600, screen_height - 160)
            print(f"[DEBUG] Viewport calculado: {viewport_w}x{viewport_h}")

            launch_args = [
                f"--window-size={screen_width},{screen_height}",
                "--window-position=0,0",
                "--ignore-certificate-errors"
            ]

            self.browser = await self.playwright.chromium.launch(
                headless=False,
                proxy={"server": f"http://127.0.0.1:{self.proxy_port}"},
                args=launch_args
            )
            print("[DEBUG] Playwright: chromium lançado.")

            context = await self.browser.new_context(
                viewport={'width': viewport_w, 'height': viewport_h}
            )

            self.page = await context.new_page()
            await self.page.goto("http://127.0.0.1")
            print("[DEBUG] Playwright: navegação concluída.")

            self.page.on("close", self.close_browser_sync)
            print("[DEBUG] Playwright: pronto.")
            self._notify_ui("browser_launch_ready")
            return True


        except Exception as e:
            print(f"[ERRO] Falha ao abrir o navegador: {e}")
            traceback.print_exc()
            self._notify_ui("browser_launch_error", str(e))
            await self._cleanup_after_launch_error()
            return False




    def launch_browser(self):
        """Ponto de entrada síncrono para lançar o navegador."""
        with self._lock:
            if self._launching or (self.browser_thread and self.browser_thread.isRunning()):
                print("[DEBUG] Playwright thread: lançamento ignorado, navegador já está em execução.")
                return False
            self._launching = True

        # O Playwright é assíncrono, então precisamos de um loop de eventos
        # para executá-lo a partir de um contexto síncrono (como o PySide6).
        def run_async():
            loop = asyncio.new_event_loop()
            # Armazena o loop para permitir fechamentos thread-safe
            self.playwright_loop = loop
            asyncio.set_event_loop(loop)
            try:
                print("[DEBUG] Playwright thread: iniciando loop de eventos")
                launched = loop.run_until_complete(self._launch_browser_async())
                if launched:
                    print("[DEBUG] Playwright thread: _launch_browser_async finalizado, executando loop forever")
                    loop.run_forever()
            except Exception as e:
                print(f"[DEBUG] Playwright thread: exceção não tratada: {e}")
                traceback.print_exc()
                self._notify_ui("browser_launch_error", str(e))
            finally:
                try:
                    pending = asyncio.all_tasks(loop)
                    for task in pending:
                        task.cancel()
                    if pending:
                        loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                except Exception:
                    pass
                loop.close()
                with self._lock:
                    self._launching = False
                    self.browser_thread = None
                    self.playwright_loop = None
                self._notify_ui("browser_closed")

        thread = PlaywrightThread(run_async)
        self.browser_thread = thread
        thread.start()
        return True

    def close_browser_sync(self, *args):
        """Fecha o navegador a partir de um contexto síncrono."""
        if self.playwright or self.playwright_loop:
            # Usa o loop da thread do Playwright, se disponível
            loop = self.playwright_loop
            if not loop:
                return
            print(f"[DEBUG] close_browser_sync: agendando _close_browser_async no loop {loop}")
            # Agende o fechamento de forma thread-safe
            loop.call_soon_threadsafe(lambda: asyncio.create_task(self._close_browser_async()))

    async def _close_browser_async(self):
        """Fecha o navegador e o playwright de forma assíncrona."""
        if self.browser and self.browser.is_connected:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()

        # Limpar instâncias para permitir nova inicialização em um novo event loop
        self.browser = None
        self.page = None
        self.playwright = None

        # Para o loop de eventos
        loop = self.playwright_loop
        if loop and loop.is_running():
            loop.stop()

    async def _cleanup_after_launch_error(self):
        """Libera recursos quando o Chromium falha antes de ficar pronto."""
        try:
            if self.browser and self.browser.is_connected:
                await self.browser.close()
        except Exception:
            pass
        try:
            if self.playwright:
                await self.playwright.stop()
        except Exception:
            pass
        self.browser = None
        self.page = None
        self.playwright = None

    def close(self):
        """Ponto de entrada síncrono para fechar tudo."""
        self.close_browser_sync()
        if self.browser_thread:
            self.browser_thread.wait(3000)  # Wait up to 3 seconds

    def _notify_ui(self, msg_type, data=None):
        if self.ui_queue:
            self.ui_queue.put({"type": msg_type, "data": data})

if __name__ == '__main__':
    # Exemplo de uso
    manager = BrowserManager()
    print("Verificando Chromium...")
    if not manager._is_chromium_installed():
        print("Chromium não instalado. Instalando...")
        manager._install_chromium()
        print("Instalação concluída.")

    print("Lançando navegador...")
    manager.launch_browser()

    # Em uma aplicação real, o fechamento seria acionado pelo fechamento da UI
    input("Pressione Enter para fechar o navegador...")
    manager.close()
    print("Navegador fechado.")
