import random
import string
import subprocess
import sys
import time
import os
from collections import deque
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests

from .logger_config import log
from .spider import LinkParser, FormParser, Spider


class AutoNavigator:
    """
    Navegador automatico simples para CLI.

    - Faz crawl basico (HTML) seguindo links.
    - Submete formularios com dados aleatorios para gerar rotas POST/GET.
    - Todas as requisicoes passam pelo proxy (mitmproxy) para gerar historico e scan passivo.
    """

    def __init__(
        self,
        start_urls: List[str],
        spider: Spider,
        proxy_port: int,
        max_depth: int = 2,
        max_pages: int = 200,
        max_forms: int = 200,
        delay: float = 0.2,
        timeout: int = 10,
        user_agent: Optional[str] = None,
        submit_forms: bool = True,
    ):
        self.start_urls = [self._normalize_url(u) for u in start_urls]
        self.spider = spider
        self.proxy_port = proxy_port
        self.max_depth = max(0, int(max_depth))
        self.max_pages = max(1, int(max_pages))
        self.max_forms = max(0, int(max_forms))
        self.delay = max(0.0, float(delay))
        self.timeout = max(1, int(timeout))
        self.submit_forms = bool(submit_forms)

        self.session = requests.Session()
        self.session.verify = False
        self.session.proxies = {
            "http": f"http://127.0.0.1:{self.proxy_port}",
            "https": f"http://127.0.0.1:{self.proxy_port}",
        }
        self.session.headers.update(
            {"User-Agent": user_agent or "ProxyHunter-AutoNavigator/1.0"}
        )

        self._queue: deque[Tuple[str, int]] = deque()
        self._visited: set[str] = set()
        self._submitted_forms: set[Tuple[str, str, Tuple[str, ...]]] = set()
        self._pages_fetched = 0
        self._total_requests = 0
        self._forms_submitted = 0

        for u in self.start_urls:
            self._queue.append((u, 0))

        try:
            requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]
        except Exception:
            pass

    def crawl(self) -> Dict[str, int]:
        start_time = time.time()

        while self._queue and self._pages_fetched < self.max_pages:
            url, depth = self._queue.popleft()
            if url in self._visited:
                continue
            if self.spider and not self._is_in_scope(url):
                continue
            if self.spider and self.spider._should_ignore_url(url):
                continue

            self._visited.add(url)
            try:
                response = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                self._total_requests += 1
                self._pages_fetched += 1
            except Exception as e:
                log.debug(f"AutoNavigator: falha ao acessar {url}: {e}")
                continue

            try:
                self._process_response(url, depth, response)
            except Exception as e:
                log.debug(f"AutoNavigator: erro ao processar resposta de {url}: {e}")

            if self.delay:
                time.sleep(self.delay)

        elapsed = max(0.0, time.time() - start_time)
        return {
            "pages_fetched": self._pages_fetched,
            "total_requests": self._total_requests,
            "forms_submitted": self._forms_submitted,
            "visited": len(self._visited),
            "elapsed_sec": int(elapsed),
        }

    def _process_response(self, base_url: str, depth: int, response: requests.Response) -> None:
        content_type = response.headers.get("Content-Type", "")
        is_html = "html" in (content_type or "").lower()
        if not is_html:
            return

        try:
            html_text = response.text or ""
        except Exception:
            return

        if depth < self.max_depth:
            self._enqueue_links(base_url, depth, html_text)

        if self.submit_forms and self._forms_submitted < self.max_forms:
            self._handle_forms(base_url, depth, html_text)

    def _enqueue_links(self, base_url: str, depth: int, html_text: str) -> None:
        link_parser = LinkParser()
        link_parser.feed(html_text)
        for link in link_parser.links:
            absolute_url = urljoin(base_url, link).split("#")[0]
            if not absolute_url:
                continue
            if self.spider and self.spider._should_ignore_url(absolute_url):
                continue
            if self.spider and not self._is_in_scope(absolute_url):
                continue
            if absolute_url in self._visited:
                continue
            self._queue.append((absolute_url, depth + 1))

    def _handle_forms(self, base_url: str, depth: int, html_text: str) -> None:
        form_parser = FormParser()
        form_parser.feed(html_text)
        for form in form_parser.forms:
            if self._forms_submitted >= self.max_forms:
                break
            method = (form.get("method") or "GET").upper()
            action = form.get("action") or ""
            inputs = form.get("inputs") or []
            form_url = urljoin(base_url, action).split("#")[0] if action else base_url

            signature = self._form_signature(method, form_url, inputs)
            if signature in self._submitted_forms:
                continue

            self._submitted_forms.add(signature)
            self._register_form(method, form_url, inputs)

            data = self._build_form_data(inputs)
            if not data:
                continue

            self._submit_form(method, form_url, data)
            self._forms_submitted += 1

            if depth < self.max_depth:
                self._queue.append((form_url, depth + 1))

    def _submit_form(self, method: str, url: str, data: Dict[str, str]) -> None:
        try:
            if method == "GET":
                self.session.get(url, params=data, timeout=self.timeout, allow_redirects=True)
            else:
                self.session.post(url, data=data, timeout=self.timeout, allow_redirects=True)
            self._total_requests += 1
        except Exception as e:
            log.debug(f"AutoNavigator: falha ao submeter form {method} {url}: {e}")

    def _register_form(self, method: str, url: str, inputs: List[Dict[str, str]]) -> None:
        if not self.spider:
            return
        try:
            form_entry = {
                "method": method,
                "url": url,
                "inputs": inputs,
            }
            with getattr(self.spider, "_lock", _NullContext()):
                input_names = tuple(sorted(i["name"] for i in inputs if i.get("name")))
                signature = (method, url, input_names)
                existing = getattr(self.spider, "_form_signatures", set())
                if signature not in existing:
                    self.spider.forms.append(form_entry)
                    existing.add(signature)
                    self.spider._form_signatures = existing
        except Exception:
            pass

    @staticmethod
    def _form_signature(method: str, url: str, inputs: List[Dict[str, str]]) -> Tuple[str, str, Tuple[str, ...]]:
        names = tuple(sorted(i.get("name", "") for i in inputs if i.get("name")))
        return method, url, names

    @staticmethod
    def _build_form_data(inputs: List[Dict[str, str]]) -> Dict[str, str]:
        data: Dict[str, str] = {}
        for item in inputs:
            name = item.get("name") or ""
            if not name:
                continue
            input_type = (item.get("type") or "text").lower()
            if input_type in ("submit", "button", "reset", "image", "file"):
                continue
            data[name] = _random_value_for_type(input_type)
        return data

    @staticmethod
    def _normalize_url(url: str) -> str:
        if not url:
            return url
        parsed = urlparse(url)
        if not parsed.scheme:
            return f"http://{url}"
        return url

    def _is_in_scope(self, url: str) -> bool:
        try:
            return self.spider._is_in_scope(url)
        except Exception:
            return True


class _NullContext:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        return False


def _random_value_for_type(input_type: str) -> str:
    if input_type in ("email",):
        return "teste@example.com"
    if input_type in ("number", "range"):
        return "123"
    if input_type in ("password",):
        return "Teste123!"
    if input_type in ("search",):
        return "teste"
    if input_type in ("checkbox", "radio"):
        return "on"
    return _random_string(10)


def _random_string(length: int) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(length))


class PlaywrightAutoNavigator:
    """
    Navegador automatico usando Playwright (renderiza JS).

    - Renderiza paginas com JS.
    - Coleta links e formularios a partir do DOM renderizado.
    - Submete formularios no navegador para gerar requisicoes reais.
    """

    def __init__(
        self,
        start_urls: List[str],
        spider: Spider,
        proxy_port: int,
        max_depth: int = 2,
        max_pages: int = 200,
        max_forms: int = 200,
        delay: float = 0.2,
        timeout: int = 10,
        user_agent: Optional[str] = None,
        submit_forms: bool = True,
        headless: bool = True,
    ):
        self.start_urls = [AutoNavigator._normalize_url(u) for u in start_urls]
        self.spider = spider
        self.proxy_port = proxy_port
        self.max_depth = max(0, int(max_depth))
        self.max_pages = max(1, int(max_pages))
        self.max_forms = max(0, int(max_forms))
        self.delay = max(0.0, float(delay))
        self.timeout = max(1, int(timeout))
        self.submit_forms = bool(submit_forms)
        self.headless = bool(headless)
        self.user_agent = user_agent or "ProxyHunter-Playwright/1.0"

        self.session = requests.Session()
        self.session.verify = False
        self.session.proxies = {
            "http": f"http://127.0.0.1:{self.proxy_port}",
            "https": f"http://127.0.0.1:{self.proxy_port}",
        }
        self.session.headers.update({"User-Agent": self.user_agent})

        self._queue: deque[Tuple[str, int]] = deque()
        self._visited: set[str] = set()
        self._submitted_forms: set[Tuple[str, str, Tuple[str, ...]]] = set()
        self._pages_fetched = 0
        self._total_requests = 0
        self._forms_submitted = 0

        for u in self.start_urls:
            self._queue.append((u, 0))

    async def crawl(self) -> Dict[str, int]:
        start_time = time.time()
        try:
            from playwright.async_api import async_playwright
        except Exception as e:
            raise RuntimeError(f"Playwright nao disponivel: {e}")

        self._ensure_playwright_browsers()

        async with async_playwright() as p:
            try:
                browser = await p.chromium.launch(
                    headless=self.headless,
                    proxy={"server": f"http://127.0.0.1:{self.proxy_port}"},
                    args=["--ignore-certificate-errors"],
                )
            except Exception as e:
                if "playwright install" in str(e).lower() or "executable doesn't exist" in str(e).lower():
                    self._ensure_playwright_browsers(force=True)
                    browser = await p.chromium.launch(
                        headless=self.headless,
                        proxy={"server": f"http://127.0.0.1:{self.proxy_port}"},
                        args=["--ignore-certificate-errors"],
                    )
                else:
                    raise
            context = await browser.new_context(ignore_https_errors=True, user_agent=self.user_agent)
            page = await context.new_page()

            while self._queue and self._pages_fetched < self.max_pages:
                url, depth = self._queue.popleft()
                if url in self._visited:
                    continue
                if self.spider and not self._is_in_scope(url):
                    continue
                if self.spider and self.spider._should_ignore_url(url):
                    continue

                self._visited.add(url)
                try:
                    await page.goto(url, wait_until="networkidle", timeout=self.timeout * 1000)
                    self._total_requests += 1
                    self._pages_fetched += 1
                except Exception as e:
                    log.debug(f"PlaywrightAutoNavigator: falha ao acessar {url}: {e}")
                    continue

                try:
                    await self._process_page(page, url, depth)
                except Exception as e:
                    log.debug(f"PlaywrightAutoNavigator: erro ao processar {url}: {e}")

                if self.delay:
                    await page.wait_for_timeout(int(self.delay * 1000))

            await browser.close()

        elapsed = max(0.0, time.time() - start_time)
        return {
            "pages_fetched": self._pages_fetched,
            "total_requests": self._total_requests,
            "forms_submitted": self._forms_submitted,
            "visited": len(self._visited),
            "elapsed_sec": int(elapsed),
        }

    async def _process_page(self, page, base_url: str, depth: int) -> None:
        html_text = await page.content()
        if depth < self.max_depth:
            self._enqueue_links(base_url, depth, html_text)
        if self.submit_forms and self._forms_submitted < self.max_forms:
            await self._handle_forms(page, base_url, depth, html_text)

    def _enqueue_links(self, base_url: str, depth: int, html_text: str) -> None:
        link_parser = LinkParser()
        link_parser.feed(html_text)
        for link in link_parser.links:
            absolute_url = urljoin(base_url, link).split("#")[0]
            if not absolute_url:
                continue
            if self.spider and self.spider._should_ignore_url(absolute_url):
                continue
            if self.spider and not self._is_in_scope(absolute_url):
                continue
            if absolute_url in self._visited:
                continue
            self._queue.append((absolute_url, depth + 1))

    async def _handle_forms(self, page, base_url: str, depth: int, html_text: str) -> None:
        form_parser = FormParser()
        form_parser.feed(html_text)
        forms = list(form_parser.forms)
        if not forms:
            return

        for idx, form in enumerate(forms):
            if self._forms_submitted >= self.max_forms:
                break
            method = (form.get("method") or "GET").upper()
            action = form.get("action") or ""
            inputs = form.get("inputs") or []
            form_url = urljoin(base_url, action).split("#")[0] if action else base_url

            signature = AutoNavigator._form_signature(method, form_url, inputs)
            if signature in self._submitted_forms:
                continue

            self._submitted_forms.add(signature)
            self._register_form(method, form_url, inputs)

            data = AutoNavigator._build_form_data(inputs)
            if not data:
                continue

            await self._submit_form(page, idx, method, form_url, data)
            self._forms_submitted += 1
            self._total_requests += 1

            if depth < self.max_depth:
                self._queue.append((form_url, depth + 1))

    async def _submit_form(self, page, form_index: int, method: str, url: str, data: Dict[str, str]) -> None:
        try:
            await page.evaluate(
                """(idx, data) => {
                    const forms = Array.from(document.forms);
                    const form = forms[idx];
                    if (!form) return false;
                    for (const [name, value] of Object.entries(data)) {
                        const el = form.querySelector(`[name="${name}"]`);
                        if (!el) continue;
                        const type = (el.type || "").toLowerCase();
                        if (type === "checkbox" || type === "radio") {
                            el.checked = true;
                        } else {
                            el.value = value;
                        }
                    }
                    const submit = form.querySelector('[type="submit"]');
                    if (submit) submit.click();
                    else form.submit();
                    return true;
                }""",
                form_index,
                data,
            )
            try:
                await page.wait_for_load_state("networkidle", timeout=self.timeout * 1000)
            except Exception:
                pass
        except Exception as e:
            log.debug(f"PlaywrightAutoNavigator: falha ao submeter form idx={form_index}: {e}")

        # Submissao direta via requests para garantir POST no historico
        try:
            if method == "GET":
                self.session.get(url, params=data, timeout=self.timeout, allow_redirects=True)
            else:
                self.session.post(url, data=data, timeout=self.timeout, allow_redirects=True)
            self._total_requests += 1
        except Exception as e:
            log.debug(f"PlaywrightAutoNavigator: falha submit requests {method} {url}: {e}")

    def _register_form(self, method: str, url: str, inputs: List[Dict[str, str]]) -> None:
        if not self.spider:
            return
        try:
            form_entry = {
                "method": method,
                "url": url,
                "inputs": inputs,
            }
            with getattr(self.spider, "_lock", _NullContext()):
                input_names = tuple(sorted(i["name"] for i in inputs if i.get("name")))
                signature = (method, url, input_names)
                existing = getattr(self.spider, "_form_signatures", set())
                if signature not in existing:
                    self.spider.forms.append(form_entry)
                    existing.add(signature)
                    self.spider._form_signatures = existing
        except Exception:
            pass

    def _is_in_scope(self, url: str) -> bool:
        try:
            return self.spider._is_in_scope(url)
        except Exception:
            return True

    def _ensure_playwright_browsers(self, force: bool = False) -> None:
        cmd = [sys.executable, "-m", "playwright", "install", "chromium"]
        env = os.environ.copy()
        env.setdefault("PLAYWRIGHT_BROWSERS_PATH", os.path.expanduser("~/.cache/ms-playwright"))
        if force:
            log.info("Playwright: instalando chromium...")
            subprocess.run(cmd, check=False, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return
        try:
            subprocess.run(cmd + ["--dry-run"], check=False, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
