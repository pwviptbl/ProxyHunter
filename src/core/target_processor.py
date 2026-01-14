from .database import DatabaseManager
from .parameter_mapper import ParameterMapper
from .spider import LinkParser, FormParser
from urllib.parse import urljoin
from .logger_config import log
from contextlib import nullcontext
import codecs
import re

# Instâncias globais para evitar recriação constante
db_manager = DatabaseManager()
param_mapper = ParameterMapper()

def _spider_lock(spider_instance):
    lock = getattr(spider_instance, "_lock", None)
    return lock if lock is not None else nullcontext()

def _decode_response_body(flow, content_type: str) -> str:
    if not flow.response or not flow.response.content:
        return ""
    content = flow.response.content
    try:
        return flow.response.get_text()
    except Exception:
        pass
    candidates = []

    charset = ""
    if content_type:
        match = re.search(r"charset=([^\s;]+)", content_type, re.IGNORECASE)
        if match:
            charset = match.group(1).strip('"\'')
    if charset:
        candidates.append(charset)

    if content.startswith(codecs.BOM_UTF8):
        candidates.append("utf-8-sig")
    elif content.startswith(codecs.BOM_UTF16_LE):
        candidates.append("utf-16-le")
    elif content.startswith(codecs.BOM_UTF16_BE):
        candidates.append("utf-16-be")
    elif content.startswith(codecs.BOM_UTF32_LE):
        candidates.append("utf-32-le")
    elif content.startswith(codecs.BOM_UTF32_BE):
        candidates.append("utf-32-be")

    sample = content[:4096].decode("latin-1", errors="ignore")
    meta_charset = re.search(r"<meta[^>]+charset=[\"']?\s*([-\w]+)\s*[\"']?", sample, re.IGNORECASE)
    if meta_charset:
        candidates.append(meta_charset.group(1))
    else:
        meta_equiv = re.search(
            r"<meta[^>]+http-equiv=[\"']?content-type[\"']?[^>]+content=[\"']?[^\"'>]*charset=([-\w]+)",
            sample,
            re.IGNORECASE,
        )
        if meta_equiv:
            candidates.append(meta_equiv.group(1))

    common_encodings = ["utf-8", "windows-1252", "iso-8859-1", "latin-1"]
    for encoding in candidates + common_encodings:
        try:
            return content.decode(encoding)
        except Exception:
            continue
    return content.decode("latin-1", errors="replace")

def process_flow(flow, spider_instance):
    """
    Processa um fluxo HTTP/HTTPS, salva no banco de dados e alimenta o spider.

    Args:
        flow: O objeto de fluxo do mitmproxy.
        spider_instance: A instância ativa do Spider.
    """
    if not flow.response:
        return

    # 0. Se houver escopo definido no Spider e a URL não estiver no escopo, ignorar
    if spider_instance and getattr(spider_instance, 'scope_urls', None):
        try:
            if not spider_instance._is_in_scope(flow.request.url):
                return
        except Exception:
            # Em caso de falha na verificação de escopo, segue o fluxo padrão
            pass

    # 1. Salva o "molde" da requisição e obtém o ID
    request_node_id = db_manager.get_or_create_request_node(flow)

    # 2. Mapeia os pontos de injeção
    injection_points = param_mapper.find_injection_points(flow)

    # 3. Salva os pontos de injeção no banco
    db_manager.add_injection_points(request_node_id, injection_points)

    # 4. Executa a lógica de crawling para encontrar novos links (HTML detection mais robusta)
    # Lê Content-Type sem depender de caixa
    try:
        content_type = next((v for k, v in flow.response.headers.items() if str(k).lower() == 'content-type'), '')
    except Exception:
        content_type = flow.response.headers.get('Content-Type', '')

    is_html = 'html' in (content_type or '').lower()
    if not is_html:
        try:
            body_preview = flow.response.get_text()[:256].lower() if flow.response and flow.response.content else ''
            is_html = '<html' in body_preview or '<!doctype html' in body_preview
        except Exception:
            is_html = False

    log.debug(f"Spider HTML detection -> header='{content_type}', is_html={is_html}, running={spider_instance.is_running() if spider_instance else False}")

    if spider_instance and spider_instance.is_running():
        # Respeita escopo também para marcação e descoberta
        if spider_instance.scope_urls and not spider_instance._is_in_scope(flow.request.url):
            return
        # Sempre registra a URL atual como descoberta/visitada
        with _spider_lock(spider_instance):
            spider_instance.visited.add(flow.request.url)
            try:
                spider_instance.discovered_urls.add(flow.request.url)
                spider_instance.discovered_urls.add(getattr(flow.request, 'pretty_url', flow.request.url))
            except Exception:
                pass

        # Notifica a UI mesmo quando não é HTML
        if spider_instance.ui_queue:
            stats = spider_instance.get_stats()
            stats['discovered_urls'] = len(spider_instance.discovered_urls)
            spider_instance.ui_queue.put({"type": "update_spider_stats", "data": stats})

        # Extração de links apenas se for HTML
        if not is_html:
            return

        # A partir daqui é HTML
        try:
            log.info(f"Spider: HTML detectado em {flow.request.url}")
        except Exception:
            pass
        try:
            log.info(f"Spider: HTML detectado em {flow.request.url}")
        except Exception:
            pass

        # O spider marca a URL como visitada
        with _spider_lock(spider_instance):
            spider_instance.visited.add(flow.request.url)

        # Limite de URLs descobertas
        with _spider_lock(spider_instance):
            if len(spider_instance.discovered_urls) >= spider_instance.max_urls:
                return

        try:
            with _spider_lock(spider_instance):
                log.info(f"Spider: URLs descobertas = {len(spider_instance.discovered_urls)}")
        except Exception:
            pass

        # Notifica a UI
        if spider_instance.ui_queue:
            stats = spider_instance.get_stats()
            stats['discovered_urls'] = len(spider_instance.discovered_urls) # Garante que está atualizado
            spider_instance.ui_queue.put({"type": "update_spider_stats", "data": stats})

        try:
            html_text = _decode_response_body(flow, content_type)

            # 1) Links
            link_parser = LinkParser()
            link_parser.feed(html_text)

            for link in link_parser.links:
                absolute_url = urljoin(flow.request.url, link).split('#')[0]

                if not absolute_url or absolute_url == flow.request.url:
                    continue

                # Reutiliza a lógica de ignorar do spider
                if spider_instance._should_ignore_url(absolute_url):
                    continue

                spider_instance.add_to_queue(absolute_url)

            # 2) Formulários
            form_parser = FormParser()
            form_parser.feed(html_text)

            form_entries = []
            for form in form_parser.forms:
                # Monta URL absoluta do action do form
                form_action = form.get('action') or ''
                absolute_form_url = urljoin(flow.request.url, form_action).split('#')[0]
                # Canonicaliza URL de formulário: ignora querystring e fragmento
                try:
                    from urllib.parse import urlparse, urlunparse
                    parsed = urlparse(absolute_form_url)
                    form_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path or '/', '', '', ''))
                except Exception:
                    form_url = absolute_form_url

                if spider_instance.scope_urls and not spider_instance._is_in_scope(form_url):
                    continue

                # Estrutura esperada pela UI
                form_entry = {
                    'method': (form.get('method') or 'GET').upper(),
                    'url': form_url,
                    'inputs': form.get('inputs') or []
                }

                form_entries.append(form_entry)

            if form_entries:
                with _spider_lock(spider_instance):
                    for form_entry in form_entries:
                        # Deduplicação simples por (method, url, sorted input names)
                        try:
                            input_names = tuple(sorted(i['name'] for i in form_entry['inputs'] if i.get('name')))
                            signature = (form_entry['method'], form_entry['url'], input_names)
                            existing_signatures = getattr(spider_instance, '_form_signatures', set())
                            if signature not in existing_signatures:
                                spider_instance.forms.append(form_entry)
                                existing_signatures.add(signature)
                                spider_instance._form_signatures = existing_signatures
                        except Exception:
                            # fallback sem dedup
                            spider_instance.forms.append(form_entry)

        except Exception as e:
            # Em um cenário real, logaríamos o erro
            print(f"Erro ao parsear HTML de {flow.request.url}: {e}")
