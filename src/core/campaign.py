"""
Captured route campaigns for focused active scans.

A campaign is a reusable collection of HTTP requests captured while the
analyst navigates an application manually. It intentionally keeps only
requests with a useful active-scan surface, avoiding static assets and noise.
"""
from __future__ import annotations

import re
from copy import deepcopy
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse


CAMPAIGN_SCHEMA_VERSION = 1

ACTIVE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
STATIC_EXTENSIONS = {
    ".7z",
    ".avi",
    ".bmp",
    ".css",
    ".eot",
    ".gif",
    ".gz",
    ".ico",
    ".jpeg",
    ".jpg",
    ".js",
    ".map",
    ".mov",
    ".mp3",
    ".mp4",
    ".otf",
    ".pdf",
    ".png",
    ".rar",
    ".svg",
    ".tar",
    ".ttf",
    ".wav",
    ".webp",
    ".woff",
    ".woff2",
    ".zip",
}
STATIC_CONTENT_TYPES = (
    "application/javascript",
    "application/pdf",
    "application/x-javascript",
    "audio/",
    "font/",
    "image/",
    "text/css",
    "video/",
)


def _headers_lower(headers: Optional[Dict[str, Any]]) -> Dict[str, str]:
    return {str(k).lower(): str(v) for k, v in (headers or {}).items()}


def _content_type(headers: Optional[Dict[str, Any]]) -> str:
    return _headers_lower(headers).get("content-type", "").lower()


def _path_has_static_extension(path: str) -> bool:
    lower_path = (path or "").lower()
    return any(lower_path.endswith(ext) for ext in STATIC_EXTENSIONS)


def is_static_resource(entry: Dict[str, Any]) -> bool:
    """Return True when a history entry is likely a static asset."""
    parsed = urlparse(str(entry.get("url") or ""))
    path = parsed.path or str(entry.get("path") or "")
    if _path_has_static_extension(path):
        return True

    response_type = _content_type(entry.get("response_headers"))
    if response_type and any(response_type.startswith(prefix) for prefix in STATIC_CONTENT_TYPES):
        return True

    request_type = _content_type(entry.get("request_headers"))
    return bool(request_type and any(request_type.startswith(prefix) for prefix in STATIC_CONTENT_TYPES))


def _has_query_params(url: str) -> bool:
    return bool(parse_qs(urlparse(url).query, keep_blank_values=True))


def _has_body_params(entry: Dict[str, Any]) -> bool:
    body = entry.get("request_body") or entry.get("body") or ""
    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="ignore")
    if not str(body).strip():
        return False

    content_type = _content_type(entry.get("request_headers") or entry.get("headers"))
    if any(
        marker in content_type
        for marker in (
            "application/x-www-form-urlencoded",
            "application/json",
            "multipart/form-data",
            "text/xml",
            "application/xml",
        )
    ):
        return True

    # Fallback for legacy forms where Content-Type is missing or inconsistent.
    return "=" in str(body)


def has_testable_surface(entry: Dict[str, Any]) -> bool:
    """Keep GET requests with params and mutating methods with params/body."""
    method = str(entry.get("method") or "").upper()
    url = str(entry.get("url") or "")
    if not method or not url:
        return False
    if is_static_resource(entry):
        return False
    if method == "GET":
        return _has_query_params(url)
    if method in ACTIVE_METHODS:
        return _has_query_params(url) or _has_body_params(entry)
    return False


def route_signature(entry: Dict[str, Any]) -> Tuple[Any, ...]:
    """Build a stable signature used to remove duplicate captured requests."""
    method = str(entry.get("method") or "").upper()
    parsed = urlparse(str(entry.get("url") or ""))
    query_names = tuple(sorted(parse_qs(parsed.query, keep_blank_values=True).keys()))
    body_names: Tuple[str, ...] = ()

    body = entry.get("request_body") or entry.get("body") or ""
    content_type = _content_type(entry.get("request_headers") or entry.get("headers"))
    if isinstance(body, bytes):
        body = body.decode("utf-8", errors="ignore")
    if "application/x-www-form-urlencoded" in content_type and body:
        body_names = tuple(sorted(parse_qs(str(body), keep_blank_values=True).keys()))

    return (
        method,
        parsed.scheme.lower(),
        parsed.netloc.lower(),
        parsed.path or "/",
        query_names,
        content_type.split(";")[0],
        body_names,
    )


def _campaign_route(entry: Dict[str, Any], source_id: int) -> Dict[str, Any]:
    route = _json_safe(deepcopy(entry))
    original_id = entry.get("id")
    route["id"] = source_id
    route["campaign_metadata"] = {
        "signature": "|".join(map(str, route_signature(entry))),
        "source_history_id": original_id,
        "captured_status": entry.get("status"),
        "captured_elapsed_ms": entry.get("elapsed_ms"),
    }
    return route


def _json_safe(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat(timespec="seconds")
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_safe(v) for v in value]
    if isinstance(value, tuple):
        return [_json_safe(v) for v in value]
    return value


def build_campaign(
    entries: Iterable[Dict[str, Any]],
    name: str,
    scope: Optional[Iterable[str]] = None,
    include_static: bool = False,
) -> Dict[str, Any]:
    """Create a focused reusable campaign from raw history entries."""
    raw_entries = list(entries or [])
    scoped_entries = []
    scope_terms = [s.lower() for s in (scope or []) if s]
    for entry in raw_entries:
        url = str(entry.get("url") or "").lower()
        if scope_terms and not any(term in url for term in scope_terms):
            continue
        scoped_entries.append(entry)

    routes: List[Dict[str, Any]] = []
    seen = set()
    ignored_static = 0
    ignored_no_surface = 0
    ignored_duplicate = 0

    for entry in scoped_entries:
        static = is_static_resource(entry)
        if static and not include_static:
            ignored_static += 1
            continue
        if not has_testable_surface(entry):
            ignored_no_surface += 1
            continue
        signature = route_signature(entry)
        if signature in seen:
            ignored_duplicate += 1
            continue
        seen.add(signature)
        routes.append(_campaign_route(entry, len(routes) + 1))

    return {
        "schema": "proxyhunter.campaign",
        "version": CAMPAIGN_SCHEMA_VERSION,
        "name": name,
        "created_at": datetime.now().isoformat(timespec="seconds"),
        "scope": list(scope or []),
        "filters": {
            "focused_surface": "GET with query params; POST/PUT/PATCH/DELETE with query/body params",
            "include_static": include_static,
        },
        "stats": {
            "input": len(raw_entries),
            "in_scope": len(scoped_entries),
            "routes": len(routes),
            "ignored_static": ignored_static,
            "ignored_no_surface": ignored_no_surface,
            "ignored_duplicate": ignored_duplicate,
        },
        "routes": routes,
    }


def campaign_routes(campaign: Dict[str, Any]) -> List[Dict[str, Any]]:
    routes = campaign.get("routes") if isinstance(campaign, dict) else []
    return routes if isinstance(routes, list) else []


def parse_raw_http_headers(raw_text: str) -> Dict[str, str]:
    """
    Extrai headers de um request HTTP bruto colado pelo usuario.

    Aceita tanto o request completo ("GET / HTTP/1.1") quanto linhas soltas
    no formato "Header: valor".
    """
    headers: Dict[str, str] = {}
    if not raw_text:
        return headers

    current_key = ""
    for raw_line in raw_text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw_line.rstrip()
        if not line:
            continue
        if re.match(r"^[A-Z]+\s+\S+\s+HTTP/\d(?:\.\d)?$", line):
            continue
        if line[:1] in (" ", "\t") and current_key:
            headers[current_key] = f"{headers[current_key]} {line.strip()}".strip()
            continue
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        key = key.strip()
        if not key:
            continue
        current_key = key
        headers[key] = value.strip()
    return headers


def parse_cookie_header(cookie_header: str) -> Dict[str, str]:
    cookies: Dict[str, str] = {}
    if not cookie_header:
        return cookies
    for part in cookie_header.split(";"):
        part = part.strip()
        if "=" in part:
            ck, cv = part.split("=", 1)
            cookies[ck.strip()] = cv.strip()
    return cookies


def format_cookie_header(cookies: Dict[str, str]) -> str:
    return "; ".join(f"{name}={value}" for name, value in cookies.items())


def ecidade_window_cookie_name(url: str) -> Optional[str]:
    if not url:
        return None
    path = urlparse(url).path
    match = re.search(r"/e-cidade/w/(\d+)(?:/|$)", path)
    if not match:
        return None
    return f"ECIDADEWINDOW{match.group(1)}"


def adapt_ecidade_window_cookie(cookie_header: str, route_url: str, existing_cookie_header: str = "") -> str:
    """
    Ajusta o cookie ECIDADEWINDOWN para coincidir com a janela da URL /w/N.

    Se o Cookie colado trouxer ECIDADEWINDOW5 e a rota for /w/2, a rota recebe
    ECIDADEWINDOW2 com o mesmo valor. Se o Cookie colado nao trouxer nenhum
    ECIDADEWINDOWN, preserva o valor especifico ja capturado na rota, quando
    existir.
    """
    target_cookie = ecidade_window_cookie_name(route_url)
    if not target_cookie:
        return cookie_header.strip()

    cookies = parse_cookie_header(cookie_header)
    if not cookies:
        return cookie_header.strip()

    window_value = cookies.get(target_cookie)
    if not window_value:
        for name, value in cookies.items():
            if re.fullmatch(r"ECIDADEWINDOW\d+", name):
                window_value = value
                break

    if not window_value and existing_cookie_header:
        existing_cookies = parse_cookie_header(existing_cookie_header)
        window_value = existing_cookies.get(target_cookie)

    filtered_cookies = {
        name: value
        for name, value in cookies.items()
        if not re.fullmatch(r"ECIDADEWINDOW\d+", name)
    }
    if window_value:
        filtered_cookies[target_cookie] = window_value

    return format_cookie_header(filtered_cookies)


def update_campaign_auth(
    campaign: Dict[str, Any],
    update_headers: Optional[Dict[str, str]] = None,
    update_cookies: Optional[Dict[str, str]] = None,
    cookie_header: Optional[str] = None,
    adapt_ecidade_window: bool = False,
) -> int:
    """
    Atualiza headers e/ou cookies especificos em todas as rotas da campanha.
    Ideal para injetar sessoes/tokens renovados sem precisar remapear rotas.
    Quando cookie_header for informado, substitui o header Cookie inteiro em
    vez de mesclar com cookies antigos da captura. Com adapt_ecidade_window,
    ajusta ECIDADEWINDOWN conforme a URL /e-cidade/w/N de cada rota.
    Retorna o numero de rotas atualizadas.
    """
    routes = campaign_routes(campaign)
    updated = 0

    for route in routes:
        headers = route.get("request_headers") or route.get("headers") or {}
        changed = False

        if update_headers:
            for k, v in update_headers.items():
                existing_key = k
                for ek in headers.keys():
                    if ek.lower() == k.lower():
                        existing_key = ek
                        break
                if headers.get(existing_key) != v:
                    headers[existing_key] = v
                    changed = True

        if cookie_header is not None:
            cookie_key = "Cookie"
            for ek in headers.keys():
                if ek.lower() == "cookie":
                    cookie_key = ek
                    break

            existing_cookie_str = headers.get(cookie_key, "")
            if adapt_ecidade_window:
                new_cookie_str = adapt_ecidade_window_cookie(
                    cookie_header,
                    route.get("url", ""),
                    existing_cookie_str,
                )
            else:
                new_cookie_str = cookie_header.strip()
            if headers.get(cookie_key, "") != new_cookie_str:
                headers[cookie_key] = new_cookie_str
                changed = True

        elif update_cookies:
            cookie_key = "Cookie"
            for ek in headers.keys():
                if ek.lower() == "cookie":
                    cookie_key = ek
                    break
            
            existing_cookie_str = headers.get(cookie_key, "")
            
            cookie_dict = parse_cookie_header(existing_cookie_str)

            for k, v in update_cookies.items():
                cookie_dict[k] = v

            new_cookie_str = format_cookie_header(cookie_dict)
            if new_cookie_str != existing_cookie_str:
                headers[cookie_key] = new_cookie_str
                changed = True

        if changed:
            if "request_headers" in route:
                route["request_headers"] = headers
            else:
                route["headers"] = headers
            updated += 1

    return updated
