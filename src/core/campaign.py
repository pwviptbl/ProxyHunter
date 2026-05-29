"""
Captured route campaigns for focused active scans.

A campaign is a reusable collection of HTTP requests captured while the
analyst navigates an application manually. It intentionally keeps only
requests with a useful active-scan surface, avoiding static assets and noise.
"""
from __future__ import annotations

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
