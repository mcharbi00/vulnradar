# Cherche dans la page d'accueil les liens avec des paramètres (ex: /search?q=)
# pour que les tests XSS/SQLi visent les vrais paramètres du site.
from __future__ import annotations

import re
from urllib.parse import parse_qs, urljoin, urlparse

import httpx

from app.core.config import get_settings

settings = get_settings()

LINK_RE = re.compile(r'href=["\']([^"\'#]+)["\']', re.IGNORECASE)


def discover_query_endpoints(base_url: str) -> list[dict]:
    """Retourne une liste de {"url": <url sans query>, "params": [...]}."""
    try:
        response = httpx.get(
            base_url,
            timeout=settings.SCAN_HTTP_TIMEOUT,
            follow_redirects=True,
            trust_env=False,
        )
    except httpx.HTTPError:
        return []

    endpoints: list[dict] = []
    seen: set[tuple[str, tuple[str, ...]]] = set()

    for href in LINK_RE.findall(response.text):
        full_url = urljoin(str(response.url), href)
        parsed = urlparse(full_url)
        if not parsed.query or parsed.netloc != urlparse(str(response.url)).netloc:
            continue

        endpoint_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = tuple(parse_qs(parsed.query).keys())
        key = (endpoint_url, params)
        if key in seen or not params:
            continue
        seen.add(key)
        endpoints.append({"url": endpoint_url, "params": list(params)})

    return endpoints
