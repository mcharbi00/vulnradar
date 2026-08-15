"""Analyse des attributs de sécurité des cookies (Secure, HttpOnly, SameSite)."""
from __future__ import annotations

import httpx

from app.core.config import get_settings

settings = get_settings()


def analyze_cookies(set_cookie_headers: list[str]) -> list[dict]:
    """Vérifie les attributs Secure / HttpOnly / SameSite sur chaque Set-Cookie."""
    findings: list[dict] = []

    for raw_cookie in set_cookie_headers:
        parts = [p.strip() for p in raw_cookie.split(";")]
        cookie_name = parts[0].split("=")[0] if parts else "cookie"
        attrs_lower = [p.lower() for p in parts[1:]]

        if not any(a == "secure" for a in attrs_lower):
            findings.append(
                {
                    "category": "cookies",
                    "severity": "medium",
                    "title": f"Cookie '{cookie_name}' sans attribut Secure",
                    "description": "Le cookie peut être transmis en clair sur une connexion HTTP.",
                    "evidence": raw_cookie,
                    "recommendation": "Ajouter l'attribut Secure à ce cookie.",
                }
            )

        if not any(a == "httponly" for a in attrs_lower):
            findings.append(
                {
                    "category": "cookies",
                    "severity": "medium",
                    "title": f"Cookie '{cookie_name}' sans attribut HttpOnly",
                    "description": "Le cookie est accessible en JavaScript, ce qui facilite son vol via un XSS.",
                    "evidence": raw_cookie,
                    "recommendation": "Ajouter l'attribut HttpOnly à ce cookie.",
                }
            )

        if not any(a.startswith("samesite") for a in attrs_lower):
            findings.append(
                {
                    "category": "cookies",
                    "severity": "low",
                    "title": f"Cookie '{cookie_name}' sans attribut SameSite",
                    "description": "Sans SameSite, le cookie peut être envoyé lors de requêtes cross-site (CSRF).",
                    "evidence": raw_cookie,
                    "recommendation": "Ajouter 'SameSite=Lax' ou 'SameSite=Strict'.",
                }
            )

    return findings


def scan_cookies(target_url: str) -> list[dict]:
    try:
        response = httpx.get(
            target_url,
            timeout=settings.SCAN_HTTP_TIMEOUT,
            follow_redirects=True,
            trust_env=False,
        )
    except httpx.HTTPError:
        return []
    raw_cookies = response.headers.get_list("set-cookie")
    return analyze_cookies(raw_cookies)
