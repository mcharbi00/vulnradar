"""Vérifie les méthodes HTTP autorisées par le serveur (via une requête OPTIONS).

Certaines méthodes activées par défaut sont risquées : TRACE (attaques XST),
PUT/DELETE (écriture ou suppression de fichiers si mal protégées).
"""
from __future__ import annotations

import httpx

from app.core.config import get_settings

settings = get_settings()

# méthode -> (gravité, explication)
RISKY_METHODS = {
    "TRACE": ("medium", "TRACE est activé : possible attaque Cross-Site Tracing (XST)."),
    "TRACK": ("medium", "TRACK est activé (équivalent de TRACE côté IIS)."),
    "PUT": ("high", "PUT est activé : un attaquant pourrait déposer des fichiers sur le serveur."),
    "DELETE": ("high", "DELETE est activé : un attaquant pourrait supprimer des ressources."),
    "CONNECT": ("medium", "CONNECT est activé : le serveur peut être détourné en proxy."),
}


def analyze_allow_header(allow_header: str) -> list[dict]:
    """Regarde les méthodes annoncées dans l'en-tête Allow et remonte les risquées."""
    methods = [m.strip().upper() for m in allow_header.split(",") if m.strip()]
    findings = []
    for method in methods:
        if method in RISKY_METHODS:
            severity, description = RISKY_METHODS[method]
            findings.append(
                {
                    "category": "methods",
                    "severity": severity,
                    "title": f"Méthode HTTP {method} autorisée",
                    "description": description,
                    "evidence": f"Allow: {allow_header}",
                    "recommendation": f"Désactiver la méthode {method} si elle n'est pas nécessaire.",
                }
            )
    return findings


def scan_http_methods(target_url: str) -> list[dict]:
    try:
        response = httpx.request(
            "OPTIONS",
            target_url,
            timeout=settings.SCAN_HTTP_TIMEOUT,
            follow_redirects=True,
            trust_env=False,
        )
    except httpx.HTTPError:
        return []

    allow = response.headers.get("allow")
    if not allow:
        return []
    return analyze_allow_header(allow)
