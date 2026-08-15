"""Analyse des en-têtes de sécurité HTTP."""
from __future__ import annotations

import httpx

from app.core.config import get_settings

settings = get_settings()

# (nom d'en-tête, sévérité si absent, description, recommandation)
SECURITY_HEADERS = [
    (
        "content-security-policy",
        "high",
        "Aucune Content-Security-Policy définie : le navigateur n'a aucune restriction "
        "sur les scripts/ressources qu'il peut charger, ce qui aggrave l'impact d'un XSS.",
        "Définir une CSP restrictive, ex : default-src 'self'.",
    ),
    (
        "x-frame-options",
        "medium",
        "Absence de X-Frame-Options : la page peut être chargée dans une <iframe>, "
        "ouvrant la voie à des attaques de clickjacking.",
        "Ajouter 'X-Frame-Options: DENY' ou 'SAMEORIGIN'.",
    ),
    (
        "x-content-type-options",
        "low",
        "Absence de X-Content-Type-Options : certains navigateurs peuvent tenter de "
        "deviner le type MIME d'une réponse (MIME sniffing).",
        "Ajouter 'X-Content-Type-Options: nosniff'.",
    ),
    (
        "strict-transport-security",
        "medium",
        "Absence de HSTS : le site ne force pas le navigateur à utiliser HTTPS, "
        "ce qui permet des attaques de downgrade (SSL stripping).",
        "Ajouter 'Strict-Transport-Security: max-age=63072000; includeSubDomains'.",
    ),
    (
        "referrer-policy",
        "info",
        "Absence de Referrer-Policy : l'URL complète peut fuiter vers des sites tiers "
        "via l'en-tête Referer.",
        "Ajouter 'Referrer-Policy: strict-origin-when-cross-origin'.",
    ),
    (
        "permissions-policy",
        "info",
        "Absence de Permissions-Policy : aucune restriction explicite sur les API "
        "sensibles du navigateur (caméra, géolocalisation...).",
        "Ajouter 'Permissions-Policy' avec les fonctionnalités réellement utilisées.",
    ),
]


def analyze_headers(headers: dict[str, str]) -> list[dict]:
    """Compare les en-têtes reçus à la liste attendue et retourne les manquants."""
    normalized = {k.lower(): v for k, v in headers.items()}
    findings: list[dict] = []

    for header_name, severity, description, recommendation in SECURITY_HEADERS:
        if header_name not in normalized:
            findings.append(
                {
                    "category": "headers",
                    "severity": severity,
                    "title": f"En-tête de sécurité manquant : {header_name}",
                    "description": description,
                    "evidence": "En-tête absent de la réponse HTTP.",
                    "recommendation": recommendation,
                }
            )

    server_header = normalized.get("server")
    if server_header and any(char.isdigit() for char in server_header):
        findings.append(
            {
                "category": "headers",
                "severity": "low",
                "title": "Version du serveur exposée",
                "description": (
                    "L'en-tête Server révèle une version précise, utile à un "
                    "attaquant pour cibler des vulnérabilités connues."
                ),
                "evidence": f"Server: {server_header}",
                "recommendation": "Masquer ou généraliser l'en-tête Server.",
            }
        )

    return findings


def scan_headers(target_url: str) -> list[dict]:
    try:
        response = httpx.get(
            target_url,
            timeout=settings.SCAN_HTTP_TIMEOUT,
            follow_redirects=True,
            trust_env=False,
        )
    except httpx.HTTPError as exc:
        return [
            {
                "category": "headers",
                "severity": "info",
                "title": "Impossible d'analyser les en-têtes",
                "description": f"Requête HTTP échouée : {exc}",
                "evidence": None,
                "recommendation": None,
            }
        ]
    return analyze_headers(dict(response.headers))
