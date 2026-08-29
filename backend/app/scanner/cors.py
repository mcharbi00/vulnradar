# Détection de CORS mal configuré : on envoie une origine bidon et on regarde
# si le serveur l'accepte (reflète l'origine + autorise les credentials).
from __future__ import annotations

import httpx

from app.core.config import get_settings

settings = get_settings()

PROBE_ORIGIN = "https://vulnradar-cors-probe.example"


def analyze_cors(sent_origin: str, headers: dict) -> list[dict]:
    h = {k.lower(): v for k, v in headers.items()}
    acao = h.get("access-control-allow-origin")
    credentials = h.get("access-control-allow-credentials", "").lower() == "true"

    if not acao:
        return []

    # le serveur renvoie exactement l'origine bidon qu'on a envoyée -> il accepte tout
    if acao == sent_origin:
        if credentials:
            return [
                {
                    "category": "cors",
                    "severity": "high",
                    "title": "CORS mal configuré (origine reflétée + credentials)",
                    "description": (
                        "Le serveur accepte n'importe quelle origine ET autorise l'envoi "
                        "des cookies. Un site malveillant peut lire les données d'un "
                        "utilisateur connecté."
                    ),
                    "evidence": f"Origin envoyé: {sent_origin} -> Access-Control-Allow-Origin: {acao}, credentials: true",
                    "recommendation": "N'autoriser qu'une liste précise d'origines de confiance.",
                }
            ]
        return [
            {
                "category": "cors",
                "severity": "medium",
                "title": "CORS trop permissif (origine reflétée)",
                "description": "Le serveur reflète n'importe quelle origine dans Access-Control-Allow-Origin.",
                "evidence": f"Origin envoyé: {sent_origin} -> Access-Control-Allow-Origin: {acao}",
                "recommendation": "Restreindre à une liste d'origines autorisées.",
            }
        ]

    # wildcard : ouvert à tous, mais le navigateur bloque les credentials -> impact plus faible
    if acao == "*":
        return [
            {
                "category": "cors",
                "severity": "low",
                "title": "CORS en wildcard (*)",
                "description": "Toutes les origines sont autorisées. Sans credentials l'impact reste limité, mais à surveiller.",
                "evidence": "Access-Control-Allow-Origin: *",
                "recommendation": "Préciser les origines autorisées au lieu de '*'.",
            }
        ]

    return []


def scan_cors(target_url: str) -> list[dict]:
    try:
        response = httpx.get(
            target_url,
            headers={"Origin": PROBE_ORIGIN},
            timeout=settings.SCAN_HTTP_TIMEOUT,
            follow_redirects=True,
            trust_env=False,
        )
    except httpx.HTTPError:
        return []
    return analyze_cors(PROBE_ORIGIN, dict(response.headers))
