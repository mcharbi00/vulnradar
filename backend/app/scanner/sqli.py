# Détection d'injection SQL error-based : on injecte un guillemet et on regarde
# si la réponse contient un message d'erreur SQL. Rien de destructif.
from __future__ import annotations

import httpx

from app.core.config import get_settings

settings = get_settings()

PROBE = "'"

# Signatures d'erreurs typiques renvoyées par les moteurs SQL les plus courants.
ERROR_SIGNATURES = [
    "sql syntax",
    "sqlite3.operationalerror",
    "sqlite3.programmingerror",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "psycopg2",
    "pg::syntaxerror",
    "mysql_fetch",
    "you have an error in your sql syntax",
    "ora-00933",
    "warning: mysqli",
    "sqlstate",
]

DEFAULT_PARAMS = ["id", "user", "search", "q", "category"]


def matches_error_signature(response_body: str) -> str | None:
    """Retourne la première signature d'erreur SQL trouvée dans la réponse, sinon None."""
    lowered = response_body.lower()
    for signature in ERROR_SIGNATURES:
        if signature in lowered:
            return signature
    return None


def _probe_params(url: str, params: list[str]) -> list[dict]:
    findings: list[dict] = []
    for param in params:
        try:
            baseline = httpx.get(
                url,
                timeout=settings.SCAN_HTTP_TIMEOUT,
                follow_redirects=True,
                trust_env=False,
            )
            probed = httpx.get(
                url,
                params={param: PROBE},
                timeout=settings.SCAN_HTTP_TIMEOUT,
                follow_redirects=True,
                trust_env=False,
            )
        except httpx.HTTPError:
            continue

        signature = matches_error_signature(probed.text)
        # évite un faux positif si le mot est déjà présent dans la page normale
        if signature and signature not in baseline.text.lower():
            findings.append(
                {
                    "category": "sqli",
                    "severity": "critical",
                    "title": f"Injection SQL potentielle sur le paramètre '{param}'",
                    "description": (
                        "L'ajout d'un guillemet simple dans ce paramètre provoque "
                        "une erreur de base de données visible dans la réponse, "
                        "signe que l'entrée n'est pas correctement paramétrée."
                    ),
                    "evidence": f"Signature détectée : '{signature}'",
                    "recommendation": (
                        "Utiliser des requêtes paramétrées (prepared statements) "
                        "ou un ORM, et désactiver l'affichage des erreurs SQL brutes "
                        "en production."
                    ),
                }
            )
    return findings


def scan_sqli(target_url: str, endpoints: list[dict] | None = None) -> list[dict]:
    """Teste l'injection SQL sur `target_url` (paramètres par défaut) et, si
    fournis, sur des `endpoints` découverts par le crawl."""
    findings = _probe_params(target_url, DEFAULT_PARAMS)

    for endpoint in endpoints or []:
        findings.extend(_probe_params(endpoint["url"], endpoint["params"]))

    return findings
