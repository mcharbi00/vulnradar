"""Énumération de chemins/fichiers sensibles couramment exposés par erreur."""
from __future__ import annotations

import httpx

from app.core.config import get_settings

settings = get_settings()

COMMON_PATHS = [
    ".env",
    ".git/config",
    "admin",
    "administrator",
    "backup.zip",
    "config.php",
    "wp-admin",
    "wp-login.php",
    ".well-known/security.txt",
    "api/docs",
    "swagger.json",
    "server-status",
    "phpinfo.php",
    "debug",
]

SENSITIVE_PATHS = {".env", ".git/config", "backup.zip", "config.php", "phpinfo.php"}


def scan_dirs(target_url: str, paths: list[str] | None = None) -> list[dict]:
    base = target_url.rstrip("/")
    paths = paths or COMMON_PATHS
    findings: list[dict] = []

    for path in paths:
        url = f"{base}/{path}"
        try:
            response = httpx.get(
                url,
                timeout=settings.SCAN_HTTP_TIMEOUT,
                follow_redirects=False,
                trust_env=False,
            )
        except httpx.HTTPError:
            continue

        if response.status_code < 400:
            severity = "high" if path in SENSITIVE_PATHS else "low"
            findings.append(
                {
                    "category": "dirs",
                    "severity": severity,
                    "title": f"Ressource accessible : /{path}",
                    "description": (
                        f"Le chemin /{path} répond avec le code {response.status_code} "
                        "et pourrait exposer des informations sensibles."
                    ),
                    "evidence": f"{url} -> HTTP {response.status_code}",
                    "recommendation": "Restreindre l'accès à cette ressource ou la retirer du serveur public.",
                }
            )

    return findings
