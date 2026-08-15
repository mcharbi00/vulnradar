"""Vérifications TLS/HTTPS basiques : usage de HTTPS et expiration du certificat."""
from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse


def scan_tls(target_url: str) -> list[dict]:
    findings: list[dict] = []
    parsed = urlparse(target_url if "://" in target_url else f"http://{target_url}")

    if parsed.scheme != "https":
        findings.append(
            {
                "category": "tls",
                "severity": "high",
                "title": "Site accessible en HTTP non chiffré",
                "description": "La cible ne force pas HTTPS : les données transitent en clair.",
                "evidence": f"URL testée : {target_url}",
                "recommendation": "Forcer une redirection vers HTTPS et activer HSTS.",
            }
        )
        return findings

    host = parsed.hostname
    port = parsed.port or 443

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((host, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert = ssock.getpeercert()
    except (socket.error, ssl.SSLError, TimeoutError) as exc:
        findings.append(
            {
                "category": "tls",
                "severity": "medium",
                "title": "Impossible de vérifier le certificat TLS",
                "description": f"Connexion TLS échouée : {exc}",
                "evidence": None,
                "recommendation": "Vérifier la configuration TLS du serveur.",
            }
        )
        return findings

    not_after = cert.get("notAfter")
    if not_after:
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        days_left = (expiry - datetime.now(timezone.utc)).days
        if days_left < 0:
            findings.append(
                {
                    "category": "tls",
                    "severity": "critical",
                    "title": "Certificat TLS expiré",
                    "description": f"Le certificat a expiré depuis {-days_left} jour(s).",
                    "evidence": f"notAfter={not_after}",
                    "recommendation": "Renouveler immédiatement le certificat.",
                }
            )
        elif days_left < 15:
            findings.append(
                {
                    "category": "tls",
                    "severity": "medium",
                    "title": "Certificat TLS bientôt expiré",
                    "description": f"Le certificat expire dans {days_left} jour(s).",
                    "evidence": f"notAfter={not_after}",
                    "recommendation": "Planifier le renouvellement du certificat.",
                }
            )

    return findings
