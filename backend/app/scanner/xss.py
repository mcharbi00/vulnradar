# Détection de XSS réfléchi : on injecte un marqueur unique dans les paramètres
# et on vérifie s'il ressort non échappé dans le HTML. Pas d'exécution de script.
from __future__ import annotations

import httpx

from app.core.config import get_settings

settings = get_settings()

# Marqueur inoffensif (pas de <script>) : une balise custom qui ne peut
# apparaître dans la réponse que si l'entrée est réfléchie sans échappement.
MARKER = "vulnradar-xss-marker"
PAYLOAD = f'"><vulnradar-probe id="{MARKER}">'

DEFAULT_PARAMS = ["q", "search", "id", "query", "name", "term"]


def is_reflected_unescaped(response_body: str, payload: str = PAYLOAD) -> bool:
    """Vrai si le payload ressort tel quel (non échappé) dans la réponse."""
    return payload in response_body


def _probe_params(url: str, params: list[str]) -> list[dict]:
    findings: list[dict] = []
    for param in params:
        try:
            response = httpx.get(
                url,
                params={param: PAYLOAD},
                timeout=settings.SCAN_HTTP_TIMEOUT,
                follow_redirects=True,
                trust_env=False,
            )
        except httpx.HTTPError:
            continue

        if is_reflected_unescaped(response.text):
            findings.append(
                {
                    "category": "xss",
                    "severity": "high",
                    "title": f"XSS réfléchi potentiel sur le paramètre '{param}'",
                    "description": (
                        "Le paramètre est renvoyé dans la réponse HTML sans être "
                        "échappé, ce qui permettrait d'injecter du HTML/JS arbitraire."
                    ),
                    "evidence": f"{url}?{param}={PAYLOAD}",
                    "recommendation": (
                        "Échapper systématiquement les entrées utilisateur avant de "
                        "les insérer dans le HTML, ou utiliser un moteur de template "
                        "avec échappement automatique."
                    ),
                }
            )
    return findings


def scan_xss(target_url: str, endpoints: list[dict] | None = None) -> list[dict]:
    """Teste le XSS réfléchi sur `target_url` (paramètres par défaut) et, si
    fournis, sur des `endpoints` découverts par le crawl (chacun avec ses
    propres paramètres) — ex: [{"url": ".../search", "params": ["q"]}]."""
    findings = _probe_params(target_url, DEFAULT_PARAMS)

    for endpoint in endpoints or []:
        findings.extend(_probe_params(endpoint["url"], endpoint["params"]))

    return findings
