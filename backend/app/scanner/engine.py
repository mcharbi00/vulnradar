"""Moteur d'orchestration : enchaîne tous les modules de scan et calcule un score."""
from __future__ import annotations

from typing import Awaitable, Callable
from urllib.parse import urlparse

from starlette.concurrency import run_in_threadpool

from app.scanner import cookies, dirs, discovery, headers, methods, ports, sqli, tls, xss

SEVERITY_WEIGHTS = {
    "info": 0,
    "low": 2,
    "medium": 6,
    "high": 12,
    "critical": 20,
}

# Poids de progression par étape (doit totaliser 100).
STEP_WEIGHTS = {
    "discovery": 5,
    "headers": 10,
    "cookies": 10,
    "tls": 10,
    "ports": 15,
    "xss": 15,
    "sqli": 15,
    "dirs": 10,
    "methods": 10,
}


def normalize_target(target: str) -> str:
    """Garantit un schéma http(s) pour les modules qui en ont besoin."""
    if "://" not in target:
        return f"http://{target}"
    return target


def compute_score(findings: list[dict]) -> float:
    penalty = sum(SEVERITY_WEIGHTS.get(f["severity"], 0) for f in findings)
    return max(0.0, round(100 - penalty, 1))


def get_hostname(target: str) -> str:
    parsed = urlparse(normalize_target(target))
    return parsed.hostname or target


def run_scan(
    target: str, on_progress: Callable[[int, str], None] | None = None
) -> tuple[list[dict], float]:
    """Exécute toutes les étapes de scan de façon synchrone et retourne
    (liste de findings, score). `on_progress(percent, label)` est appelé après
    chaque étape pour permettre un suivi en temps réel (ex: via WebSocket)."""
    url = normalize_target(target)
    all_findings: list[dict] = []
    progress = 0

    def step(key: str, label: str, scan_fn: Callable[[], list[dict]]) -> None:
        nonlocal progress
        try:
            findings = scan_fn()
        except Exception as exc:  # une étape qui échoue ne doit pas casser tout le scan
            findings = [
                {
                    "category": "engine",
                    "severity": "info",
                    "title": f"Étape '{label}' interrompue",
                    "description": str(exc),
                    "evidence": None,
                    "recommendation": None,
                }
            ]
        all_findings.extend(findings)
        progress = min(100, progress + STEP_WEIGHTS[key])
        if on_progress:
            on_progress(progress, label)

    # 1. Découverte des endpoints avec paramètres (crawl 1 niveau de la page
    #    d'accueil) — permet aux modules XSS/SQLi de tester les vrais points
    #    d'entrée de l'appli plutôt que de deviner à l'aveugle sur la racine.
    endpoints: list[dict] = []

    def discover() -> list[dict]:
        nonlocal endpoints
        endpoints = discovery.discover_query_endpoints(url)
        return []

    step("discovery", "Découverte des points d'entrée", discover)

    step("headers", "En-têtes de sécurité", lambda: headers.scan_headers(url))
    step("cookies", "Cookies", lambda: cookies.scan_cookies(url))
    step("tls", "TLS / HTTPS", lambda: tls.scan_tls(url))
    step("ports", "Ports ouverts", lambda: ports.scan_ports(url))
    step("xss", "XSS réfléchi", lambda: xss.scan_xss(url, endpoints=endpoints))
    step("sqli", "Injection SQL", lambda: sqli.scan_sqli(url, endpoints=endpoints))
    step("dirs", "Fichiers/chemins exposés", lambda: dirs.scan_dirs(url))
    step("methods", "Méthodes HTTP", lambda: methods.scan_http_methods(url))

    score = compute_score(all_findings)
    return all_findings, score


async def run_scan_async(
    target: str, on_progress: Callable[[int, str], Awaitable[None]] | None = None
) -> tuple[list[dict], float]:
    """Équivalent async de `run_scan`, utilisé par l'API. Chaque étape (bloquante,
    réseau synchrone) est déportée dans un threadpool via `run_in_threadpool`,
    mais tout le reste tourne sur la boucle d'événements de l'application —
    contrairement à un job lancé dans un thread à part, `on_progress` peut donc
    être une coroutine (ex: diffusion WebSocket) sans jonglage entre boucles."""
    url = normalize_target(target)
    all_findings: list[dict] = []
    progress = 0
    endpoints: list[dict] = []

    async def step(key: str, label: str, scan_fn: Callable[[], list[dict]]) -> None:
        nonlocal progress
        try:
            findings = await run_in_threadpool(scan_fn)
        except Exception as exc:  # une étape qui échoue ne doit pas casser tout le scan
            findings = [
                {
                    "category": "engine",
                    "severity": "info",
                    "title": f"Étape '{label}' interrompue",
                    "description": str(exc),
                    "evidence": None,
                    "recommendation": None,
                }
            ]
        all_findings.extend(findings)
        progress = min(100, progress + STEP_WEIGHTS[key])
        if on_progress:
            await on_progress(progress, label)

    async def discover() -> None:
        nonlocal endpoints
        endpoints = await run_in_threadpool(discovery.discover_query_endpoints, url)

    try:
        await discover()
    except Exception:
        endpoints = []
    progress = min(100, progress + STEP_WEIGHTS["discovery"])
    if on_progress:
        await on_progress(progress, "Découverte des points d'entrée")

    await step("headers", "En-têtes de sécurité", lambda: headers.scan_headers(url))
    await step("cookies", "Cookies", lambda: cookies.scan_cookies(url))
    await step("tls", "TLS / HTTPS", lambda: tls.scan_tls(url))
    await step("ports", "Ports ouverts", lambda: ports.scan_ports(url))
    await step("xss", "XSS réfléchi", lambda: xss.scan_xss(url, endpoints=endpoints))
    await step("sqli", "Injection SQL", lambda: sqli.scan_sqli(url, endpoints=endpoints))
    await step("dirs", "Fichiers/chemins exposés", lambda: dirs.scan_dirs(url))
    await step("methods", "Méthodes HTTP", lambda: methods.scan_http_methods(url))

    score = compute_score(all_findings)
    return all_findings, score
