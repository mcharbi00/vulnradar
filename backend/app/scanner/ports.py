"""Scan de ports TCP basique (connect scan), inspiré du module réseau de cyber-dashboard."""
from __future__ import annotations

import socket
from urllib.parse import urlparse

from app.core.config import get_settings

settings = get_settings()

COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    143: "IMAP",
    443: "HTTPS",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    6379: "Redis",
    8000: "HTTP-alt",
    8080: "HTTP-alt",
    8443: "HTTPS-alt",
}

SENSITIVE_PORTS = {23, 3306, 3389, 5432, 6379}


def _extract_host(target: str) -> str:
    if "://" in target:
        return urlparse(target).hostname or target
    return target.split(":")[0]


def scan_ports(target: str, ports: list[int] | None = None) -> list[dict]:
    host = _extract_host(target)
    ports = ports or settings.COMMON_PORTS
    findings: list[dict] = []
    open_ports: list[int] = []

    for port in ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(settings.SCAN_PORT_TIMEOUT)
            result = sock.connect_ex((host, port))
            if result == 0:
                open_ports.append(port)

    for port in open_ports:
        service = COMMON_SERVICES.get(port, "inconnu")
        severity = "medium" if port in SENSITIVE_PORTS else "info"
        findings.append(
            {
                "category": "ports",
                "severity": severity,
                "title": f"Port {port} ouvert ({service})",
                "description": f"Le port {port} répond aux connexions TCP entrantes.",
                "evidence": f"{host}:{port} -> OPEN",
                "recommendation": (
                    "Vérifier que ce service doit être exposé publiquement, "
                    "sinon le fermer ou le restreindre par pare-feu."
                    if severity == "medium"
                    else None
                ),
            }
        )

    return findings
