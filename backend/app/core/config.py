import os
from functools import lru_cache


class Settings:
    """Configuration centralisée, lue depuis les variables d'environnement.

    Voir .env.example à la racine du projet pour la liste complète.
    """

    PROJECT_NAME: str = "VulnRadar"

    DATABASE_URL: str = os.getenv(
        "DATABASE_URL", "sqlite:///./vulnradar.db"
    )

    SECRET_KEY: str = os.getenv("SECRET_KEY", "change-me-in-production")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = int(
        os.getenv("ACCESS_TOKEN_EXPIRE_MINUTES", "60")
    )

    # Cibles autorisées au scan (par défaut le demo-target + localhost).
    # On bloque tout le reste pour éviter de scanner un site sans autorisation.
    ALLOWED_SCAN_HOSTS: list[str] = [
        h.strip()
        for h in os.getenv(
            "ALLOWED_SCAN_HOSTS", "demo-target,localhost,127.0.0.1"
        ).split(",")
        if h.strip()
    ]

    CORS_ORIGINS: list[str] = [
        o.strip()
        for o in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",")
        if o.strip()
    ]

    # Autorise n'importe quel localhost / 127.0.0.1 (tout port) en dev, sans
    # avoir à lister chaque port Vite à la main. Mettre à None pour désactiver.
    CORS_ORIGIN_REGEX: str | None = os.getenv(
        "CORS_ORIGIN_REGEX", r"http://(localhost|127\.0\.0\.1):\d+"
    )

    # Ports scannés par le module de scan réseau (services les plus courants).
    COMMON_PORTS: list[int] = [21, 22, 23, 25, 53, 80, 110, 143, 443, 3306, 3389, 5432, 6379, 8000, 8080, 8443]

    SCAN_HTTP_TIMEOUT: float = float(os.getenv("SCAN_HTTP_TIMEOUT", "5"))
    SCAN_PORT_TIMEOUT: float = float(os.getenv("SCAN_PORT_TIMEOUT", "0.75"))


@lru_cache
def get_settings() -> Settings:
    return Settings()
