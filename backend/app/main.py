from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import auth, scans
from app.core.config import get_settings

settings = get_settings()

# Les tables sont créées et mises à jour par les migrations Alembic
# (alembic upgrade head), pas au démarrage de l'application.

app = FastAPI(
    title=settings.PROJECT_NAME,
    description=(
        "Scanner de vulnérabilités web fullstack — détection de failles courantes "
        "(en-têtes, cookies, TLS, ports, XSS, SQLi, chemins exposés) avec rapport "
        "et historique de scans. Usage pédagogique, sur cibles autorisées uniquement."
    ),
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    # En dev, le front peut tourner sur localhost ou 127.0.0.1 et sur un port
    # Vite variable : on autorise tout localhost/127.0.0.1 par regex pour éviter
    # les erreurs CORS, tout en gardant la liste explicite pour la prod.
    allow_origin_regex=settings.CORS_ORIGIN_REGEX,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(scans.router)


@app.get("/api/health", tags=["health"])
def health_check():
    return {"status": "ok", "service": settings.PROJECT_NAME}
