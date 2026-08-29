# Cible de test pour VulnRadar. Elle contient des failles faites exprès
# (headers manquants, XSS, injection SQL, fichiers exposés) pour avoir quelque
# chose à scanner en local. À ne pas mettre en ligne.
import sqlite3
from pathlib import Path

from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse

app = FastAPI(title="VulnRadar Demo Target (delibérément vulnérable)")

# CORS mal configuré exprès : reflète n'importe quelle origine + credentials
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=".*",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = Path(__file__).parent / "demo.db"


def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("DROP TABLE IF EXISTS users")
    conn.execute("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, role TEXT)")
    conn.executemany(
        "INSERT INTO users (id, name, role) VALUES (?, ?, ?)",
        [(1, "alice", "admin"), (2, "bob", "user"), (3, "carol", "user")],
    )
    conn.commit()
    conn.close()


init_db()


@app.options("/")
def options_root():
    # déclare exprès des méthodes dangereuses (PUT, DELETE, TRACE)
    return Response(
        status_code=200,
        headers={"Allow": "GET, POST, PUT, DELETE, TRACE, OPTIONS"},
    )


@app.get("/", response_class=HTMLResponse)
def home():
    # pas d'en-têtes de sécurité, exprès
    return """
    <html>
      <head><title>Demo Target</title></head>
      <body>
        <h1>VulnRadar Demo Target</h1>
        <p>Cible de test avec des failles faites exprès.</p>
        <ul>
          <li><a href="/search?q=test">/search?q=</a> — XSS réfléchi</li>
          <li><a href="/users?id=1">/users?id=</a> — Injection SQL</li>
        </ul>
      </body>
    </html>
    """


@app.get("/search", response_class=HTMLResponse)
def search(q: str = ""):
    # Vulnérabilité volontaire : la donnée utilisateur est réinjectée sans
    # échappement dans le HTML -> XSS réfléchi.
    return f"<html><body><h2>Résultats pour : {q}</h2></body></html>"


@app.get("/users")
def get_user(id: str = "1"):
    # requête construite par concaténation au lieu d'un paramètre -> injection SQL
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    query = f"SELECT id, name, role FROM users WHERE id = {id}"
    try:
        cursor.execute(query)
        rows = cursor.fetchall()
        conn.close()
        return JSONResponse([{"id": r[0], "name": r[1], "role": r[2]} for r in rows])
    except sqlite3.Error as exc:
        conn.close()
        # on renvoie l'erreur SQL brute (comme une app en mode debug) : c'est ce
        # que le scanner repère
        return JSONResponse(
            status_code=500,
            content={"error": f"sqlite3.OperationalError: {exc}", "query": query},
        )


@app.get("/.env", response_class=PlainTextResponse)
def leaked_env():
    # Vulnérabilité volontaire : fichier de config exposé publiquement.
    return "DATABASE_URL=sqlite:///demo.db\nSECRET_KEY=not-so-secret\n"


@app.get("/admin", response_class=HTMLResponse)
def leaked_admin():
    # Vulnérabilité volontaire : panneau d'administration accessible sans authentification.
    return "<html><body><h1>Panel Admin (non protégé)</h1></body></html>"
