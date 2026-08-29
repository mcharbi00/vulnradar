# VulnRadar

![CI](https://github.com/mcharbi00/vulnradar/actions/workflows/ci.yml/badge.svg)

Un scanner de vulnérabilités web que j'ai construit pour me former à la sécurité applicative et à FastAPI. On lui donne une cible, il lance une série de checks (en-têtes HTTP, cookies, HTTPS, ports ouverts, XSS, injection SQL, fichiers exposés) et il renvoie un rapport avec un score et le détail des problèmes trouvés.

Le projet est fourni avec une petite appli volontairement vulnérable (`demo-target`) qui sert de cible d'entraînement, donc tout peut se tester en local sans toucher à un vrai site.

## Avertissement

C'est un outil d'apprentissage. Par défaut le backend refuse toute cible qui n'est pas dans `ALLOWED_SCAN_HOSTS` (le `demo-target`, `localhost`, `127.0.0.1`). Scanner un site qui ne vous appartient pas sans autorisation est illégal — n'élargissez cette liste qu'à des machines que vous avez le droit de tester.

## Stack

- **Backend** : FastAPI, SQLAlchemy, PostgreSQL (SQLite en local), JWT, WebSocket
- **Frontend** : React (Vite), React Router, Tailwind
- **Infra** : Docker / docker-compose

## Ce que le scanner détecte

- En-têtes de sécurité manquants (CSP, HSTS, X-Frame-Options, etc.)
- Cookies sans `Secure` / `HttpOnly` / `SameSite`
- Absence de HTTPS, certificat expiré
- Ports TCP ouverts (avec une alerte sur les services sensibles type MySQL, Redis, RDP)
- XSS réfléchi (via un marqueur inoffensif, sans exécuter de script)
- Injection SQL (détectée sur les messages d'erreur SQL renvoyés)
- Fichiers/chemins sensibles laissés accessibles (`.env`, `/admin`, etc.)

Le score part de 100 et baisse selon la gravité de ce qui est trouvé. Chaque scan est stocké en base et consultable dans l'historique, avec la progression affichée en direct via WebSocket pendant l'exécution.

## Lancer le projet

### Avec Docker

```bash
git clone https://github.com/mcharbi00/vulnradar.git
cd vulnradar
cp .env.example .env
docker compose up --build
```

- App : http://localhost:5173
- API (Swagger) : http://localhost:8000/docs

Crée un compte depuis l'interface, puis lance un scan sur `demo-target`.

### Sans Docker

Trois terminaux. Backend :

```bash
cd backend
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
alembic upgrade head        # crée / met à jour les tables
uvicorn app.main:app --reload
```

Cible de test :

```bash
cd demo-target
pip install -r requirements.txt
uvicorn app:app --port 8001
```

Frontend :

```bash
cd frontend
cp .env.example .env
npm install
npm run dev
```

Puis scanner `127.0.0.1:8001` depuis le dashboard.

## Tests

```bash
cd backend
pytest
```

Les modules de détection (en-têtes, cookies, XSS, SQLi, calcul du score) sont couverts par des tests unitaires qui n'ont pas besoin de réseau.

## Notes

Le moteur de scan tourne en asynchrone directement dans l'API : chaque check bloquant est envoyé dans un threadpool et la progression est poussée aux clients connectés via WebSocket. J'ai découpé les checks en modules indépendants (`backend/app/scanner/`) pour pouvoir en ajouter facilement.

Quelques idées que j'aimerais ajouter plus tard : export PDF des rapports, rejeu automatique d'un scan à intervalle régulier, et une détection de versions de services connues.
