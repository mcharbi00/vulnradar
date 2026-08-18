import asyncio
from datetime import datetime
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect, status
from sqlalchemy.orm import Session

from app import schemas
from app.core.config import get_settings
from app.core.security import get_current_user
from app.db import models
from app.db.database import SessionLocal, get_db
from app.scanner.engine import run_scan_async
from app.ws_manager import manager

router = APIRouter(prefix="/api/scans", tags=["scans"])
settings = get_settings()


def _hostname(target: str) -> str:
    url = target if "://" in target else f"http://{target}"
    return (urlparse(url).hostname or target).lower()


def assert_target_allowed(target: str) -> None:
    host = _hostname(target)
    if host not in settings.ALLOWED_SCAN_HOSTS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                f"Cible '{host}' non autorisée. VulnRadar ne scanne que les hôtes de "
                f"ALLOWED_SCAN_HOSTS ({', '.join(settings.ALLOWED_SCAN_HOSTS)}) — "
                "n'utilisez cet outil que sur des systèmes que vous possédez ou "
                "êtes explicitement autorisé·e à tester."
            ),
        )


async def _run_scan_job(scan_id: int, target: str) -> None:
    """Tâche de fond : reste sur la boucle d'événements de l'appli (pas de
    thread séparé), ce qui permet de diffuser la progression en WebSocket
    sans jonglage entre boucles asyncio."""
    db: Session = SessionLocal()
    try:
        scan = db.get(models.Scan, scan_id)
        scan.status = models.ScanStatus.running
        db.commit()

        async def on_progress(percent: int, label: str) -> None:
            scan.progress = percent
            db.commit()
            await manager.broadcast(
                scan_id, {"type": "progress", "progress": percent, "step": label}
            )

        findings, score = await run_scan_async(target, on_progress=on_progress)

        for f in findings:
            db.add(models.Finding(scan_id=scan_id, **f))

        scan.status = models.ScanStatus.completed
        scan.progress = 100
        scan.score = score
        scan.finished_at = datetime.utcnow()
        db.commit()

        await manager.broadcast(scan_id, {"type": "completed", "score": score})
    except Exception as exc:
        scan = db.get(models.Scan, scan_id)
        if scan:
            scan.status = models.ScanStatus.failed
            scan.error = str(exc)
            scan.finished_at = datetime.utcnow()
            db.commit()
        await manager.broadcast(scan_id, {"type": "failed", "error": str(exc)})
    finally:
        db.close()


@router.post("", response_model=schemas.ScanOut, status_code=status.HTTP_201_CREATED)
async def create_scan(
    payload: schemas.ScanCreate,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    assert_target_allowed(payload.target)

    scan = models.Scan(owner_id=current_user.id, target=payload.target)
    db.add(scan)
    db.commit()
    db.refresh(scan)

    asyncio.create_task(_run_scan_job(scan.id, payload.target))

    return scan


@router.get("", response_model=list[schemas.ScanOut])
def list_scans(
    db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)
):
    return (
        db.query(models.Scan)
        .filter(models.Scan.owner_id == current_user.id)
        .order_by(models.Scan.started_at.desc())
        .all()
    )


@router.get("/{scan_id}", response_model=schemas.ScanDetailOut)
def get_scan(
    scan_id: int,
    db: Session = Depends(get_db),
    current_user: models.User = Depends(get_current_user),
):
    scan = (
        db.query(models.Scan)
        .filter(models.Scan.id == scan_id, models.Scan.owner_id == current_user.id)
        .first()
    )
    if not scan:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    return scan


@router.websocket("/{scan_id}/ws")
async def scan_progress_ws(websocket: WebSocket, scan_id: int):
    await manager.connect(scan_id, websocket)
    try:
        while True:
            # On ne traite pas de messages entrants, on garde juste la connexion ouverte.
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(scan_id, websocket)
