# Gère les connexions WebSocket pour envoyer la progression des scans.
# Stockage en mémoire (dict), suffisant pour une seule instance du backend.
from __future__ import annotations

from fastapi import WebSocket


class ScanProgressManager:
    def __init__(self) -> None:
        self._connections: dict[int, list[WebSocket]] = {}

    async def connect(self, scan_id: int, websocket: WebSocket) -> None:
        await websocket.accept()
        self._connections.setdefault(scan_id, []).append(websocket)

    def disconnect(self, scan_id: int, websocket: WebSocket) -> None:
        if scan_id in self._connections and websocket in self._connections[scan_id]:
            self._connections[scan_id].remove(websocket)
            if not self._connections[scan_id]:
                del self._connections[scan_id]

    async def broadcast(self, scan_id: int, message: dict) -> None:
        for connection in list(self._connections.get(scan_id, [])):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(scan_id, connection)


manager = ScanProgressManager()
