import socket
import threading
import time

import httpx
import pytest
import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from app.scanner.engine import run_scan


def make_vulnerable_app():
    app = FastAPI()

    @app.get("/", response_class=HTMLResponse)
    def home():
        return '<html><body><a href="/search?q=test">recherche</a></body></html>'

    @app.get("/search", response_class=HTMLResponse)
    def search(q: str = ""):
        return f"<html><body><h2>{q}</h2></body></html>"

    return app


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture
def live_target():
    port = free_port()
    config = uvicorn.Config(
        make_vulnerable_app(), host="127.0.0.1", port=port, log_level="warning"
    )
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    base_url = f"http://127.0.0.1:{port}"
    for _ in range(50):
        try:
            httpx.get(base_url, timeout=0.5, trust_env=False)
            break
        except httpx.HTTPError:
            time.sleep(0.1)

    yield base_url

    server.should_exit = True
    thread.join(timeout=5)


def test_scan_detecte_les_vulnerabilites(live_target):
    findings, score = run_scan(live_target)
    categories = {f["category"] for f in findings}

    assert "headers" in categories
    assert "xss" in categories
    assert score < 100
