from app.scanner.headers import analyze_headers
from app.scanner.cookies import analyze_cookies
from app.scanner.sqli import matches_error_signature
from app.scanner.methods import analyze_allow_header
from app.scanner.engine import compute_score


def test_headers_manquants():
    findings = analyze_headers({"content-type": "text/html"})
    assert len(findings) >= 6


def test_headers_ok():
    headers = {
        "content-security-policy": "default-src 'self'",
        "x-frame-options": "DENY",
        "x-content-type-options": "nosniff",
        "strict-transport-security": "max-age=63072000",
        "referrer-policy": "strict-origin-when-cross-origin",
        "permissions-policy": "geolocation=()",
        "server": "nginx",
    }
    assert analyze_headers(headers) == []


def test_cookie_sans_flags():
    findings = analyze_cookies(["session=abc123; Path=/"])
    # il manque Secure, HttpOnly et SameSite
    assert len(findings) == 3


def test_detecte_erreur_sql():
    assert matches_error_signature("sqlite3.OperationalError: near ...") is not None
    assert matches_error_signature("page normale") is None


def test_score():
    assert compute_score([]) == 100.0
    assert compute_score([{"severity": "critical"}]) == 80.0


def test_methodes_http_risquees():
    findings = analyze_allow_header("GET, POST, PUT, DELETE")
    titres = [f["title"] for f in findings]
    assert any("PUT" in t for t in titres)
    assert any("DELETE" in t for t in titres)


def test_methodes_http_ok():
    # GET/POST/HEAD ne sont pas dangereuses -> aucun problème
    assert analyze_allow_header("GET, POST, HEAD") == []
