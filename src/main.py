"""Secure Digital Voting System — web UI + API."""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from src.api_routes import router as api_router
from src.bootstrap import ensure_bootstrap
from src.config import settings

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("voting")

BASE_DIR = Path(__file__).resolve().parent.parent


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings.data_dir.mkdir(parents=True, exist_ok=True)
    (settings.data_dir / "uploads").mkdir(parents=True, exist_ok=True)
    ensure_bootstrap(
        settings.db_file(),
        settings.admin_password,
        settings.election_starts_at,
        settings.election_ends_at,
    )
    if settings.jwt_secret == "change-me-in-production-use-long-random-secret":
        logger.warning("JWT_SECRET is the built-in default; anyone can forge sessions. Set it in .env.")
    if settings.admin_password == "admin-change-me":
        logger.warning("ADMIN_PASSWORD is the built-in default. Set it in .env.")
    if settings.expose_otp_in_response and (settings.otp_delivery_mode or "demo").strip().lower() != "smtp":
        logger.warning("Demo OTP mode: login codes are returned in API responses. Do not deploy like this.")
    if not settings.key_encryption_secret:
        logger.warning("KEY_ENCRYPTION_SECRET is not set; election keys are wrapped with a key derived from JWT_SECRET.")
    roster = sorted(settings.allowed_student_emails())
    logger.info(
        "Application started; database at %s; authorized student roster (%s): %s",
        settings.db_file(),
        len(roster),
        ", ".join(roster) if roster else "(empty — no students can register)",
    )
    yield


app = FastAPI(title="Secure Digital Voting System", lifespan=lifespan)

CONTENT_SECURITY_POLICY = "; ".join(
    [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self'",
        "font-src 'self'",
        "img-src 'self' data:",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'",
    ]
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    h = response.headers
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("X-Frame-Options", "DENY")
    h.setdefault("Referrer-Policy", "no-referrer")
    h.setdefault("Content-Security-Policy", CONTENT_SECURITY_POLICY)
    if request.url.path.startswith("/api"):
        # Responses carry tokens, OTP state and keys: never cache them.
        h.setdefault("Cache-Control", "no-store")
    if request.url.scheme == "https" and request.url.hostname != "localhost":
        # Tell browsers to use HTTPS only from now on. Skipped for "localhost" so other local
        # development servers on this machine are not forced to HTTPS by the browser.
        h.setdefault("Strict-Transport-Security", "max-age=31536000")
    return response


@app.get("/api/security/transport")
def transport_info(request: Request):
    """What the server sees about this connection (used by the UI badge and for demos)."""
    secure = request.url.scheme == "https"
    return {
        "scheme": request.url.scheme,
        "tls": secure,
        "minimum_tls_version": "TLSv1.2" if secure else None,
    }


app.include_router(api_router, prefix="/api")

app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
_upload_root = settings.data_dir / "uploads"
_upload_root.mkdir(parents=True, exist_ok=True)
app.mount("/uploads", StaticFiles(directory=str(_upload_root)), name="uploads")

templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(
        request,
        "app.html",
        {"app_name": "SecureVote"},
    )


@app.get("/health")
def health():
    return {"status": "ok"}
