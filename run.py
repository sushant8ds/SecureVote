#!/usr/bin/env python3
"""Start SecureVote over HTTPS (TLS 1.2+), with a plain-HTTP listener that only redirects to HTTPS.

    python run.py                # https://127.0.0.1:8443/  (http://127.0.0.1:8000 redirects there)

Certificates are created on first start under <DATA_DIR>/tls/ (see src/tls_setup.py).
Settings (in .env): HOST, HTTPS_PORT, HTTP_REDIRECT_PORT (0 disables), TLS_CERT_FILE, TLS_KEY_FILE, TLS_HOSTS.
"""

from __future__ import annotations

import logging
import threading
from collections.abc import Callable

import uvicorn

from src.config import settings
from src.tls_setup import ensure_certificates, harden_server_context

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("voting")


def exposes_secrets(scope) -> bool:
    """A plain-HTTP API request that carries a body or a bearer token has already leaked it on the wire."""
    if not scope.get("path", "").startswith("/api"):
        return False
    headers = dict(scope.get("headers", []))
    has_body = headers.get(b"content-length", b"0") not in (b"", b"0") or b"transfer-encoding" in headers
    return scope.get("method", "GET") not in ("GET", "HEAD") or has_body or b"authorization" in headers


def make_redirect_app(https_port: int, on_cleartext: Callable[[dict], None] | None = None):
    """ASGI app: answer every plain-HTTP request with a permanent redirect to the HTTPS origin.

    The request is never processed. If it was an API call carrying credentials or a token,
    ``on_cleartext(scope)`` is called so the administrator can be alerted.
    """

    async def app(scope, receive, send):
        if scope["type"] != "http":
            return
        if on_cleartext and exposes_secrets(scope):
            try:
                on_cleartext(scope)
            except Exception:  # an alerting failure must never break the redirect
                logger.exception("Could not record the plain-HTTP alert")
        host = "127.0.0.1"
        for k, v in scope.get("headers", []):
            if k == b"host":
                host = v.decode("latin-1")
                break
        # strip the port (handles "name:port" and "[v6]:port")
        if host.startswith("["):
            host = host[: host.find("]") + 1]
        else:
            host = host.split(":", 1)[0]
        target = f"https://{host}" + ("" if https_port == 443 else f":{https_port}") + scope.get("raw_path", b"/").decode("latin-1")
        if scope.get("query_string"):
            target += "?" + scope["query_string"].decode("latin-1")
        body = b"This service is only available over HTTPS.\n"
        await send(
            {
                "type": "http.response.start",
                "status": 308,  # keeps the method; clients must not resend a body in clear text
                "headers": [
                    (b"location", target.encode("latin-1")),
                    (b"content-type", b"text/plain; charset=utf-8"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})

    return app


def alert_cleartext_request(scope) -> None:
    from src.alerts import record_alert
    from src.database import get_connection

    client = scope.get("client") or (None, None)
    with get_connection(settings.db_file()) as conn:
        record_alert(
            conn,
            "plaintext_http",
            detail=f"{scope.get('method')} {scope.get('path')} arrived on plain-HTTP port {settings.http_redirect_port} "
            "with a body or token, readable by anyone on the network. It was not processed; the client was sent to HTTPS.",
            detected_by=f"HTTP port {settings.http_redirect_port}",
            source_ip=client[0],
        )


def main() -> None:
    if settings.tls_cert_file and settings.tls_key_file:
        cert, key = str(settings.tls_cert_file), str(settings.tls_key_file)
        logger.info("Using TLS certificate from TLS_CERT_FILE / TLS_KEY_FILE")
    else:
        files, created = ensure_certificates(settings.tls_dir(), settings.tls_extra_hosts())
        cert, key = str(files.server_cert), str(files.server_key)
        if created:
            logger.info("Created a new local CA and server certificate in %s", settings.tls_dir())
        logger.info("To avoid browser warnings, trust this CA certificate: %s", files.ca_cert)

    config = uvicorn.Config(
        "src.main:app",
        host=settings.host,
        port=settings.https_port,
        ssl_certfile=cert,
        ssl_keyfile=key,
        log_level="info",
    )
    config.load()
    harden_server_context(config.ssl)

    if settings.http_redirect_port:
        redirect = uvicorn.Server(
            uvicorn.Config(
                make_redirect_app(settings.https_port, alert_cleartext_request),
                host=settings.host,
                port=settings.http_redirect_port,
                log_level="warning",
            )
        )
        threading.Thread(target=redirect.run, daemon=True, name="http-redirect").start()
        logger.info("HTTP port %s redirects to HTTPS", settings.http_redirect_port)

    logger.info("SecureVote: https://%s:%s/", settings.host, settings.https_port)
    uvicorn.Server(config).run()


if __name__ == "__main__":
    main()
