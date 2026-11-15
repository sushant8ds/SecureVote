"""Transport security (TLS certificates, HTTPS redirect, headers) and key encryption at rest."""

import socket
import ssl
import sqlite3
import threading

import pytest
from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric import padding

from src.crypto_service import generate_rsa_keypair, is_wrapped_private_key, unwrap_private_key, wrap_private_key
from src.tls_setup import ensure_certificates, generate_certificates, harden_server_context
from tests.helpers import create_test_election


def test_generated_server_certificate_is_signed_by_local_ca(tmp_path):
    files = generate_certificates(tmp_path, ["vote.example.test"])
    ca = x509.load_pem_x509_certificate(files.ca_cert.read_bytes())
    cert = x509.load_pem_x509_certificate(files.server_cert.read_bytes())
    ca.public_key().verify(
        cert.signature, cert.tbs_certificate_bytes, padding.PKCS1v15(), cert.signature_hash_algorithm
    )
    assert ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert {"localhost", "vote.example.test"} <= set(san.get_values_for_type(x509.DNSName))
    assert "127.0.0.1" in {str(i) for i in san.get_values_for_type(x509.IPAddress)}
    assert cert.public_key().key_size == 2048
    assert (files.server_key.stat().st_mode & 0o077) == 0
    assert not (tmp_path / "ca_key.pem").exists()


def test_ensure_certificates_reuses_then_regenerates_for_new_host(tmp_path):
    first, created = ensure_certificates(tmp_path)
    assert created is True
    before = first.server_cert.read_bytes()
    _, created = ensure_certificates(tmp_path)
    assert created is False
    assert first.server_cert.read_bytes() == before
    _, created = ensure_certificates(tmp_path, ["10.1.2.3"])
    assert created is True


def _tls_echo_server(files):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(files.server_cert, files.server_key)
    harden_server_context(ctx)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(5)

    def serve():
        while True:
            try:
                conn, _ = sock.accept()
            except OSError:
                return
            try:
                with ctx.wrap_socket(conn, server_side=True) as tls:
                    tls.sendall(b"ok")
            except (ssl.SSLError, OSError):
                pass

    threading.Thread(target=serve, daemon=True).start()
    return sock, sock.getsockname()[1]


def test_tls_handshake_verifies_against_ca_and_rejects_old_protocols(tmp_path):
    files = generate_certificates(tmp_path)
    sock, port = _tls_echo_server(files)
    try:
        client = ssl.create_default_context(cafile=str(files.ca_cert))
        with client.wrap_socket(socket.create_connection(("127.0.0.1", port)), server_hostname="localhost") as tls:
            assert tls.version() in ("TLSv1.2", "TLSv1.3")
            assert tls.recv(2) == b"ok"

        # A client that does not trust our CA must fail certificate verification.
        with pytest.raises(ssl.SSLCertVerificationError):
            ssl.create_default_context().wrap_socket(
                socket.create_connection(("127.0.0.1", port)), server_hostname="localhost"
            )

        # A client limited to TLS 1.1 must be refused.
        old = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        old.check_hostname = False
        old.verify_mode = ssl.CERT_NONE
        try:
            old.minimum_version = ssl.TLSVersion.TLSv1
            old.maximum_version = ssl.TLSVersion.TLSv1_1
        except ValueError:
            pytest.skip("local OpenSSL cannot offer TLS 1.1")
        with pytest.raises((ssl.SSLError, OSError)):
            old.wrap_socket(socket.create_connection(("127.0.0.1", port)))
    finally:
        sock.close()


def test_security_headers_present(client):
    r = client.get("/")
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
    assert "script-src 'self'" in r.headers["Content-Security-Policy"]
    assert "Strict-Transport-Security" not in r.headers  # plain HTTP: HSTS must not be sent
    assert client.get("/api/elections").headers["Cache-Control"] == "no-store"
    assert client.get("/api/security/transport").json()["tls"] is False


def test_hsts_sent_over_https(client):
    from fastapi.testclient import TestClient

    with TestClient(client.app, base_url="https://vote.example.test") as c:
        r = c.get("/health")
        assert r.headers["Strict-Transport-Security"].startswith("max-age=")
        assert c.get("/api/security/transport").json()["tls"] is True


def test_page_loads_no_third_party_scripts(client):
    html = client.get("/").text
    assert "cdn.jsdelivr.net" not in html
    assert client.get("/static/js/vendor/forge.min.js").status_code == 200


def test_http_redirect_app_points_to_https():
    import asyncio

    from run import make_redirect_app

    sent = []

    async def go():
        scope = {
            "type": "http",
            "headers": [(b"host", b"127.0.0.1:8000")],
            "raw_path": b"/api/login",
            "query_string": b"a=1",
        }

        async def send(msg):
            sent.append(msg)

        await make_redirect_app(8443)(scope, None, send)

    asyncio.run(go())
    assert sent[0]["status"] == 308
    assert dict(sent[0]["headers"])[b"location"] == b"https://127.0.0.1:8443/api/login?a=1"


def test_private_key_wrap_roundtrip_and_tamper_detection():
    priv, _ = generate_rsa_keypair()
    wrapped = wrap_private_key(priv, "secret-one")
    assert is_wrapped_private_key(wrapped)
    assert "PRIVATE KEY" not in wrapped
    assert wrap_private_key(priv, "secret-one") != wrapped  # fresh salt + nonce every time
    assert unwrap_private_key(wrapped, "secret-one") == priv
    with pytest.raises(InvalidTag):
        unwrap_private_key(wrapped, "wrong-secret")
    head, ct = wrapped.rsplit("$", 1)
    flipped = ("A" if ct[10] != "A" else "B")
    with pytest.raises(InvalidTag):
        unwrap_private_key(f"{head}${ct[:10]}{flipped}{ct[11:]}", "secret-one")
    assert unwrap_private_key(priv.decode(), "anything") == priv  # legacy plaintext row


def test_election_private_key_is_encrypted_in_database(client, tmp_path):
    adm = client.post(
        "/api/admin/login", json={"username": "admin", "password": "test-admin-password"}
    ).json()["access_token"]
    eid = create_test_election(client, adm)
    conn = sqlite3.connect(tmp_path / "test_voting.db")
    stored = conn.execute("SELECT private_key_pem FROM elections WHERE id = ?", (eid,)).fetchone()[0]
    conn.close()
    assert stored.startswith("aes256gcm-pbkdf2$")
    assert "BEGIN" not in stored
