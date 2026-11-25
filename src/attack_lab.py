"""Server-side probes for the security lab.

A browser cannot open raw sockets, speak old TLS versions or read the database file, so these three
attacks are run by the server against its own public endpoints, exactly as an outside client would:

- ``run_sniff``: send a login over HTTPS while recording every byte on the wire (what someone on the
  same Wi-Fi captures), then the same request to the plain-HTTP port.
- ``run_tls_probe``: connect with a client limited to TLS 1.0/1.1, and connect a correctly configured
  client to an impostor server that presents its own self-signed certificate.
- ``run_db_theft``: copy ``voting.db`` and attack the copy offline with no access to the server's secrets.

Each returns ``{"outcome", "summary", "steps": [...]}`` for the lab page; the route records the alert.
"""

from __future__ import annotations

import hashlib
import json
import socket
import sqlite3
import ssl
import tempfile
import threading
import time
import warnings
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

import bcrypt
from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from src.crypto_service import decrypt_vote_ciphertext, unwrap_private_key
from src.secrets_store import DEFAULT_JWT_SECRET

TIMEOUT = 5.0
# A made-up victim: the email is not on the roster, so the login is refused and no account is touched.
VICTIM_EMAIL = "victim@lab.invalid"
VICTIM_PASSWORD = "Campus-WiFi-Secret-42"

_RECORD_TYPES = {20: "change cipher spec", 21: "alert", 22: "handshake", 23: "application data"}


@dataclass(frozen=True)
class Target:
    host: str
    https_port: int
    http_port: int
    cafile: str | None


def default_target(settings) -> Target:
    host = settings.host if settings.host not in ("0.0.0.0", "::", "") else "127.0.0.1"
    ca = settings.tls_dir() / "ca_cert.pem"
    custom = bool(settings.tls_cert_file and settings.tls_key_file)
    return Target(host, settings.https_port, settings.http_redirect_port, None if custom or not ca.is_file() else str(ca))


def step(title: str, status: str = "info", lines: list[str] | None = None, code: str | None = None) -> dict:
    """status: info | blocked | exposed | warn"""
    return {"title": title, "status": status, "lines": lines or [], "code": code}


def hexdump(data: bytes, limit: int = 96) -> str:
    out = []
    for off in range(0, min(len(data), limit), 16):
        chunk = data[off : off + 16]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out.append(f"{off:04x}  {hexpart:<47}  {text}")
    if len(data) > limit:
        out.append(f"…  {len(data) - limit} more bytes")
    return "\n".join(out)


def tls_records(data: bytes) -> list[str]:
    out, i = [], 0
    while i + 5 <= len(data):
        ctype, major, minor, length = data[i], data[i + 1], data[i + 2], int.from_bytes(data[i + 3 : i + 5], "big")
        out.append(f"TLS record: {_RECORD_TYPES.get(ctype, ctype)}, {length} bytes (header {major:02x} {minor:02x})")
        i += 5 + length
    return out


def _login_request(host_header: str) -> bytes:
    body = json.dumps({"voter_id": VICTIM_EMAIL, "password": VICTIM_PASSWORD}).encode()
    head = (
        f"POST /api/login HTTP/1.1\r\nHost: {host_header}\r\nContent-Type: application/json\r\n"
        f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n"
    ).encode()
    return head + body


def _client_context(target: Target) -> ssl.SSLContext:
    return ssl.create_default_context(cafile=target.cafile) if target.cafile else ssl.create_default_context()


def capture_tls_exchange(target: Target, request: bytes) -> dict:
    """Run one HTTPS request through a memory BIO so every byte sent on the socket can be recorded."""
    ctx = _client_context(target)
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    tls = ctx.wrap_bio(incoming, outgoing, server_hostname=target.host)
    wire_out = bytearray()
    sock = socket.create_connection((target.host, target.https_port), timeout=TIMEOUT)
    try:

        def flush() -> None:
            data = outgoing.read()
            if data:
                wire_out.extend(data)
                sock.sendall(data)

        def pump() -> bool:
            data = sock.recv(65536)
            if not data:
                return False
            incoming.write(data)
            return True

        deadline = time.monotonic() + TIMEOUT
        while True:
            if time.monotonic() > deadline:
                raise ConnectionError("TLS handshake timed out")
            try:
                tls.do_handshake()
                break
            except ssl.SSLWantReadError:
                flush()
                if not pump():
                    raise ConnectionError("server closed the connection during the handshake")
        flush()
        handshake_len = len(wire_out)
        tls.write(request)
        flush()
        app_bytes = bytes(wire_out[handshake_len:])
        response = bytearray()
        deadline = time.monotonic() + TIMEOUT
        while time.monotonic() < deadline:
            try:
                chunk = tls.read(65536)
                if not chunk:  # close_notify received: SSLObject.read() returns b"" instead of raising
                    break
                response.extend(chunk)
            except ssl.SSLWantReadError:
                flush()
                try:
                    if not pump():
                        break
                except socket.timeout:
                    break
            except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
                break
        cert_der = tls.getpeercert(binary_form=True)
        return {
            "version": tls.version(),
            "cipher": tls.cipher()[0] if tls.cipher() else None,
            "handshake_bytes": handshake_len,
            "app_bytes": app_bytes,
            "wire": bytes(wire_out),
            "response_head": bytes(response).split(b"\r\n", 1)[0].decode("latin-1"),
            "cert_der": cert_der,
        }
    finally:
        sock.close()


def capture_plain_http(target: Target, request: bytes) -> dict:
    sock = socket.create_connection((target.host, target.http_port), timeout=TIMEOUT)
    try:
        sock.sendall(request)
        resp = bytearray()
        while len(resp) < 4096:
            try:
                chunk = sock.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            resp.extend(chunk)
        return {"sent": request, "response_head": bytes(resp).split(b"\r\n", 1)[0].decode("latin-1")}
    finally:
        sock.close()


def run_sniff(target: Target) -> dict:
    steps = []
    request = _login_request(f"{target.host}:{target.https_port}")
    steps.append(
        step(
            "A voter signs in on campus Wi-Fi",
            lines=[f"POST /api/login with password “{VICTIM_PASSWORD}” (a made-up victim account)."],
        )
    )
    try:
        cap = capture_tls_exchange(target, request)
    except (OSError, ssl.SSLError, ConnectionError) as exc:
        return {
            "outcome": "error",
            "summary": f"Could not reach https://{target.host}:{target.https_port} ({exc}). Start the app with python run.py.",
            "steps": steps,
        }
    steps.append(
        step(
            "The connection is protected with TLS",
            lines=[f"Negotiated {cap['version']} with {cap['cipher']}.", f"Handshake: {cap['handshake_bytes']} bytes sent by the client, then the keys are agreed (ECDHE)."],
        )
    )
    recs = tls_records(cap["app_bytes"])
    steps.append(
        step(
            "The attacker records every byte of the request",
            lines=recs[:4] or ["(no records captured)"],
            code=hexdump(cap["app_bytes"]),
        )
    )
    leaked = VICTIM_PASSWORD.encode() in cap["wire"] or b"/api/login" in cap["wire"]
    steps.append(
        step(
            "The attacker searches the capture for the password",
            "exposed" if leaked else "blocked",
            [
                "Found the password in the captured bytes."
                if leaked
                else "Neither the password nor even the URL appears anywhere in the captured bytes.",
                f"The real client still got the server's answer: {cap['response_head']}",
            ],
        )
    )
    if target.http_port:
        try:
            plain = capture_plain_http(target, _login_request(f"{target.host}:{target.http_port}"))
            sent = plain["sent"].decode("latin-1")
            steps.append(
                step(
                    f"For comparison: the same request to plain HTTP (port {target.http_port})",
                    "warn",
                    [
                        "On plain HTTP the password is readable by anyone on the network.",
                        f"The server answered {plain['response_head'] or '(no reply)'}: it did not process the "
                        "login, sent the client to HTTPS and alerted the administrator. HSTS keeps browsers "
                        "from using plain HTTP after their first visit.",
                    ],
                    code=sent[-240:],
                )
            )
        except OSError as exc:
            steps.append(step(f"Plain-HTTP port {target.http_port} is not listening", "info", [str(exc)]))
    return {
        "outcome": "exposed" if leaked else "blocked",
        "summary": (
            "Password visible in the capture."
            if leaked
            else f"Captured {len(cap['app_bytes'])} bytes of {cap['version']} ciphertext: password not recoverable."
        ),
        "steps": steps,
    }


def _impostor_certificate(host: str) -> tuple[bytes, bytes]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SecureVote (impostor)")])
    now = datetime.now(timezone.utc)
    import ipaddress

    san: list[x509.GeneralName] = [x509.DNSName("localhost")]
    try:
        san.append(x509.IPAddress(ipaddress.ip_address(host)))
    except ValueError:
        san.append(x509.DNSName(host))
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .sign(key, hashes.SHA256())
    )
    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    return cert.public_bytes(serialization.Encoding.PEM), key_pem


def _cert_summary(der: bytes) -> str:
    cert = x509.load_der_x509_certificate(der)
    issuer = cert.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
    fp = hashlib.sha256(der).hexdigest()
    return f"issued by “{issuer[0].value if issuer else cert.issuer.rfc4514_string()}”, SHA-256 {fp[:16]}…"


def run_tls_probe(target: Target) -> dict:
    steps = []
    # Control: a modern client.
    try:
        ctx = _client_context(target)
        with socket.create_connection((target.host, target.https_port), timeout=TIMEOUT) as raw:
            with ctx.wrap_socket(raw, server_hostname=target.host) as tls:
                real_version, real_cipher = tls.version(), tls.cipher()[0]
                real_cert = tls.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError) as exc:
        return {
            "outcome": "error",
            "summary": f"Could not reach https://{target.host}:{target.https_port} ({exc}). Start the app with python run.py.",
            "steps": steps,
        }
    steps.append(
        step(
            "A normal client connects",
            lines=[f"{real_version} with {real_cipher}.", f"Server certificate {_cert_summary(real_cert)}."],
        )
    )

    # 1. Downgrade: offer only TLS 1.0 / 1.1.
    old = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    old.check_hostname = False
    old.verify_mode = ssl.CERT_NONE
    can_offer = True
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        try:
            old.minimum_version = ssl.TLSVersion.TLSv1
            old.maximum_version = ssl.TLSVersion.TLSv1_1
            old.set_ciphers("DEFAULT:@SECLEVEL=0")
        except (ValueError, ssl.SSLError):
            can_offer = False
    downgrade_blocked = True
    if can_offer:
        try:
            with socket.create_connection((target.host, target.https_port), timeout=TIMEOUT) as raw:
                with old.wrap_socket(raw) as tls:
                    downgrade_blocked = False
                    got = tls.version()
            steps.append(step("Attacker's client offers only TLS 1.0 / 1.1", "exposed", [f"Server accepted {got}."]))
        except (ssl.SSLError, OSError) as exc:
            reason = getattr(exc, "reason", None) or type(exc).__name__
            local = "NO_PROTOCOLS_AVAILABLE" in str(reason).upper() or "no protocols available" in str(exc)
            steps.append(
                step(
                    "Attacker's client offers only TLS 1.0 / 1.1",
                    "blocked",
                    [
                        "This machine's OpenSSL refuses to even offer TLS 1.1."
                        if local
                        else f"Handshake refused by the server ({reason}).",
                        "The server's minimum is TLS 1.2 (src/tls_setup.py), so a downgrade to a broken "
                        "protocol version is impossible.",
                    ],
                )
            )
    else:
        steps.append(
            step(
                "Attacker's client offers only TLS 1.0 / 1.1",
                "blocked",
                ["This machine's OpenSSL cannot offer TLS 1.1 at all; the server's minimum is TLS 1.2."],
            )
        )

    # 2. Impostor server with its own self-signed certificate (e.g. an evil-twin Wi-Fi hotspot).
    cert_pem, key_pem = _impostor_certificate(target.host)
    impostor_blocked = True
    with tempfile.TemporaryDirectory() as td:
        cp, kp = Path(td) / "c.pem", Path(td) / "k.pem"
        cp.write_bytes(cert_pem)
        kp.write_bytes(key_pem)
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(cp, kp)
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        srv.settimeout(TIMEOUT)
        port = srv.getsockname()[1]

        def serve() -> None:
            try:
                conn, _ = srv.accept()
                with sctx.wrap_socket(conn, server_side=True) as s:
                    s.sendall(b"HTTP/1.1 200 OK\r\n\r\nfake login page")
            except (OSError, ssl.SSLError):
                pass

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        der = x509.load_pem_x509_certificate(cert_pem).public_bytes(serialization.Encoding.DER)
        steps.append(
            step(
                "Attacker runs a fake SecureVote server",
                lines=[f"Self-signed certificate for {target.host}, {_cert_summary(der)}."],
            )
        )
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=TIMEOUT) as raw:
                with _client_context(target).wrap_socket(raw, server_hostname=target.host):
                    impostor_blocked = False
            steps.append(step("A voter's client connects to it", "exposed", ["The client accepted the impostor."]))
        except ssl.SSLCertVerificationError as exc:
            steps.append(
                step(
                    "A voter's client connects to it",
                    "blocked",
                    [
                        f"Certificate check failed: {exc.verify_message}.",
                        "Only certificates signed by the SecureVote CA are trusted, so the fake server never "
                        "receives a password.",
                    ],
                )
            )
        except (OSError, ssl.SSLError) as exc:
            steps.append(step("A voter's client connects to it", "blocked", [f"Connection refused: {exc}"]))
        finally:
            srv.close()
            t.join(timeout=1)

    blocked = downgrade_blocked and impostor_blocked
    return {
        "outcome": "blocked" if blocked else "exposed",
        "summary": "Old TLS refused and the impostor certificate rejected."
        if blocked
        else "A downgrade or impostor connection succeeded.",
        "steps": steps,
        "downgrade_blocked": downgrade_blocked,
        "impostor_blocked": impostor_blocked,
    }


# Secrets an attacker would try first: empty, obvious words, and every value printed in this repo.
GUESSED_SECRETS = [
    ("empty", ""),
    ("“admin”", "admin"),
    ("“password”", "password"),
    ("“securevote”", "securevote"),
    ("old default JWT_SECRET from config.py", DEFAULT_JWT_SECRET),
    ("JWT_SECRET example from .env.example", "replace-with-long-random-string"),
    ("KEY_ENCRYPTION_SECRET example from .env.example", "replace-with-another-long-random-string"),
    ("default ADMIN_PASSWORD", "admin-change-me"),
]
COMMON_PASSWORDS = ["password", "12345678", "password123", "qwerty123", "admin123", "iloveyou"]


def _short(s: str | None, n: int = 28) -> str:
    if not s:
        return "(none)"
    return s if len(s) <= n else s[:n] + "…"


def run_db_theft(db_path: Path) -> dict:
    steps = []
    with tempfile.TemporaryDirectory() as td:
        stolen = Path(td) / "stolen.db"
        src = sqlite3.connect(str(db_path))
        dst = sqlite3.connect(str(stolen))
        src.backup(dst)
        src.close()
        dst.row_factory = sqlite3.Row
        try:
            q = lambda sql, *a: dst.execute(sql, a).fetchall()  # noqa: E731
            n_voters = q("SELECT COUNT(*) c FROM voters")[0]["c"]
            n_votes = q("SELECT COUNT(*) c FROM election_votes")[0]["c"]
            n_el = q("SELECT COUNT(*) c FROM elections")[0]["c"]
            n_roster = q("SELECT COUNT(*) c FROM voter_roster")[0]["c"]
            steps.append(
                step(
                    "The attacker copies voting.db",
                    lines=[
                        f"{n_voters} voter accounts, {n_votes} ballots, {n_el} elections, {n_roster} roster entries.",
                        "The secrets in data/secrets/ and any .env are not part of the copy.",
                    ],
                )
            )
            ballot = q("SELECT encrypted_vote FROM election_votes LIMIT 1")
            el = q("SELECT id, title, private_key_pem FROM elections ORDER BY id LIMIT 1")
            pw = q("SELECT password_hash FROM voters LIMIT 2")
            ro = q("SELECT aadhaar_hmac, aadhaar_last4 FROM voter_roster WHERE aadhaar_hmac IS NOT NULL LIMIT 1")
            steps.append(
                step(
                    "What the attacker sees",
                    lines=["Values are cut short here; the attacker has them in full."],
                    code="\n".join(
                        [
                            f"ballot        {_short(ballot[0]['encrypted_vote'] if ballot else None)}  (RSA-OAEP ciphertext)",
                            f"election key  {_short(el[0]['private_key_pem'] if el else None, 40)}  (AES-256-GCM)",
                            f"password      {_short(pw[0]['password_hash'] if pw else None, 20)}  (bcrypt, cost 12)",
                            f"Aadhaar       {_short(ro[0]['aadhaar_hmac'] if ro else None, 20)}  (HMAC-SHA256) + last 4 digits",
                        ]
                    ),
                )
            )

            # 1. Election private key: guess the wrapping secret.
            opened = None
            if el:
                stored = el[0]["private_key_pem"]
                tried = []
                for label, guess in GUESSED_SECRETS:
                    try:
                        opened = unwrap_private_key(stored, guess)
                        tried.append(f"{label}: OPENED")
                        break
                    except (InvalidTag, ValueError):
                        tried.append(f"{label}: wrong (GCM tag check failed)")
                steps.append(
                    step(
                        "Open the election private key by guessing its secret",
                        "exposed" if opened else "blocked",
                        tried
                        + (
                            []
                            if opened
                            else [
                                "Each guess costs 200,000 PBKDF2 rounds, and the real secret is 64 random characters stored outside the database."
                            ]
                        ),
                    )
                )
            else:
                steps.append(step("Open the election private key", "info", ["No elections in the database yet."]))

            # 2. Ballots.
            if ballot and opened:
                try:
                    plain = decrypt_vote_ciphertext(ballot[0]["encrypted_vote"], opened)
                    steps.append(step("Decrypt a ballot", "exposed", [f"Readable: {plain.decode(errors='replace')}"]))
                except Exception:
                    steps.append(step("Decrypt a ballot", "blocked", ["This ballot belongs to another election's key."]))
            elif ballot:
                steps.append(
                    step(
                        "Decrypt a ballot",
                        "blocked",
                        ["Without the election private key, RSA-2048 OAEP ciphertext cannot be read."],
                    )
                )

            # 3. Passwords: a small dictionary attack against bcrypt.
            if pw:
                t0 = time.perf_counter()
                bcrypt.checkpw(b"timing-probe", pw[0]["password_hash"].encode())
                per_guess = time.perf_counter() - t0
                cracked = 0
                for r in pw:
                    h = r["password_hash"].encode()
                    if any(bcrypt.checkpw(w.encode(), h) for w in COMMON_PASSWORDS):
                        cracked += 1
                steps.append(
                    step(
                        "Crack passwords with a dictionary",
                        "exposed" if cracked else "blocked",
                        [
                            f"Tried {len(COMMON_PASSWORDS)} common passwords against {len(pw)} hash(es): {cracked} cracked.",
                            f"One bcrypt guess takes {per_guess * 1000:.0f} ms, so a 10-million-word list costs about "
                            f"{per_guess * 10_000_000 / 86400:.0f} days per account.",
                        ],
                    )
                )

            # 4. ID numbers.
            if ro:
                steps.append(
                    step(
                        "Recover Aadhaar numbers",
                        "blocked",
                        [
                            "The roster keeps only an HMAC-SHA256 of each number. Even knowing the last 4 digits, "
                            "testing the remaining 10⁸ candidates needs the HMAC key, which is not in the database.",
                        ],
                    )
                )
        finally:
            dst.close()

    exposed = any(s["status"] == "exposed" for s in steps)
    return {
        "outcome": "exposed" if exposed else "blocked",
        "summary": "Something in the stolen copy was readable."
        if exposed
        else "Ballots, election keys, passwords and ID numbers stayed protected in the stolen copy.",
        "steps": steps,
    }
