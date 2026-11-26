"""Identity verification against the roster, admin security alerts, generated secrets and lab probes."""

from __future__ import annotations

import json
import os
import socket
import sqlite3
import ssl
import threading
from datetime import datetime, timedelta, timezone

import pytest

from src.identity import (
    IdentityFormatError,
    normalize_id_number,
    normalize_name,
    verhoeff_check_digit,
    verhoeff_valid,
)
from tests.helpers import aadhaar_for, build_ballot_contestant, create_test_election, identity_for

EMAIL = "idcheck@umsystem.edu"


def admin_headers(client) -> dict:
    tok = client.post("/api/admin/login", json={"username": "admin", "password": "test-admin-password"}).json()
    return {"Authorization": f"Bearer {tok['access_token']}"}


def alerts(client) -> list[dict]:
    return client.get("/api/admin/alerts", headers=admin_headers(client)).json()["alerts"]


def register(client, email=EMAIL, **identity):
    body = {"voter_id": email, "password": "password12", **identity_for(email)}
    body.update(identity)
    return client.post("/api/register", json=body)


def login(client, email=EMAIL) -> dict:
    step1 = client.post("/api/login", json={"voter_id": email, "password": "password12"}).json()
    step2 = client.post("/api/login", json={"voter_id": email, "password": "password12", "otp": step1["dev_otp"]})
    return {"Authorization": f"Bearer {step2.json()['access_token']}"}


# ---------- Pure functions ----------


def test_verhoeff_detects_single_digit_typos():
    body = "23456789012"
    good = body + verhoeff_check_digit(body)
    assert verhoeff_valid(good)
    for i in range(12):
        typo = good[:i] + str((int(good[i]) + 1) % 10) + good[i + 1 :]
        assert not verhoeff_valid(typo)
    swapped = good[:3] + good[4] + good[3] + good[5:]
    assert swapped == good or not verhoeff_valid(swapped)


def test_id_and_name_normalisation():
    a = aadhaar_for(EMAIL)
    assert normalize_id_number("aadhaar", f"{a[:4]} {a[4:8]}-{a[8:]}") == a
    with pytest.raises(IdentityFormatError):
        normalize_id_number("aadhaar", a[:-1] + str((int(a[-1]) + 1) % 10))
    with pytest.raises(IdentityFormatError):
        normalize_id_number("aadhaar", "1" + a[1:])  # Aadhaar never starts with 0 or 1
    assert normalize_id_number("college_id", " 01fe23bcs145 ") == "01FE23BCS145"
    assert normalize_name("  K. S.   Rao ") == normalize_name("k s rao")


# ---------- Registration identity check ----------


def test_register_with_matching_aadhaar_or_college_id(client):
    r = register(client)
    assert r.status_code == 201, r.text
    s = client.get("/api/voter/session", headers=login(client)).json()
    assert s["identity_verified"] is True and s["identity_method"] == "aadhaar"
    assert s["full_name"] == "Test Idcheck"

    r2 = register(client, "v1@umsystem.edu", **identity_for("v1@umsystem.edu", "college_id"))
    assert r2.status_code == 201, r2.text


def test_register_name_match_ignores_case_and_spacing(client):
    assert register(client, full_name="  test   IDCHECK ").status_code == 201


def test_wrong_id_number_rejected_and_admin_alerted(client):
    other = aadhaar_for("v1@umsystem.edu")  # someone else's real (roster) Aadhaar number
    r = register(client, id_number=other)
    assert r.status_code == 403
    assert "2 attempts left" in r.json()["detail"]
    assert "ID number" not in r.json()["detail"]  # the voter is not told which field was wrong
    a = alerts(client)
    assert a[0]["kind"] == "identity_mismatch"
    assert a[0]["actor"] == EMAIL
    assert "ID number" in a[0]["detail"]  # the administrator is


def test_typo_in_aadhaar_is_a_format_error_not_a_failed_attempt(client):
    a = aadhaar_for(EMAIL)
    r = register(client, id_number=a[:-1] + str((int(a[-1]) + 1) % 10))
    assert r.status_code == 400
    assert not alerts(client)


def test_three_failures_lock_identity_checks(client):
    for i in range(2):
        assert register(client, date_of_birth="2001-01-0" + str(i + 1)).status_code == 403
    r = register(client, date_of_birth="2001-01-09")
    assert r.status_code == 429
    assert register(client).status_code == 429  # even the right details, while locked
    kinds = [x["kind"] for x in alerts(client)]
    assert "identity_lockout" in kinds
    assert next(x for x in alerts(client) if x["kind"] == "identity_lockout")["severity"] == "high"


def test_roster_never_stores_id_numbers(client, tmp_path):
    register(client)
    conn = sqlite3.connect(tmp_path / "test_voting.db")
    dump = "\n".join(conn.iterdump())
    conn.close()
    assert aadhaar_for(EMAIL) not in dump
    assert aadhaar_for(EMAIL)[-4:] in dump  # only the last four, for display


def test_unverified_account_must_verify_before_requesting_access(client, tmp_path):
    assert register(client).status_code == 201
    conn = sqlite3.connect(tmp_path / "test_voting.db")
    conn.execute("UPDATE voters SET identity_method = NULL, identity_verified_at = NULL")
    conn.commit()
    conn.close()
    h = login(client)
    eid = create_test_election(client, admin_headers(client)["Authorization"].split()[1])
    r = client.post(f"/api/elections/{eid}/register", headers=h)
    assert r.status_code == 403 and "identity" in r.json()["detail"].lower()
    v = client.post("/api/voter/verify-identity", headers=h, json=identity_for(EMAIL, "college_id"))
    assert v.status_code == 200, v.text
    assert client.post(f"/api/elections/{eid}/register", headers=h).status_code == 200


def test_admin_roster_add_list_remove(client):
    ah = admin_headers(client)
    body = {"email": "new@umsystem.edu", "full_name": "New Student", "date_of_birth": "2005-02-02",
            "aadhaar": "2345 6789 012" + verhoeff_check_digit("23456789012")}
    assert client.post("/api/admin/roster", headers=ah, json=body).status_code == 201
    assert client.post("/api/admin/roster", headers=ah, json=body).status_code == 409
    dup_id = {**body, "email": "other@umsystem.edu"}
    r = client.post("/api/admin/roster", headers=ah, json=dup_id)
    assert r.status_code == 409 and "ID number" in r.json()["detail"]
    entries = client.get("/api/admin/roster", headers=ah).json()["entries"]
    new = next(e for e in entries if e["email"] == "new@umsystem.edu")
    assert new["aadhaar"].endswith(body["aadhaar"][-4:]) and "2345" not in new["aadhaar"]
    assert client.post("/api/register/precheck", json={"voter_id": "new@umsystem.edu"}).status_code == 200
    assert client.delete("/api/admin/roster/new@umsystem.edu", headers=ah).status_code == 200
    assert client.post("/api/register/precheck", json={"voter_id": "new@umsystem.edu"}).status_code == 403
    register(client)
    assert client.delete(f"/api/admin/roster/{EMAIL}", headers=ah).status_code == 409
    assert client.get("/api/admin/roster").status_code == 401


# ---------- Alerts from the real defences ----------


def _approved(client, email=EMAIL):
    assert register(client, email).status_code == 201
    h = login(client, email)
    ah = admin_headers(client)
    eid = create_test_election(client, ah["Authorization"].split()[1])
    client.post(f"/api/elections/{eid}/register", headers=h)
    rid = client.get("/api/admin/registrations", headers=ah).json()["registrations"][0]
    assert rid["identity_label"] == "Aadhaar card" and rid["full_name"] == "Test Idcheck"
    assert rid["identity_masked"].endswith(aadhaar_for(email)[-4:])
    client.post(f"/api/admin/registrations/{rid['id']}/approve", headers=ah)
    return h, ah, eid, client.get(f"/api/elections/{eid}/detail", headers=h).json()


def test_forged_signature_alerts_admin_and_repeats_coalesce(client):
    from src.crypto_service import generate_rsa_keypair

    h, ah, eid, d = _approved(client)
    attacker_priv, _pub = generate_rsa_keypair()
    for _ in range(2):
        enc, sig, ts = build_ballot_contestant(d["contestants"][0]["id"], d["public_key_pem"], attacker_priv.decode())
        body = {"voter_id": EMAIL, "encrypted_vote": enc, "signature": sig, "timestamp": ts}
        assert client.post(f"/api/elections/{eid}/vote", headers=h, json=body).status_code == 409
    a = [x for x in alerts(client) if x["kind"] == "forged_signature"]
    assert len(a) == 1 and a[0]["count"] == 2 and a[0]["detected_by"] == "Ballot intake"
    summary = client.get("/api/admin/alerts/summary", headers=ah).json()
    assert summary["unacknowledged"] >= 1 and summary["latest"]["kind"] == "forged_signature"
    assert client.post(f"/api/admin/alerts/{a[0]['id']}/ack", headers=ah).status_code == 200
    assert client.post("/api/admin/alerts/ack-all", headers=ah).status_code == 200
    assert client.get("/api/admin/alerts/summary", headers=ah).json()["unacknowledged"] == 0
    assert client.get("/api/admin/alerts").status_code == 401


def test_replay_and_double_vote_alert(client):
    from src.crypto_service import encrypt_vote_plaintext, generate_rsa_keypair, sign_submission

    priv, pub = generate_rsa_keypair()
    assert client.post(
        "/api/register",
        json={"voter_id": EMAIL, "password": "password12", "public_key_pem": pub.decode(), **identity_for(EMAIL)},
    ).status_code == 201
    h = login(client)
    ah = admin_headers(client)
    eid = create_test_election(client, ah["Authorization"].split()[1])
    client.post(f"/api/elections/{eid}/register", headers=h)
    rid = client.get("/api/admin/registrations", headers=ah).json()["registrations"][0]["id"]
    client.post(f"/api/admin/registrations/{rid}/approve", headers=ah)
    d = client.get(f"/api/elections/{eid}/detail", headers=h).json()
    cid = d["contestants"][0]["id"]

    old = (datetime.now(timezone.utc) - timedelta(minutes=20)).isoformat().replace("+00:00", "Z")
    enc = encrypt_vote_plaintext(json.dumps({"contestant_id": cid}).encode(), d["public_key_pem"].encode())
    body = {"voter_id": EMAIL, "encrypted_vote": enc, "signature": sign_submission(enc, old, priv), "timestamp": old}
    assert client.post(f"/api/elections/{eid}/vote", headers=h, json=body).status_code == 422

    enc, sig, ts = build_ballot_contestant(cid, d["public_key_pem"], priv.decode())
    ok = {"voter_id": EMAIL, "encrypted_vote": enc, "signature": sig, "timestamp": ts}
    assert client.post(f"/api/elections/{eid}/vote", headers=h, json=ok).status_code == 200
    enc, sig, ts = build_ballot_contestant(cid, d["public_key_pem"], priv.decode())
    again = {"voter_id": EMAIL, "encrypted_vote": enc, "signature": sig, "timestamp": ts}
    assert client.post(f"/api/elections/{eid}/vote", headers=h, json=again).status_code == 403
    kinds = {x["kind"] for x in alerts(client)}
    assert {"replay", "double_vote"} <= kinds
    assert "forged_signature" not in kinds  # an honest ballot never raises an alert


def test_ballot_in_another_voters_name_alerts(client):
    h, _ah, eid, _d = _approved(client)
    r = client.post(
        f"/api/elections/{eid}/vote",
        headers=h,
        json={"voter_id": "v1@umsystem.edu", "encrypted_vote": "AA==", "signature": "AA==", "timestamp": "2026-01-01T00:00:00Z"},
    )
    assert r.status_code == 401
    assert alerts(client)[0]["kind"] == "ballot_for_other_voter"


def test_otp_guessing_alerts_admin(client):
    register(client)
    real = client.post("/api/login", json={"voter_id": EMAIL, "password": "password12"}).json()["dev_otp"]
    wrong = "000000" if real != "000000" else "111111"
    for _ in range(5):
        client.post("/api/login", json={"voter_id": EMAIL, "password": "password12", "otp": wrong})
    a = alerts(client)[0]
    assert a["kind"] == "otp_bruteforce" and a["severity"] == "high" and a["detected_by"] == "Sign-in"


def test_plain_http_listener_flags_only_requests_that_leak_secrets():
    import asyncio

    from run import make_redirect_app

    seen = []

    async def call(method, path, headers):
        sent = []

        async def send(m):
            sent.append(m)

        scope = {"type": "http", "method": method, "path": path, "raw_path": path.encode(),
                 "headers": [(b"host", b"127.0.0.1:8000"), *headers], "query_string": b""}
        await make_redirect_app(8443, seen.append)(scope, None, send)
        return sent[0]["status"]

    assert asyncio.run(call("GET", "/", [])) == 308
    assert asyncio.run(call("GET", "/api/elections", [])) == 308
    assert not seen
    assert asyncio.run(call("POST", "/api/login", [(b"content-length", b"40")])) == 308
    assert asyncio.run(call("GET", "/api/elections", [(b"authorization", b"Bearer x")])) == 308
    assert len(seen) == 2


# ---------- Generated secrets ----------


def test_secrets_are_generated_outside_the_database(tmp_path):
    from src.secrets_store import load_or_create

    d = tmp_path / "secrets"
    a = load_or_create(d, "key_encryption_secret")
    load_or_create.cache_clear()
    assert load_or_create(d, "key_encryption_secret") == a
    assert len(a) >= 60
    assert (os.stat(d / "key_encryption_secret").st_mode & 0o077) == 0


def test_keys_wrapped_with_old_default_secret_are_rewrapped(client, tmp_path):
    """Databases from before generated secrets used the public default; bootstrap moves them."""
    from src.bootstrap import ensure_bootstrap
    from src.config import settings
    from src.crypto_service import generate_rsa_keypair, unwrap_private_key, wrap_private_key
    from src.secrets_store import DEFAULT_JWT_SECRET

    db = tmp_path / "test_voting.db"
    priv, _ = generate_rsa_keypair()
    conn = sqlite3.connect(db)
    conn.execute(
        """INSERT INTO elections (title, category, public_key_pem, private_key_pem, starts_at, ends_at, created_at)
           VALUES ('old', 'class', 'x', ?, '2026-01-01T00:00:00Z', '2026-12-31T00:00:00Z', '2026-01-01T00:00:00Z')""",
        (wrap_private_key(priv, DEFAULT_JWT_SECRET),),
    )
    conn.execute("DELETE FROM meta WHERE key = 'key_wrap_secret_v2'")
    conn.commit()
    conn.close()
    ensure_bootstrap(db, "test-admin-password", None, None)
    conn = sqlite3.connect(db)
    stored = conn.execute("SELECT private_key_pem FROM elections WHERE title = 'old'").fetchone()[0]
    conn.close()
    assert unwrap_private_key(stored, settings.key_wrap_secret()) == priv


# ---------- Lab probes ----------


@pytest.fixture
def tls_server(tmp_path):
    from src.tls_setup import generate_certificates, harden_server_context

    files = generate_certificates(tmp_path / "tls")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(files.server_cert, files.server_key)
    harden_server_context(ctx)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    sock.listen(8)

    def serve():
        while True:
            try:
                conn, _ = sock.accept()
            except OSError:
                return
            try:
                with ctx.wrap_socket(conn, server_side=True) as t:
                    t.settimeout(2)
                    t.recv(4096)
                    t.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    t.unwrap()  # send close_notify, as uvicorn does
            except (ssl.SSLError, OSError):
                pass

    threading.Thread(target=serve, daemon=True).start()
    yield sock.getsockname()[1], str(files.ca_cert)
    sock.close()


def test_sniff_probe_sees_only_ciphertext(tls_server):
    from src.attack_lab import VICTIM_PASSWORD, Target, capture_tls_exchange, run_sniff

    port, ca = tls_server
    t = Target("127.0.0.1", port, 0, ca)
    res = run_sniff(t)
    assert res["outcome"] == "blocked", res
    cap = capture_tls_exchange(t, b"GET / HTTP/1.1\r\nHost: x\r\nX-Secret: " + VICTIM_PASSWORD.encode() + b"\r\n\r\n")
    assert cap["version"] in ("TLSv1.2", "TLSv1.3")
    assert VICTIM_PASSWORD.encode() not in cap["wire"]
    assert cap["app_bytes"][0] == 23  # TLS application-data record
    assert cap["response_head"].startswith("HTTP/1.1 403")


def test_tls_probe_refuses_downgrade_and_impostor(tls_server):
    from src.attack_lab import Target, run_tls_probe

    port, ca = tls_server
    res = run_tls_probe(Target("127.0.0.1", port, 0, ca))
    assert res["outcome"] == "blocked", res
    assert res["downgrade_blocked"] and res["impostor_blocked"]


def test_db_theft_probe_is_honest(client, tmp_path):
    from src.attack_lab import run_db_theft
    from src.crypto_service import generate_rsa_keypair, wrap_private_key
    from src.secrets_store import DEFAULT_JWT_SECRET

    ah = admin_headers(client)
    create_test_election(client, ah["Authorization"].split()[1])
    db = tmp_path / "test_voting.db"
    assert run_db_theft(db)["outcome"] == "blocked"

    # A key wrapped with a secret printed in the repo must be reported as broken, not hidden.
    priv, _ = generate_rsa_keypair()
    conn = sqlite3.connect(db)
    conn.execute("UPDATE elections SET private_key_pem = ?", (wrap_private_key(priv, DEFAULT_JWT_SECRET),))
    conn.commit()
    conn.close()
    assert run_db_theft(db)["outcome"] == "exposed"


def test_lab_endpoints_need_sign_in_and_raise_alerts(client):
    assert client.post("/api/lab/db-theft").status_code == 401
    ah = admin_headers(client)
    r = client.post("/api/lab/db-theft", headers=ah)
    assert r.status_code == 200 and r.json()["outcome"] == "blocked"
    a = alerts(client)[0]
    assert a["kind"] == "db_theft" and a["detected_by"] == "Security lab probe"
    assert a["actor"] == "lab run by admin admin"


def test_unknown_user_sign_in_and_register_alert_admin(client):
    r = client.post("/api/login", json={"voter_id": "outsider@umsystem.edu", "password": "whatever1"})
    assert r.status_code == 403
    r = client.post(
        "/api/register",
        json={"voter_id": "outsider@umsystem.edu", "password": "password12", **identity_for(EMAIL)},
    )
    assert r.status_code == 403
    a = [x for x in alerts(client) if x["kind"] == "unknown_user"]
    # Same person within a minute: one alert with a counter.
    assert len(a) == 1 and a[0]["count"] == 2 and a[0]["actor"] == "outsider@umsystem.edu"
    # The precheck (typing an email on the sign-up page) does not raise an alert.
    client.post("/api/register/precheck", json={"voter_id": "someone@umsystem.edu"})
    assert [x["count"] for x in alerts(client) if x["kind"] == "unknown_user"] == [2]


def test_repeated_wrong_passwords_alert_admin(client):
    register(client)
    for i in range(2):
        assert client.post("/api/login", json={"voter_id": EMAIL, "password": f"wrong-{i}"}).status_code == 401
    assert not [x for x in alerts(client) if x["kind"] == "password_guessing"]
    client.post("/api/login", json={"voter_id": EMAIL, "password": "wrong-3"})
    a = [x for x in alerts(client) if x["kind"] == "password_guessing"]
    assert len(a) == 1 and a[0]["severity"] == "high" and "3 wrong passwords" in a[0]["detail"]


def test_admin_stored_data_shows_only_ciphertext(client):
    register(client)
    assert client.get("/api/admin/stored-data").status_code == 401
    d = client.get("/api/admin/stored-data", headers=admin_headers(client)).json()
    assert d["path"].endswith("test_voting.db")
    t = {x["table"]: x for x in d["tables"]}
    assert set(t) == {"election_votes", "elections", "voters", "voter_roster", "voter_login_otps"}
    pw = t["voters"]["rows"][0][t["voters"]["columns"].index("password_hash")]
    assert pw.startswith("$2b$12$")
    dump = str(d)
    assert aadhaar_for(EMAIL) not in dump and "password12" not in dump
