"""Admin security alerts, voter roster management, and the security lab's server-side probes."""

from __future__ import annotations

import sqlite3
import threading
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from src import alerts as alert_store
from src.alerts import record_alert
from src.api_routes import admin_bearer, bearer_token, client_ip
from src.attack_lab import default_target, run_db_theft, run_sniff, run_tls_probe
from src.auth_tokens import safe_decode
from src.config import settings
from src.database import audit_log, get_connection
from src.identity import IdentityFormatError, add_roster_entry, masked, normalize_email

router = APIRouter()
_db_path = settings.db_file()
# Lab probes open sockets and run PBKDF2/bcrypt; one at a time is plenty.
_lab_lock = threading.Lock()


def require_signed_in(token: str = Depends(bearer_token)) -> str:
    """Any signed-in voter or administrator; returns a label for the alert's actor field."""
    payload = safe_decode(token)
    if not payload or payload.get("role") not in ("voter", "admin") or not payload.get("sub"):
        raise HTTPException(status_code=401, detail="Sign in to use the security lab")
    return f"{payload['role']} {payload['sub']}"


# ---------- Alerts ----------


@router.get("/admin/alerts")
def list_alerts(limit: int = 100, _: None = Depends(admin_bearer)):
    with get_connection(_db_path) as conn:
        return {"alerts": alert_store.list_alerts(conn, max(1, min(limit, 500))), **alert_store.summary(conn)}


@router.get("/admin/alerts/summary")
def alerts_summary(_: None = Depends(admin_bearer)):
    with get_connection(_db_path) as conn:
        return alert_store.summary(conn)


@router.post("/admin/alerts/{alert_id}/ack")
def ack_alert(alert_id: int, _: None = Depends(admin_bearer)):
    with get_connection(_db_path) as conn:
        cur = conn.execute("UPDATE security_alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Alert not found")
        conn.commit()
    return {"ok": True}


@router.post("/admin/alerts/ack-all")
def ack_all_alerts(_: None = Depends(admin_bearer)):
    with get_connection(_db_path) as conn:
        n = conn.execute("UPDATE security_alerts SET acknowledged = 1 WHERE acknowledged = 0").rowcount
        conn.commit()
    return {"ok": True, "acknowledged": n}


# ---------- Voter roster ----------


class RosterEntryBody(BaseModel):
    email: str = Field(min_length=3, max_length=128)
    full_name: str = Field(min_length=2, max_length=120)
    date_of_birth: str = Field(min_length=8, max_length=10)
    aadhaar: str | None = Field(default=None, max_length=32)
    college_id: str | None = Field(default=None, max_length=32)


@router.get("/admin/roster")
def list_roster(_: None = Depends(admin_bearer)):
    """ID numbers are never returned: only the last four digits that are stored for display."""
    with get_connection(_db_path) as conn:
        rows = conn.execute(
            """SELECT ro.email, ro.full_name, ro.aadhaar_last4, ro.college_id_last4, ro.source,
                      v.voter_id IS NOT NULL AS registered, v.identity_method, v.identity_verified_at
               FROM voter_roster ro LEFT JOIN voters v ON v.voter_id = ro.email
               ORDER BY ro.full_name COLLATE NOCASE"""
        ).fetchall()
    return {
        "entries": [
            {
                "email": r["email"],
                "full_name": r["full_name"],
                "aadhaar": masked(r["aadhaar_last4"]),
                "college_id": masked(r["college_id_last4"]),
                "source": r["source"],
                "registered": bool(r["registered"]),
                "identity_method": r["identity_method"],
                "identity_verified": bool(r["identity_verified_at"]),
            }
            for r in rows
        ]
    }


@router.post("/admin/roster", status_code=201)
def add_roster(body: RosterEntryBody, _: None = Depends(admin_bearer)):
    with get_connection(_db_path) as conn:
        try:
            email = add_roster_entry(
                conn,
                settings.identity_secret(),
                email=body.email,
                full_name=body.full_name,
                date_of_birth=body.date_of_birth,
                aadhaar=body.aadhaar,
                college_id=body.college_id,
                source="admin",
            )
            conn.commit()
        except IdentityFormatError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except sqlite3.IntegrityError as exc:
            msg = str(exc)
            if "voter_roster.email" in msg:
                raise HTTPException(status_code=409, detail="This email is already on the roster") from exc
            raise HTTPException(
                status_code=409, detail="That ID number already belongs to another student on the roster"
            ) from exc
        audit_log(conn, "roster_entry_added", email)
    return {"ok": True, "email": email}


@router.delete("/admin/roster/{email}")
def remove_roster(email: str, _: None = Depends(admin_bearer)):
    try:
        email = normalize_email(email)
    except IdentityFormatError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    with get_connection(_db_path) as conn:
        if conn.execute("SELECT 1 FROM voters WHERE voter_id = ?", (email,)).fetchone():
            raise HTTPException(
                status_code=409,
                detail="This student already has an account. Remove the account first (it must have no ballots).",
            )
        cur = conn.execute("DELETE FROM voter_roster WHERE email = ?", (email,))
        if cur.rowcount == 0:
            raise HTTPException(status_code=404, detail="Not on the roster")
        conn.commit()
        audit_log(conn, "roster_entry_removed", email)
    return {"ok": True}


# ---------- Security lab: probes the browser cannot run ----------


def _run_probe(fn, *args):
    if not _lab_lock.acquire(blocking=False):
        raise HTTPException(status_code=429, detail="Another lab attack is running. Try again in a few seconds.")
    try:
        return fn(*args)
    finally:
        _lab_lock.release()


def _lab_alert(kind: str, detail: str, actor: str, request: Request, severity: str | None = None) -> None:
    with get_connection(_db_path) as conn:
        record_alert(
            conn,
            kind,
            detail=detail,
            detected_by="Security lab probe",
            actor=f"lab run by {actor}",
            source_ip=client_ip(request),
            severity=severity,
        )


@router.post("/lab/echo")
async def lab_echo(request: Request):
    """Target of the sniffing probe: reads and discards the body. Holds no data and changes nothing."""
    return {"received_bytes": len(await request.body())}


@router.post("/lab/sniff")
def lab_sniff(request: Request, actor: str = Depends(require_signed_in)):
    # The plain-HTTP step reaches the real port-8000 listener, which raises its own alert.
    return _run_probe(run_sniff, default_target(settings))


@router.post("/lab/tls")
def lab_tls(request: Request, actor: str = Depends(require_signed_in)):
    res = _run_probe(run_tls_probe, default_target(settings))
    if res["outcome"] != "error":
        _lab_alert(
            "tls_downgrade",
            "A client offering only TLS 1.0/1.1 was "
            + ("refused: the server requires TLS 1.2 or newer." if res["downgrade_blocked"] else "ACCEPTED."),
            actor,
            request,
            None if res["downgrade_blocked"] else "high",
        )
        _lab_alert(
            "fake_server",
            "An impostor server with a self-signed certificate was "
            + ("rejected by a client that trusts only the SecureVote CA." if res["impostor_blocked"] else "ACCEPTED."),
            actor,
            request,
            None if res["impostor_blocked"] else "high",
        )
    return res


@router.post("/lab/db-theft")
def lab_db_theft(request: Request, actor: str = Depends(require_signed_in)):
    res = _run_probe(run_db_theft, _db_path)
    _lab_alert(
        "db_theft",
        "Offline attack on a copy of voting.db: " + res["summary"],
        actor,
        request,
        "high" if res["outcome"] == "exposed" else None,
    )
    return res


# ---------- What is stored in the database (admin, read-only) ----------

_STORED_VIEWS = [
    {
        "table": "election_votes",
        "title": "Ballots",
        "protection": "RSA-OAEP ciphertext, RSA-PSS signature, SHA-256 integrity hash",
        "sql": "SELECT election_id, voter_id, encrypted_vote, signature, integrity_hash FROM election_votes ORDER BY id DESC LIMIT 5",
        "secret": {"encrypted_vote", "signature", "integrity_hash"},
    },
    {
        "table": "elections",
        "title": "Election private keys",
        "protection": "AES-256-GCM, key derived with PBKDF2 (200,000 rounds) from a secret outside the database",
        "sql": "SELECT id, title, private_key_pem FROM elections ORDER BY id DESC LIMIT 5",
        "secret": {"private_key_pem"},
    },
    {
        "table": "voters",
        "title": "Voter passwords",
        "protection": "bcrypt, cost 12 (salted, one-way)",
        "sql": "SELECT voter_id, password_hash, identity_method FROM voters ORDER BY voter_id LIMIT 5",
        "secret": {"password_hash"},
    },
    {
        "table": "voter_roster",
        "title": "ID numbers on the roster",
        "protection": "HMAC-SHA256 with a key outside the database; only the last 4 digits in clear",
        "sql": "SELECT email, aadhaar_hmac, aadhaar_last4, college_id_hmac, college_id_last4 FROM voter_roster ORDER BY email LIMIT 5",
        "secret": {"aadhaar_hmac", "college_id_hmac"},
    },
    {
        "table": "voter_login_otps",
        "title": "One-time login codes",
        "protection": "SHA-256 hash of the code, expires in 5 minutes",
        "sql": "SELECT voter_id, otp_hash, expires_at, consumed FROM voter_login_otps ORDER BY id DESC LIMIT 5",
        "secret": {"otp_hash"},
    },
]


def _cut(v, n: int = 60):
    if v is None:
        return None
    s = str(v).replace("\n", " ")
    return s if len(s) <= n else s[:n] + "…"


@router.get("/admin/stored-data")
def stored_data(_: None = Depends(admin_bearer)):
    """Show exactly what the database file holds, so it can be demonstrated that nothing sensitive is readable."""
    out = []
    with get_connection(_db_path) as conn:
        for v in _STORED_VIEWS:
            rows = conn.execute(v["sql"]).fetchall()
            total = conn.execute(f"SELECT COUNT(*) AS c FROM {v['table']}").fetchone()["c"]
            cols = list(rows[0].keys()) if rows else [d.strip().split()[-1] for d in v["sql"].split("FROM")[0][6:].split(",")]
            out.append(
                {
                    "table": v["table"],
                    "title": v["title"],
                    "protection": v["protection"],
                    "columns": cols,
                    "protected_columns": sorted(v["secret"]),
                    "total": total,
                    "rows": [[_cut(r[c]) for c in cols] for r in rows],
                }
            )
    p = Path(_db_path).resolve()
    return {"path": str(p), "size_bytes": p.stat().st_size, "tables": out}
