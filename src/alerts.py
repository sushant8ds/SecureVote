"""Security alerts for the administrator.

Alerts are written by the code that actually stops an attack (ballot intake, sign-in, identity check,
the plain-HTTP listener), so a real attack raises the same alert as a run from the security lab.
Network and database probes that only the lab can perform are labelled "Security lab probe".

Repeats of the same attack by the same actor within ``COALESCE_SECONDS`` update one alert (with a
counter) instead of flooding the list.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone

COALESCE_SECONDS = 60

# kind -> (title, default severity)
KINDS: dict[str, tuple[str, str]] = {
    "forged_signature": ("Forged ballot signature", "high"),
    "replay": ("Replayed or backdated ballot", "high"),
    "double_vote": ("Second vote attempt", "high"),
    "ballot_for_other_voter": ("Ballot submitted in another voter's name", "high"),
    "otp_bruteforce": ("Login code guessing", "high"),
    "identity_mismatch": ("Identity check failed", "medium"),
    "identity_lockout": ("Repeated identity check failures", "high"),
    "plaintext_http": ("Credentials sent over plain HTTP", "medium"),
    "tls_downgrade": ("Old TLS version refused", "medium"),
    "fake_server": ("Impostor server certificate rejected", "medium"),
    "db_theft": ("Stolen database file examined", "medium"),
}

SEVERITIES = ("high", "medium", "low")


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def record_alert(
    conn: sqlite3.Connection,
    kind: str,
    *,
    detail: str,
    detected_by: str,
    actor: str | None = None,
    source_ip: str | None = None,
    severity: str | None = None,
) -> int:
    title, default_sev = KINDS.get(kind, (kind.replace("_", " ").capitalize(), "medium"))
    sev = severity if severity in SEVERITIES else default_sev
    now = _utc_iso()
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=COALESCE_SECONDS)).isoformat().replace("+00:00", "Z")
    row = conn.execute(
        """SELECT id FROM security_alerts
           WHERE kind = ? AND IFNULL(actor, '') = IFNULL(?, '') AND IFNULL(source_ip, '') = IFNULL(?, '')
             AND acknowledged = 0 AND last_seen_at >= ?
           ORDER BY id DESC LIMIT 1""",
        (kind, actor, source_ip, cutoff),
    ).fetchone()
    if row:
        conn.execute(
            "UPDATE security_alerts SET count = count + 1, last_seen_at = ?, detail = ?, severity = ? WHERE id = ?",
            (now, detail, sev, row["id"]),
        )
        conn.commit()
        return int(row["id"])
    cur = conn.execute(
        """INSERT INTO security_alerts (kind, severity, title, detail, actor, source_ip, detected_by,
                                        count, acknowledged, created_at, last_seen_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, 1, 0, ?, ?)""",
        (kind, sev, title, detail, actor, source_ip, detected_by, now, now),
    )
    conn.commit()
    return int(cur.lastrowid)


def alert_dict(r: sqlite3.Row) -> dict:
    return {
        "id": r["id"],
        "kind": r["kind"],
        "severity": r["severity"],
        "title": r["title"],
        "detail": r["detail"],
        "actor": r["actor"],
        "source_ip": r["source_ip"],
        "detected_by": r["detected_by"],
        "count": r["count"],
        "acknowledged": bool(r["acknowledged"]),
        "created_at": r["created_at"],
        "last_seen_at": r["last_seen_at"],
    }


def list_alerts(conn: sqlite3.Connection, limit: int = 100) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM security_alerts ORDER BY last_seen_at DESC, id DESC LIMIT ?", (limit,)
    ).fetchall()
    return [alert_dict(r) for r in rows]


def summary(conn: sqlite3.Connection) -> dict:
    unacked = conn.execute("SELECT COUNT(*) AS c FROM security_alerts WHERE acknowledged = 0").fetchone()["c"]
    latest = conn.execute(
        "SELECT * FROM security_alerts ORDER BY last_seen_at DESC, id DESC LIMIT 1"
    ).fetchone()
    return {"unacknowledged": unacked, "latest": alert_dict(latest) if latest else None}
