"""Bootstrap default admin account when none exist (after schema + migrations)."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from cryptography.exceptions import InvalidTag

from src.config import settings
from src.crypto_service import hash_password, is_wrapped_private_key, unwrap_private_key, wrap_private_key
from src.database import audit_log, get_connection, get_meta, init_schema, set_meta
from src.identity import import_roster_file
from src.secrets_store import DEFAULT_JWT_SECRET

logger = logging.getLogger("voting")


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _prune_voters_not_on_roster(conn) -> None:
    """Remove voter rows whose email is no longer on the voter roster.

    Voters who already cast a ballot are kept: deleting them would cascade to ``election_votes`` and
    silently change a tally. They still cannot sign in, because the roster is checked on every request.
    """
    allowed = {r["email"] for r in conn.execute("SELECT email FROM voter_roster").fetchall()}
    if not allowed:
        logger.warning("The voter roster is empty: no student can register (not pruning voters).")
        return
    rows = conn.execute("SELECT voter_id FROM voters").fetchall()
    removed = 0
    kept = 0
    for r in rows:
        raw = str(r["voter_id"])
        vid = raw.strip().lower()
        if vid not in allowed:
            if conn.execute("SELECT 1 FROM election_votes WHERE voter_id = ? LIMIT 1", (raw,)).fetchone():
                kept += 1
                continue
            conn.execute("DELETE FROM voters WHERE voter_id = ?", (raw,))
            removed += 1
    if kept:
        logger.warning(
            "%s voter(s) are no longer on the roster but have recorded ballots; rows kept so tallies stay intact",
            kept,
        )
    if removed:
        conn.commit()
        audit_log(conn, "voters_pruned_roster", f"removed {removed} voter(s) not on the voter roster")
        logger.info("Removed %s voter row(s) not on the voter roster", removed)


def _encrypt_plaintext_election_keys(conn) -> None:
    """Databases created before key wrapping hold election private keys as plain PEM; encrypt them in place."""
    rows = conn.execute("SELECT id, private_key_pem FROM elections").fetchall()
    n = 0
    for r in rows:
        if not is_wrapped_private_key(r["private_key_pem"]):
            wrapped = wrap_private_key(r["private_key_pem"].encode("utf-8"), settings.key_wrap_secret())
            conn.execute("UPDATE elections SET private_key_pem = ? WHERE id = ?", (wrapped, r["id"]))
            n += 1
    if n:
        conn.commit()
        audit_log(conn, "election_keys_encrypted", f"wrapped {n} election private key(s) with AES-256-GCM")
        logger.info("Encrypted %s election private key(s) at rest", n)


def _rewrap_keys_from_old_secrets(conn) -> None:
    """Election keys used to be wrapped with JWT_SECRET, which defaulted to a value printed in the repo.

    Re-wrap every key that still opens with one of those old secrets under the current key-encryption
    secret, so a stolen database cannot be decrypted with a value anyone can read on GitHub. Runs once.
    """
    if get_meta(conn, "key_wrap_secret_v2"):
        return
    current = settings.key_wrap_secret()
    legacy = [s for s in dict.fromkeys([settings.jwt_secret, DEFAULT_JWT_SECRET]) if s and s != current]
    moved = stuck = 0
    for r in conn.execute("SELECT id, private_key_pem FROM elections").fetchall():
        stored = r["private_key_pem"]
        if not is_wrapped_private_key(stored):
            continue
        try:
            unwrap_private_key(stored, current)
            continue
        except InvalidTag:
            pass
        for old in legacy:
            try:
                pem = unwrap_private_key(stored, old)
            except InvalidTag:
                continue
            conn.execute(
                "UPDATE elections SET private_key_pem = ? WHERE id = ?", (wrap_private_key(pem, current), r["id"])
            )
            moved += 1
            break
        else:
            stuck += 1
            logger.error("Election %s: private key does not open with the current secret; it cannot be tallied", r["id"])
    conn.commit()
    set_meta(conn, "key_wrap_secret_v2", "1")
    if moved:
        audit_log(conn, "election_keys_rewrapped", f"{moved} key(s) moved off the old JWT-derived secret")
        logger.info("Re-wrapped %s election key(s) under the current key-encryption secret", moved)


def ensure_bootstrap(db_path, admin_plain_password: str, _starts_at: str | None, _ends_at: str | None) -> None:
    with get_connection(db_path) as conn:
        init_schema(conn)
        import_roster_file(conn, settings.voter_roster_file, settings.identity_secret())
        _prune_voters_not_on_roster(conn)
        _encrypt_plaintext_election_keys(conn)
        _rewrap_keys_from_old_secrets(conn)
        un = settings.admin_username.strip() or "admin"
        n = conn.execute("SELECT COUNT(*) AS c FROM admins").fetchone()["c"]
        ph = hash_password(admin_plain_password)
        row = conn.execute("SELECT username FROM admins WHERE username = ?", (un,)).fetchone()

        if settings.sync_admin_from_env:
            if row:
                conn.execute("UPDATE admins SET password_hash = ? WHERE username = ?", (ph, un))
                conn.commit()
                audit_log(conn, "admin_password_synced", un)
                return
            if n == 0:
                conn.execute(
                    "INSERT INTO admins (username, password_hash, created_at) VALUES (?,?,?)",
                    (un, ph, _utc_iso()),
                )
                conn.commit()
                audit_log(conn, "admin_bootstrap", f"Seeded administrator {un!r} from .env")
                return
            # Other admins exist but not ADMIN_USERNAME — still create/sync the .env account so login works.
            conn.execute(
                "INSERT INTO admins (username, password_hash, created_at) VALUES (?,?,?)",
                (un, ph, _utc_iso()),
            )
            conn.commit()
            audit_log(conn, "admin_bootstrap", f"Added administrator {un!r} from .env (SYNC_ADMIN_FROM_ENV)")
            return

        if n > 0:
            return
        conn.execute(
            "INSERT INTO admins (username, password_hash, created_at) VALUES (?,?,?)",
            (un, ph, _utc_iso()),
        )
        conn.commit()
        audit_log(conn, "admin_bootstrap", f"Seeded administrator {un!r} (configure ADMIN_USERNAME / ADMIN_PASSWORD in .env)")
