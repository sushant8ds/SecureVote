"""Voter identity verification against the college roster.

The roster is the college's record of who may vote: email, full name, date of birth, and the number
on the student's Aadhaar card and/or college ID card. At registration the student types the details
from one of those cards; the server compares them with the roster entry for their email.

ID numbers are never stored. The roster keeps ``HMAC-SHA256(pepper, "<type>:<number>")`` and the
last four digits for display. The pepper lives outside the database (see ``secrets_store``), so a
stolen database cannot be used to test guessed Aadhaar numbers offline, and the comparison is done
with ``hmac.compare_digest``.
"""

from __future__ import annotations

import csv
import hashlib
import hmac
import io
import logging
import re
import sqlite3
import unicodedata
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

logger = logging.getLogger("voting")

ID_TYPES = ("aadhaar", "college_id")
ID_LABELS = {"aadhaar": "Aadhaar card", "college_id": "College ID card"}

# Three wrong attempts for one email within the window lock identity checks for that email.
MAX_IDENTITY_FAILURES = 3
IDENTITY_LOCK_MINUTES = 15

_EMAIL_RE = re.compile(r"^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$")
_COLLEGE_ID_RE = re.compile(r"^[A-Z0-9]{5,20}$")


class IdentityFormatError(ValueError):
    """The input is malformed (a typo), as opposed to well-formed but not matching the roster."""


# ---------- Aadhaar checksum (Verhoeff), used by UIDAI for the 12th digit ----------

_D = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)
_P = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)
_INV = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)


def verhoeff_valid(digits: str) -> bool:
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _D[c][_P[i % 8][int(ch)]]
    return c == 0


def verhoeff_check_digit(digits: str) -> str:
    c = 0
    for i, ch in enumerate(reversed(digits)):
        c = _D[c][_P[(i + 1) % 8][int(ch)]]
    return str(_INV[c])


# ---------- Normalisation ----------


def normalize_email(raw: str) -> str:
    email = (raw or "").strip().lower()
    if not _EMAIL_RE.match(email):
        raise IdentityFormatError("Enter a valid email address")
    return email


def normalize_id_number(id_type: str, raw: str) -> str:
    if id_type not in ID_TYPES:
        raise IdentityFormatError("Choose Aadhaar card or College ID card")
    compact = re.sub(r"[\s-]", "", raw or "")
    if id_type == "aadhaar":
        if not re.fullmatch(r"\d{12}", compact):
            raise IdentityFormatError("An Aadhaar number has 12 digits")
        if compact[0] in "01" or not verhoeff_valid(compact):
            raise IdentityFormatError("That is not a valid Aadhaar number. Check it for a typo.")
        return compact
    compact = compact.upper()
    if not _COLLEGE_ID_RE.match(compact):
        raise IdentityFormatError("A college ID has 5 to 20 letters and digits")
    return compact


def normalize_name(raw: str) -> str:
    """Case, spacing, dots and accents do not matter: 'K. S.  Rao' == 'k s rao'."""
    s = unicodedata.normalize("NFKD", raw or "")
    s = "".join(ch for ch in s if not unicodedata.combining(ch))
    s = re.sub(r"[.,'’-]", " ", s).casefold()
    return " ".join(s.split())


def normalize_dob(raw: str) -> str:
    try:
        d = date.fromisoformat((raw or "").strip())
    except ValueError as exc:
        raise IdentityFormatError("Enter the date of birth as YYYY-MM-DD") from exc
    if d >= date.today() or d.year < 1900:
        raise IdentityFormatError("Enter a real date of birth")
    return d.isoformat()


def id_digest(secret: str, id_type: str, normalized: str) -> str:
    return hmac.new(secret.encode("utf-8"), f"{id_type}:{normalized}".encode("utf-8"), hashlib.sha256).hexdigest()


def masked(last4: str | None) -> str | None:
    return f"•••• {last4}" if last4 else None


# ---------- Roster storage ----------


def _utc_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def add_roster_entry(
    conn: sqlite3.Connection,
    secret: str,
    *,
    email: str,
    full_name: str,
    date_of_birth: str,
    aadhaar: str | None,
    college_id: str | None,
    source: str,
    upsert: bool = False,
) -> str:
    """Validate and store one roster entry. Raises ``IdentityFormatError`` or ``sqlite3.IntegrityError``."""
    email = normalize_email(email)
    name = " ".join((full_name or "").split())
    if len(name) < 2:
        raise IdentityFormatError("Enter the full name")
    dob = normalize_dob(date_of_birth)
    a = normalize_id_number("aadhaar", aadhaar) if (aadhaar or "").strip() else None
    c = normalize_id_number("college_id", college_id) if (college_id or "").strip() else None
    if not a and not c:
        raise IdentityFormatError("Give an Aadhaar number, a college ID, or both")
    values = (
        email,
        name,
        dob,
        id_digest(secret, "aadhaar", a) if a else None,
        a[-4:] if a else None,
        id_digest(secret, "college_id", c) if c else None,
        c[-4:] if c else None,
        source,
        _utc_iso(),
    )
    sql = """INSERT INTO voter_roster (email, full_name, date_of_birth, aadhaar_hmac, aadhaar_last4,
                                       college_id_hmac, college_id_last4, source, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)"""
    if upsert:
        sql += """ ON CONFLICT(email) DO UPDATE SET full_name = excluded.full_name,
                     date_of_birth = excluded.date_of_birth,
                     aadhaar_hmac = excluded.aadhaar_hmac, aadhaar_last4 = excluded.aadhaar_last4,
                     college_id_hmac = excluded.college_id_hmac, college_id_last4 = excluded.college_id_last4"""
    conn.execute(sql, values)
    return email


def import_roster_file(conn: sqlite3.Connection, path: Path, secret: str) -> int | None:
    """Import the roster CSV when its content (or the pepper) changed since the last import.

    Columns: ``email,full_name,date_of_birth,aadhaar,college_id``. Rows are upserted by email, so a
    corrected CSV updates the entry; entries added in the admin screen are left alone. Returns the
    number of rows imported, or ``None`` when the file is missing or unchanged.
    """
    from src.database import get_meta, set_meta

    path = Path(path)
    if not path.is_file():
        logger.warning("Voter roster file %s not found; only entries added by an administrator can register", path)
        return None
    raw = path.read_bytes()
    pepper_fp = hmac.new(secret.encode("utf-8"), b"roster-pepper-fingerprint", hashlib.sha256).hexdigest()[:16]
    stamp = hashlib.sha256(raw).hexdigest() + ":" + pepper_fp
    if get_meta(conn, "roster_import_stamp") == stamp:
        return None
    n = 0
    for lineno, row in enumerate(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"))), start=2):
        if not any((v or "").strip() for v in row.values()):
            continue
        try:
            add_roster_entry(
                conn,
                secret,
                email=row.get("email", ""),
                full_name=row.get("full_name", ""),
                date_of_birth=row.get("date_of_birth", ""),
                aadhaar=row.get("aadhaar"),
                college_id=row.get("college_id"),
                source="import",
                upsert=True,
            )
            n += 1
        except IdentityFormatError as exc:
            logger.error("Roster %s line %s skipped: %s", path.name, lineno, exc)
        except sqlite3.IntegrityError:
            logger.error("Roster %s line %s skipped: ID number already belongs to another entry", path.name, lineno)
    conn.commit()
    set_meta(conn, "roster_import_stamp", stamp)
    logger.info("Imported %s voter roster entr%s from %s", n, "y" if n == 1 else "ies", path)
    return n


def roster_row(conn: sqlite3.Connection, email: str) -> sqlite3.Row | None:
    return conn.execute("SELECT * FROM voter_roster WHERE email = ?", (email,)).fetchone()


def is_on_roster(conn: sqlite3.Connection, email: str) -> bool:
    return conn.execute("SELECT 1 FROM voter_roster WHERE email = ?", (email,)).fetchone() is not None


def mismatched_fields(
    row: sqlite3.Row, secret: str, *, id_type: str, id_number: str, full_name: str, date_of_birth: str
) -> list[str]:
    """Compare normalised input with the roster entry. Returns the fields that do not match."""
    bad: list[str] = []
    stored = row["aadhaar_hmac"] if id_type == "aadhaar" else row["college_id_hmac"]
    if not stored or not hmac.compare_digest(id_digest(secret, id_type, id_number), stored):
        bad.append("id_number")
    if normalize_name(full_name) != normalize_name(row["full_name"]):
        bad.append("name")
    if date_of_birth != row["date_of_birth"]:
        bad.append("date_of_birth")
    return bad


def recent_failures(conn: sqlite3.Connection, email: str) -> int:
    since = (datetime.now(timezone.utc) - timedelta(minutes=IDENTITY_LOCK_MINUTES)).isoformat().replace("+00:00", "Z")
    return conn.execute(
        "SELECT COUNT(*) AS c FROM identity_checks WHERE email = ? AND ok = 0 AND created_at >= ?",
        (email, since),
    ).fetchone()["c"]


def record_check(conn: sqlite3.Connection, email: str, id_type: str, ok: bool, reason: str | None, ip: str | None) -> None:
    conn.execute(
        "INSERT INTO identity_checks (email, id_type, ok, reason, source_ip, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (email, id_type, 1 if ok else 0, reason, ip, _utc_iso()),
    )
    conn.commit()
