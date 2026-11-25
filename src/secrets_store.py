"""Server secrets that must not live in the source code or inside the database file.

When ``JWT_SECRET``, ``KEY_ENCRYPTION_SECRET`` or ``IDENTITY_PEPPER`` are not configured, a random
value is generated once and kept in ``<DATA_DIR>/secrets/<name>`` (mode 0600). A copy of
``voting.db`` on its own is therefore useless to an attacker: the AES key that wraps election private
keys and the HMAC key that protects ID numbers are not in it, and neither is a value printed in the repo.
"""

from __future__ import annotations

import functools
import os
import secrets
from pathlib import Path

# The value that shipped in config.py. Anyone who has read the repo knows it, so it is never used.
DEFAULT_JWT_SECRET = "change-me-in-production-use-long-random-secret"


@functools.lru_cache(maxsize=None)
def load_or_create(secrets_dir: Path, name: str) -> str:
    path = Path(secrets_dir) / name
    try:
        value = path.read_text(encoding="utf-8").strip()
        if value:
            return value
    except FileNotFoundError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    value = secrets.token_urlsafe(48)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        # Another process created it between our read and write: use theirs.
        return path.read_text(encoding="utf-8").strip()
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(value + "\n")
    return value
