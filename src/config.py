from pathlib import Path

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict

from src.secrets_store import DEFAULT_JWT_SECRET, load_or_create

# Resolve .env from the repo root so admin credentials load even if uvicorn's cwd is elsewhere.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=_PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    data_dir: Path = Field(
        default=Path(__file__).resolve().parent.parent / "data",
        validation_alias="DATA_DIR",
    )
    database_path: Path | None = Field(default=None, validation_alias="DATABASE_PATH")

    # Empty or the old built-in default -> a random secret is generated in <DATA_DIR>/secrets/.
    jwt_secret: str = ""
    jwt_algorithm: str = "HS256"
    jwt_expire_minutes: int = 60

    admin_password: str = "admin-change-me"
    admin_username: str = "admin"
    # When true, on each app start the admin named ADMIN_USERNAME gets password hash from ADMIN_PASSWORD (fixes .env vs old DB mismatch).
    sync_admin_from_env: bool = Field(default=True, validation_alias="SYNC_ADMIN_FROM_ENV")

    election_starts_at: str | None = None
    election_ends_at: str | None = None
    # The college's voter roster (email, name, date of birth, Aadhaar and/or college ID). Imported into
    # the voter_roster table when the file changes; only roster emails can register, and registration
    # must match the identity details on record. See docs/identity_verification.md.
    voter_roster_file: Path = Field(
        default=_PROJECT_ROOT / "config" / "voter_roster.csv",
        validation_alias="VOTER_ROSTER_FILE",
    )
    # HMAC key for ID numbers in the roster. Empty -> generated in <DATA_DIR>/secrets/.
    identity_pepper: str = Field(default="", validation_alias="IDENTITY_PEPPER")
    otp_expire_seconds: int = Field(default=300, validation_alias="OTP_EXPIRE_SECONDS")
    # demo -> return/log OTP (no email). smtp -> send real email via SMTP.
    otp_delivery_mode: str = Field(default="demo", validation_alias="OTP_DELIVERY_MODE")
    smtp_host: str = Field(default="", validation_alias="SMTP_HOST")
    smtp_port: int = Field(default=587, validation_alias="SMTP_PORT")
    smtp_username: str = Field(default="", validation_alias="SMTP_USERNAME")
    smtp_password: str = Field(default="", validation_alias="SMTP_PASSWORD")
    smtp_from_email: str = Field(default="", validation_alias="SMTP_FROM_EMAIL")
    smtp_use_starttls: bool = Field(default=True, validation_alias="SMTP_USE_STARTTLS")
    # For demo/testing only. Keep false in production; OTP stays email-only.
    expose_otp_in_response: bool = Field(default=True, validation_alias="EXPOSE_OTP_IN_RESPONSE")

    # --- Transport security (run.py) ---
    host: str = Field(default="127.0.0.1", validation_alias="HOST")
    https_port: int = Field(default=8443, validation_alias="HTTPS_PORT")
    # Plain-HTTP port that only redirects to HTTPS. 0 disables it.
    http_redirect_port: int = Field(default=8000, validation_alias="HTTP_REDIRECT_PORT")
    # Optional real certificate; otherwise a local CA + certificate is generated in <DATA_DIR>/tls.
    tls_cert_file: Path | None = Field(default=None, validation_alias="TLS_CERT_FILE")
    tls_key_file: Path | None = Field(default=None, validation_alias="TLS_KEY_FILE")
    # Extra comma-separated DNS names / IPs for the generated certificate (e.g. a LAN address).
    tls_hosts: str = Field(default="", validation_alias="TLS_HOSTS")

    # Secret used to derive the AES-256-GCM key that encrypts election private keys in the database.
    # Empty -> generated in <DATA_DIR>/secrets/. Changing it makes existing elections impossible to tally.
    key_encryption_secret: str = Field(default="", validation_alias="KEY_ENCRYPTION_SECRET")

    def secrets_dir(self) -> Path:
        return self.data_dir / "secrets"

    def jwt_secret_is_configured(self) -> bool:
        return bool(self.jwt_secret) and self.jwt_secret != DEFAULT_JWT_SECRET

    def jwt_signing_secret(self) -> str:
        if self.jwt_secret_is_configured():
            return self.jwt_secret
        return load_or_create(self.secrets_dir(), "jwt_secret")

    def key_wrap_secret(self) -> str:
        return self.key_encryption_secret or load_or_create(self.secrets_dir(), "key_encryption_secret")

    def identity_secret(self) -> str:
        return self.identity_pepper or load_or_create(self.secrets_dir(), "identity_pepper")

    def tls_dir(self) -> Path:
        return self.data_dir / "tls"

    def tls_extra_hosts(self) -> list[str]:
        return [h.strip() for h in (self.tls_hosts or "").split(",") if h.strip()]

    def db_file(self) -> Path:
        if self.database_path is not None:
            return Path(self.database_path)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        return self.data_dir / "voting.db"



settings = Settings()
