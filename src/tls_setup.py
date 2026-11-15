"""TLS (HTTPS) support: a local certificate authority and server certificate for the voting server.

The site is served over TLS 1.2+ so that passwords, OTPs, JWT bearer tokens and ballots are
protected in transit. For a course demo there is no public CA, so this module creates:

- a private CA certificate (the trust anchor a browser or client can import), and
- a server certificate signed by that CA, valid for ``localhost`` / ``127.0.0.1`` / ``::1``
  plus any extra names in ``TLS_HOSTS``.

Both use RSA-2048 with SHA-256 signatures, the same primitives as the rest of the project.
The CA private key is discarded after signing, so the trusted CA cannot be used to mint
further certificates; when the server certificate nears expiry a new CA + certificate is made.
"""

from __future__ import annotations

import ipaddress
import os
import ssl
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

RSA_KEY_SIZE = 2048
CA_VALID_DAYS = 825
SERVER_VALID_DAYS = 397  # browsers reject server certificates valid for longer than 398 days
RENEW_BEFORE_DAYS = 7
DEFAULT_HOSTS = ("localhost", "127.0.0.1", "::1")


@dataclass(frozen=True)
class TlsFiles:
    ca_cert: Path
    server_cert: Path
    server_key: Path


def tls_files(tls_dir: Path) -> TlsFiles:
    return TlsFiles(
        ca_cert=tls_dir / "ca_cert.pem",
        server_cert=tls_dir / "server_cert.pem",
        server_key=tls_dir / "server_key.pem",
    )


def _san_entries(hosts: list[str]) -> list[x509.GeneralName]:
    out: list[x509.GeneralName] = []
    for h in hosts:
        try:
            out.append(x509.IPAddress(ipaddress.ip_address(h)))
        except ValueError:
            out.append(x509.DNSName(h))
    return out


def _normalized_hosts(extra_hosts: list[str] | None) -> list[str]:
    hosts: list[str] = []
    for h in [*DEFAULT_HOSTS, *(extra_hosts or [])]:
        h = h.strip().lower()
        if h and h not in hosts:
            hosts.append(h)
    return hosts


def generate_certificates(tls_dir: Path, extra_hosts: list[str] | None = None) -> TlsFiles:
    """Create a fresh CA and a server certificate signed by it. Overwrites existing files."""
    tls_dir.mkdir(parents=True, exist_ok=True)
    files = tls_files(tls_dir)
    hosts = _normalized_hosts(extra_hosts)
    now = datetime.now(timezone.utc)

    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
    ca_name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureVote (course project)"),
            x509.NameAttribute(NameOID.COMMON_NAME, "SecureVote Local Development CA"),
        ]
    )
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=CA_VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=True,
                content_commitment=False, key_encipherment=False, data_encipherment=False,
                key_agreement=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )

    server_key = rsa.generate_private_key(public_exponent=65537, key_size=RSA_KEY_SIZE)
    server_cert = (
        x509.CertificateBuilder()
        .subject_name(
            x509.Name(
                [
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureVote (course project)"),
                    x509.NameAttribute(NameOID.COMMON_NAME, hosts[0]),
                ]
            )
        )
        .issuer_name(ca_name)
        .public_key(server_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=SERVER_VALID_DAYS))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=True,
                key_cert_sign=False, crl_sign=False, content_commitment=False,
                data_encipherment=False, key_agreement=False, encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName(_san_entries(hosts)), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(server_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    # ca_key goes out of scope here and is never written to disk.

    files.ca_cert.write_bytes(ca_cert.public_bytes(serialization.Encoding.PEM))
    files.server_cert.write_bytes(server_cert.public_bytes(serialization.Encoding.PEM))
    fd = os.open(files.server_key, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(
            server_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )
    os.chmod(files.server_key, 0o600)
    return files


def _certificate_usable(files: TlsFiles, hosts: list[str]) -> bool:
    if not (files.ca_cert.exists() and files.server_cert.exists() and files.server_key.exists()):
        return False
    try:
        cert = x509.load_pem_x509_certificate(files.server_cert.read_bytes())
        if cert.not_valid_after_utc - datetime.now(timezone.utc) < timedelta(days=RENEW_BEFORE_DAYS):
            return False
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
        have = {str(v).lower() for v in san.get_values_for_type(x509.DNSName)}
        have |= {str(v) for v in san.get_values_for_type(x509.IPAddress)}
        want = {str(ipaddress.ip_address(h)) if _is_ip(h) else h for h in hosts}
        return want <= have
    except Exception:
        return False


def _is_ip(h: str) -> bool:
    try:
        ipaddress.ip_address(h)
        return True
    except ValueError:
        return False


def ensure_certificates(tls_dir: Path, extra_hosts: list[str] | None = None) -> tuple[TlsFiles, bool]:
    """Return usable TLS files, generating them if missing, expiring, or lacking a requested host.

    The second value is True when new certificates were created (the CA must then be re-trusted).
    """
    files = tls_files(tls_dir)
    if _certificate_usable(files, _normalized_hosts(extra_hosts)):
        return files, False
    return generate_certificates(tls_dir, extra_hosts), True


def harden_server_context(ctx: ssl.SSLContext) -> None:
    """Restrict a server TLS context to TLS 1.2+ with forward-secret AEAD cipher suites."""
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    # TLS 1.3 suites are fixed by OpenSSL (all AEAD); this limits the TLS 1.2 ones.
    ctx.set_ciphers("ECDHE+AESGCM:ECDHE+CHACHA20")
    ctx.options |= ssl.OP_NO_COMPRESSION
