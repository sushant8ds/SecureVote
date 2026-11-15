# Network Security: TLS (HTTPS)

## Why it is needed

The cryptography in the voting workflow protects the *ballot*: RSA-OAEP hides the choice and RSA-PSS proves who cast it. It does not protect the rest of the conversation between browser and server. Over plain HTTP, anyone on the same network could read or change:

| Data sent on every use | What an eavesdropper gains |
|---|---|
| Password (`POST /api/login`) | The voter's or administrator's account |
| One-time code | The second login factor |
| JWT bearer token (every API call) | A live session, without knowing the password |
| The page's JavaScript | The ability to replace the code that encrypts and signs ballots |

SecureVote therefore runs over **TLS**, the protocol behind HTTPS. TLS gives the connection three properties:

- **Confidentiality** – traffic is encrypted with a symmetric key agreed during the handshake.
- **Integrity** – every record is authenticated, so changes in transit are detected.
- **Server authentication** – the server proves its identity with an X.509 certificate, so the browser knows it is talking to the real voting server and not a machine in the middle.

## How it is implemented

| Part | File | What it does |
|---|---|---|
| Certificates | `src/tls_setup.py` | Creates a local certificate authority (CA) and a server certificate signed by it |
| HTTPS server | `run.py` | Starts the site on `https://127.0.0.1:8443/` with a restricted TLS configuration |
| HTTP redirect | `run.py` | Port 8000 answers every request with `308` to the HTTPS address; the application itself is never served over HTTP |
| Response headers | `src/main.py` | HSTS, Content-Security-Policy, and related headers |
| Local scripts | `static/js/vendor/` | The crypto library is served by the voting server itself, not a third-party CDN |
| UI indicator | top bar badge | Shows `HTTPS · TLS`, or a red warning if the page was opened over HTTP |

### Certificates

A public CA will not issue a certificate for `localhost`, so the project acts as its own CA:

1. A CA key pair (RSA-2048) and a self-signed CA certificate are generated. This certificate is the trust anchor.
2. A server key pair (RSA-2048) is generated.
3. The CA signs a server certificate (SHA-256 with RSA) naming `localhost`, `127.0.0.1`, and `::1` in the Subject Alternative Name extension, plus anything listed in `TLS_HOSTS`. It is marked for server authentication only and is valid for 397 days.
4. The CA private key is discarded. Nobody can use the trusted CA to sign another certificate.

Files are written to `data/tls/` (not committed): `ca_cert.pem`, `server_cert.pem`, and `server_key.pem` (owner-readable only). A new CA and certificate are created automatically when the certificate is missing, within 7 days of expiry, or lacks a requested host name.

To use a certificate from a real CA instead, set `TLS_CERT_FILE` and `TLS_KEY_FILE`.

### TLS configuration

| Setting | Value | Reason |
|---|---|---|
| Minimum version | TLS 1.2 | SSL 3, TLS 1.0 and TLS 1.1 have known weaknesses |
| Preferred version | TLS 1.3 | Negotiated by every current browser |
| TLS 1.2 cipher suites | ECDHE key exchange with AES-GCM or ChaCha20-Poly1305 | Forward secrecy and authenticated encryption; no CBC, RC4, or static-RSA key exchange |
| Compression | Off | Avoids compression side-channel attacks (CRIME) |

Forward secrecy means the session key comes from an ephemeral Diffie-Hellman exchange. If the server's private key is stolen later, recorded traffic still cannot be decrypted.

### Response headers

| Header | Effect |
|---|---|
| `Strict-Transport-Security` | The browser refuses plain HTTP for this host for a year, defeating downgrade ("SSL stripping") attacks. Not sent for the host name `localhost`, so other local development servers are unaffected. |
| `Content-Security-Policy` | Scripts load only from the voting server; the page cannot be framed |
| `X-Content-Type-Options: nosniff` | Uploaded images cannot be reinterpreted as scripts |
| `X-Frame-Options: DENY` | Blocks clickjacking |
| `Referrer-Policy: no-referrer` | URLs are not leaked to other sites |
| `Cache-Control: no-store` on `/api` | Tokens and keys are not written to caches |

## Running and trusting it

```bash
python run.py
```

Open `https://127.0.0.1:8443/`. The browser shows a warning the first time because it does not know the local CA. Either accept the warning, or trust the CA once (macOS):

```bash
security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db data/tls/ca_cert.pem
```

Remove it after the course with `security remove-trusted-cert data/tls/ca_cert.pem`.

## Demonstrating it

```bash
# 1. Handshake details: protocol version, cipher suite, certificate chain
openssl s_client -connect 127.0.0.1:8443 -CAfile data/tls/ca_cert.pem -brief </dev/null

# 2. Verified request
curl --cacert data/tls/ca_cert.pem https://127.0.0.1:8443/api/security/transport

# 3. A client that does not trust the CA refuses to connect (exit code 60)
curl https://127.0.0.1:8443/health

# 4. Old protocol versions are refused (exit code 35)
curl --tls-max 1.1 --cacert data/tls/ca_cert.pem https://127.0.0.1:8443/health

# 5. Plain HTTP is redirected
curl -i http://127.0.0.1:8000/api/elections
```

To show the difference on the wire, capture loopback traffic in Wireshark: with `uvicorn src.main:app` (HTTP) the login password is readable in the capture; with `python run.py` only the TLS handshake and encrypted application data are visible.

Automated checks are in `tests/test_network_security.py`: certificate chain and extensions, a real handshake verified against the CA, rejection of an untrusting client and of TLS 1.1, the redirect, and the headers.

## Other protocol use

OTP email is sent over SMTP with **STARTTLS** when `OTP_DELIVERY_MODE=smtp` (`SMTP_USE_STARTTLS=true`), so the one-time code is also encrypted between the server and the mail provider.

## Encryption at rest (related)

TLS protects data in transit only. Election private keys in the database are separately encrypted with **AES-256-GCM**; the key is derived with PBKDF2-HMAC-SHA256 (200,000 iterations, random salt per key) from `KEY_ENCRYPTION_SECRET`. A copy of the database file alone is not enough to decrypt ballots.

## Limits

- The local CA is for development. A deployment needs a certificate from a real CA.
- TLS does not hide a voter's choice from the server operator: the server holds the secret that unlocks the election key, and each stored ballot is linked to its voter ID.
