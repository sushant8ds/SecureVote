# Secure Digital Voting System Using Applied Cryptography

Course-scale voting platform with a **web UI** at `/`, a JSON API under `/api`, and cryptography aligned with `docs/` (proposal, CDDR, interface spec, key lifecycle).



The root path `/` must serve the app. This project now serves **`GET /`** as the SecureVote UI. JSON APIs live under **`/api/...`** (for example `/api/login`). Hitting a path that does not exist still returns JSON `Not Found` from FastAPI.

## Security properties

| Property | Mechanism |
|----------|-----------|
| Vote confidentiality | Per-election RSA-2048 OAEP (SHA-256) |
| Integrity of stored ciphertext | SHA-256 over ciphertext |
| Passwords | bcrypt |
| Sessions | JWT (`Bearer`) |
| Ballot origin | RSA-PSS + SHA-256 over UTF-8 `encrypted_vote ‖ \| ‖ timestamp` |
| Data in transit | TLS 1.2+ (HTTPS) with a locally generated CA and server certificate; HTTP redirects to HTTPS |
| Election private keys at rest | AES-256-GCM, key derived with PBKDF2-HMAC-SHA256 |

Voter **signing** key pairs are generated in the browser (WebCrypto); only the public key is sent to the server, and the private key is stored in **browser `localStorage`** for the demo UI. Each election has its own RSA key pair in the database.

Other enforced rules:

- The election window is checked against the **server clock**, and the signed ballot timestamp must be within 5 minutes of it.
- Ballots are decrypted **only at tally**, never at submission.
- A login OTP is invalidated after 5 wrong guesses.
- A voter who has cast a ballot cannot be deleted (it would remove the ballot).

Known limit of this prototype: each stored ballot is linked to its voter ID and the server holds the secret that unlocks the election key, so the server operator can learn how a voter voted.

Transport security is described in `docs/network_security.md`.

## Layout

```
.
├── docs/
├── run.py         # HTTPS launcher (TLS) + HTTP→HTTPS redirect
├── src/           # main.py, api_routes.py, crypto_service.py, tls_setup.py, database.py, …
├── static/        # CSS + JS for the UI
├── templates/     # app.html (single-page shell)
├── tests/
├── data/          # runtime DB + uploads (gitignored)
└── requirements.txt
```

## Setup

Use Python 3.12 or 3.13 (the pinned dependencies do not build on 3.14).

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp config/.env.example .env   # set JWT_SECRET and ADMIN_PASSWORD
```

## Run

```bash
python run.py
```

Open **https://127.0.0.1:8443/** in a browser. The first start creates a local CA and server certificate in `data/tls/`; the browser warns until you accept it or trust `data/tls/ca_cert.pem` (see `docs/network_security.md`). `http://127.0.0.1:8000/` redirects to the HTTPS address.

For development without TLS: `uvicorn src.main:app --reload --host 127.0.0.1 --port 8000`. The top bar then shows a red "Not encrypted" badge.

- **Voter**: sign in or create an account with an authorized `@umsystem.edu` email. Sign-in is password, then a one-time code. The **Elections** tab lists what you can vote in, request access to, or have finished; **Results** shows published counts.
- **Administrator**: switch to *Administrator* on the sign-in screen. The password is `ADMIN_PASSWORD` from `.env`.
- **Administration**: *New election* (who can vote, open/close times, candidate names + photos), *Access requests* to approve or decline voters, and *Elections* to **Close voting** and then **Count and publish** the results.

### Environment

| Variable | Purpose |
|----------|---------|
| `JWT_SECRET` | HMAC key for JWTs |
| `KEY_ENCRYPTION_SECRET` | Derives the AES-256-GCM key protecting election private keys in the database (falls back to `JWT_SECRET`) |
| `HOST`, `HTTPS_PORT`, `HTTP_REDIRECT_PORT` | Listener settings for `run.py` (defaults `127.0.0.1`, `8443`, `8000`; redirect port `0` = off) |
| `TLS_HOSTS` | Extra names / IPs for the generated certificate |
| `TLS_CERT_FILE`, `TLS_KEY_FILE` | Use a real certificate instead of the generated one |
| `ADMIN_PASSWORD` | Used to seed the first admin account if the `admins` table is empty (bcrypt in DB) |
| `ADMIN_USERNAME` | Username for that seeded account (default `admin`) |
| `STUDENT_EMAIL_ALLOWLIST` | Comma-separated authorized student emails (e.g. `ts8md@umsystem.edu,spc7p@umsystem.edu`) |
| `OTP_EXPIRE_SECONDS` | OTP lifetime in seconds (default `300`) |
| `OTP_DELIVERY_MODE` | `demo` (logs/returns OTP) or `smtp` (sends real OTP email) |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USERNAME`, `SMTP_PASSWORD`, `SMTP_FROM_EMAIL`, `SMTP_USE_STARTTLS` | SMTP settings used when `OTP_DELIVERY_MODE=smtp` |
| `EXPOSE_OTP_IN_RESPONSE` | Demo/testing helper to include OTP in API response (`true` by default; set `false` in production) |
| `DATABASE_PATH` | Optional SQLite path (default `./data/voting.db`) |
| `DATA_DIR` | Optional data root for DB default path + `uploads/` |

## API (summary)

All under prefix **`/api`**:

- `POST /api/register` (optional `public_key_pem`), `POST /api/login` (password, then password + `otp`), `POST /api/voter/restore-signing-key`, `GET /api/admin/setup-status`, `POST /api/admin/register-first` (only if no admins), `POST /api/admin/login` (username + password), `GET /api/admin/dashboard-summary`
- `GET /api/elections` (optional `Authorization: Bearer` voter token for per-user status)
- `GET /api/elections/{id}/detail`
- `POST /api/elections/{id}/register` (voter)
- `GET /api/admin/registrations?status_filter=pending`
- `POST /api/admin/registrations/{id}/approve|reject`
- `POST /api/admin/elections` (multipart: title, category, starts_at, ends_at, contestant_names JSON, photos[])
- `POST /api/elections/{id}/vote` — body: `voter_id`, `encrypted_vote` (base64), `signature`, `timestamp`; plaintext JSON is `{"contestant_id": <int>}`
- `POST /api/admin/elections/{id}/close`, `POST /api/admin/elections/{id}/publish-results`
- `GET /api/elections/{id}/results` (after publish)

Legacy shims for the original single-election flow: `/api/legacy/...`.

## Tests

```bash
pytest
```

## Scripted demo

With the server running (`python run.py`) in demo OTP mode:

```bash
python scripts/demo_flow.py --voter bayd6@umsystem.edu
```

## Real OTP email setup

1. Set these in `.env`:

```env
OTP_DELIVERY_MODE=smtp
SMTP_HOST=smtp.office365.com
SMTP_PORT=587
SMTP_USERNAME=<your-mail@umsystem.edu>
SMTP_PASSWORD=<smtp/app-password>
SMTP_FROM_EMAIL=<your-mail@umsystem.edu>
SMTP_USE_STARTTLS=true
EXPOSE_OTP_IN_RESPONSE=false
```

2. Restart the server.
3. Login sends OTP to the student email in `STUDENT_EMAIL_ALLOWLIST`.

## License

MIT — see `LICENSE`.
