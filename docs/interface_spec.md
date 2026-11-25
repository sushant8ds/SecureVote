# Interface Specification

## Overview

This document defines the interface formats, required fields, validation rules, and error codes for the Secure Digital Voting System.

The goal of this specification is to ensure clarity, consistency, and misuse prevention in how system components communicate.

**Version 2.** The Week 5 freeze described a single-election API (`/register`, `/login`, `/vote`, `/tally`). The implementation moved to multiple elections, a voter roster with ID-card verification, OTP login, per-election access approval, and admin security alerts; the changes are listed in section 10. All endpoints are under the `/api` prefix and exchange JSON unless noted.

---

# 1. System Actors

- Voter
- Election Authority (Admin)
- Voting Server

Authenticated requests carry `Authorization: Bearer <JWT>`. The JWT holds `sub` (voter email or admin username), `role` (`voter` or `admin`), `iat`, and `exp` (60 minutes).

---

# 2. Registration Interface

## Endpoint
POST /api/register

## Request Format

{
  "voter_id": "string",
  "password": "string",
  "id_type": "aadhaar | college_id",
  "id_number": "string",
  "full_name": "string",
  "date_of_birth": "YYYY-MM-DD",
  "public_key_pem": "string (optional)"
}

## Fields

- voter_id: college email that is on the voter roster (`voter_roster` table, imported from `VOTER_ROSTER_FILE`); stored lowercase
- password: minimum 8 characters
- id_type, id_number, full_name, date_of_birth: the details printed on the voter's Aadhaar card or college ID card. An Aadhaar number has 12 digits (spaces and dashes are ignored), does not start with 0 or 1, and must pass the Verhoeff check digit. A college ID has 5–20 letters and digits.
- public_key_pem: voter RSA public key (SPKI PEM, at least 2048 bits) generated on the voter's device. If omitted, the server generates the key pair and returns the private key once.

## Response (201)

{
  "voter_id": "string",
  "voter_private_key_pem": "string or null",
  "message": "string"
}

`voter_private_key_pem` is null when the client supplied `public_key_pem`.

## Processing Rules

- Identity is checked before the account is created: `HMAC-SHA256(pepper, "<id_type>:<number>")` must equal the roster value (compared with `hmac.compare_digest`), the name must match ignoring case, spacing, dots and accents, and the date of birth must match exactly.
- A mismatch does not say which field was wrong. Three failed checks for one email within 15 minutes pause checks for that email. Each failure raises an admin alert.
- Typed ID numbers are never stored. The account records `identity_method` and `identity_verified_at`.
- Password must be hashed using bcrypt before storage.
- Duplicate voter_id must be rejected.
- Plaintext passwords and voter private keys must never be stored.

## Error Codes

- 400 – Malformed email, malformed or checksum-invalid ID number, impossible date of birth, or invalid public key
- 403 – Email not on the voter roster, or identity details do not match the roster (the message gives the attempts left)
- 409 – Voter already exists
- 422 – Malformed request body
- 429 – Identity checks for this email are paused after 3 failures

`POST /api/register/precheck` with `{ "voter_id": "string" }` runs only the email checks (400 / 403) without creating an account. See `identity_verification.md`.

---

# 3. Login Interface

## Endpoint
POST /api/login

Login takes two calls to the same endpoint.

## Step 1 – Password

{
  "voter_id": "string",
  "password": "string"
}

Response: `{ "otp_required": true, "message": "...", "expires_in_seconds": 300 }`. A 6-digit code is emailed to the voter (SMTP mode) or logged (demo mode). In demo mode with `EXPOSE_OTP_IN_RESPONSE=true` the response also contains `dev_otp`.

## Step 2 – Password and OTP

{
  "voter_id": "string",
  "password": "string",
  "otp": "string"
}

Response: `{ "access_token": "JWT", "token_type": "bearer" }`

## Processing Rules

- Password must be verified using bcrypt hash comparison before an OTP is issued.
- Only the SHA-256 hash of the OTP is stored. Issuing a new OTP invalidates earlier ones.
- An OTP is single-use, expires after `OTP_EXPIRE_SECONDS`, and is invalidated after 5 wrong attempts.

## Error Codes

- 400 – Malformed email
- 401 – Wrong password, wrong / expired / missing OTP, or too many wrong OTP attempts (the fifth miss raises a *Login code guessing* alert)
- 403 – Email not on the voter roster
- 404 – Voter not found

## Related Voter Endpoints

- `GET /api/voter/session` – returns `{ "voter_id", "full_name", "identity_verified", "identity_method" }` for a valid voter token.
- `POST /api/voter/verify-identity` – body `{ "id_type", "id_number", "full_name", "date_of_birth" }`. One-time verification for accounts created before identity checks; same rules and error codes as registration.
- `POST /api/voter/restore-signing-key` – body `{ "password", "public_key_pem" (optional) }`. Replaces the voter's public key after a password check. Earlier ballots stay verifiable because each stored ballot keeps the public key used when it was cast.

---

# 4. Election Access Interface

- `GET /api/elections` – list of elections. With a voter token, each entry includes `my_registration_status` (`pending`, `approved`, `rejected`, or null) and `my_voted`.
- `GET /api/elections/{id}/detail` – election metadata and contestants (`id`, `name`, `image_url`). `public_key_pem` is included only for an authenticated voter.
- `POST /api/elections/{id}/register` – voter requests access; creates a `pending` registration. Errors: 403 identity not verified or election closed, 404 election not found, 409 already requested.

---

# 5. Vote Submission Interface

## Endpoint
POST /api/elections/{id}/vote

## Request Format

{
  "voter_id": "string",
  "encrypted_vote": "string",
  "signature": "string",
  "timestamp": "string"
}

## Field Definitions

- voter_id: must equal the authenticated voter
- encrypted_vote: Base64 of the RSA-OAEP (SHA-256, MGF1-SHA-256) encryption, under the election public key, of the UTF-8 JSON `{"contestant_id": <int>}`
- signature: Base64 RSA-PSS signature (SHA-256, MGF1-SHA-256, 32-byte salt) by the voter private key over the UTF-8 bytes of `encrypted_vote + "|" + timestamp`
- timestamp: ISO 8601 timestamp of signing

## Required Fields

All fields are mandatory.

## Validation Rules

Checked in this order:

- voter_id must equal the authenticated voter.
- The election must exist and must not be closed.
- The voter must have an approved registration for this election and a verified identity.
- The signature must verify with the voter's public key. This runs before the duplicate check, so a forged ballot is reported as forged even from a voter who has already voted.
- The server clock must be within the election window; the timestamp must be within the window and within 5 minutes of the server clock.
- The voter must not have already voted in this election.
- Encrypted vote must be valid Base64 of exactly 256 bytes.
- The server does not decrypt the ballot at submission.

A forged signature, an out-of-window or stale signed timestamp, a second ballot, or a ballot in another voter's name raises an admin security alert (section 8).

## Error Codes

- 400 – Invalid vote format
- 401 – Unauthorized (not logged in, or voter_id does not match the session)
- 403 – Election closed, voter not approved, identity not verified, or voter has already voted
- 404 – Election not found
- 409 – Invalid signature
- 422 – Vote outside election window, or timestamp too far from server time

---

# 6. Administration and Tally Interface

All endpoints require an admin token (401 otherwise).

- `POST /api/admin/login` – `{ "username", "password" }` returns a JWT.
- `POST /api/admin/elections` – multipart form: `title`, `category` (`class` | `department` | `campus`), `starts_at`, `ends_at`, `contestant_names` (JSON array), `photos` (one JPEG/PNG/WebP per contestant, max 2 MB each). Generates the election RSA key pair.
- `GET /api/admin/registrations?status_filter=pending|approved|rejected|all`
- `POST /api/admin/registrations/{id}/approve` and `/reject` – 404 if no pending registration has that id.
- `POST /api/admin/elections/{id}/close`
- `POST /api/admin/elections/{id}/publish-results` – the tally. 403 if the election is not closed.
- `GET /api/admin/dashboard-summary`, `GET /api/admin/election-stats` – counts only; no ballot contents.
- `POST /api/admin/voters/delete` – `{ "voter_id" }`. 409 if the voter has cast a ballot.
- `GET /api/admin/roster` – roster entries with masked ID numbers (`•••• 1234`) and account / verification status. ID numbers are never returned.
- `POST /api/admin/roster` – `{ "email", "full_name", "date_of_birth", "aadhaar" (optional), "college_id" (optional) }`; at least one ID. 400 malformed, 409 email already on the roster or ID number already used by another entry.
- `DELETE /api/admin/roster/{email}` – 409 if the student already has an account, 404 if not on the roster.

## Tally Processing Rules

For each stored ballot, in order:

- Verify the integrity hash before decryption.
- Verify the signature against the voter public key stored with the ballot.
- Decrypt using the election private key.
- Check that the contestant belongs to the election.

A ballot failing any step is not counted and is reported in `integrity_failures` as `integrity:`, `signature:`, `decrypt:`, or `contestant:` followed by the voter ID.

## Results

`GET /api/elections/{id}/results` is public and returns per-contestant counts. 403 until results are published.

---

# 7. Data Storage Format

## Stored Vote Record Structure

{
  "election_id": "integer",
  "voter_id": "string",
  "encrypted_vote": "string",
  "signature": "string",
  "integrity_hash": "string",
  "timestamp": "string",
  "voter_public_key_pem": "string"
}

## Storage Rules

- Only encrypted_vote is stored (never plaintext vote).
- integrity_hash is SHA-256 over the decoded encrypted_vote bytes, hex encoded.
- `(election_id, voter_id)` is unique.
- Voter private keys are not stored.
- The election private key is stored encrypted with AES-256-GCM (key derived with PBKDF2 from `KEY_ENCRYPTION_SECRET`, or a random secret generated in `data/secrets/`).
- Roster ID numbers are stored as HMAC-SHA256 with a pepper kept outside the database, plus the last four digits. Each HMAC column is unique.

---

# 8. Security Constraints

- All data is encrypted in transit: the server is started with TLS 1.2+ and plain HTTP only redirects to HTTPS (see `network_security.md`).
- Replay attacks are prevented by the server-clock window check, the timestamp tolerance, and the one-ballot rule.
- Duplicate voting is blocked at application level and by a database constraint.
- The voter roster is re-checked on every voter-authenticated request.
- Server secrets (JWT, key wrapping, ID pepper) are never the defaults in the repository: unset values are generated randomly in `data/secrets/` (mode 0600).

---

# 9. Security Alerts and Security Lab

## Alerts (admin token)

- `GET /api/admin/alerts?limit=100` – `{ "alerts": [...], "unacknowledged", "latest" }`. Each alert: `id`, `kind`, `severity` (`high` | `medium` | `low`), `title`, `detail`, `actor`, `source_ip`, `detected_by`, `count`, `acknowledged`, `created_at`, `last_seen_at`.
- `GET /api/admin/alerts/summary` – `{ "unacknowledged", "latest" }`; polled by the admin screen every 4 seconds.
- `POST /api/admin/alerts/{id}/ack` (404 if unknown) and `POST /api/admin/alerts/ack-all`.

Kinds: `forged_signature`, `replay`, `double_vote`, `ballot_for_other_voter`, `otp_bruteforce`, `identity_mismatch`, `identity_lockout`, `plaintext_http`, `tls_downgrade`, `fake_server`, `db_theft`. The same kind from the same actor and IP within 60 seconds updates one alert and increments `count`.

## Lab probes (any signed-in voter or admin)

- `POST /api/lab/sniff`, `POST /api/lab/tls`, `POST /api/lab/db-theft` – run the network and database attacks against the server's own public ports and a copy of the database. Response: `{ "outcome": "blocked" | "exposed" | "error", "summary", "steps": [{ "title", "status", "lines", "code" }] }`. 401 without a token; 429 while another probe is running.

---

# 10. Changes Since the Week 5 Freeze

| Change | Justification |
|--------|---------------|
| `/api` prefix; `/vote` became `/api/elections/{id}/vote`; `/tally` became `publish-results` | Multiple elections and a web UI served at `/` |
| Voter roster with Aadhaar / college ID verification (replaced the email allowlist) | An email account alone did not prove who the voter is |
| OTP second login step with attempt limit | Password alone was a single factor |
| Per-election access request and admin approval | Elections are scoped to class / department / campus |
| Optional `public_key_pem` at registration | Voter private key no longer has to leave the device |
| Window checked against server clock; 5-minute timestamp tolerance | A client-chosen timestamp alone allowed backdated ballots |
| No decryption at submission | Matches the key lifecycle rule that decryption happens only at tally |
| Signature checked before the duplicate-vote check | A forged ballot is reported as forged, not as a second vote |
| Admin security alerts and `/api/lab/*` probes | The administrator sees attacks as they happen; the threat model can be demonstrated live |
| Generated server secrets | The old default JWT secret, used to wrap election keys, was printed in the repository |

The original unprefixed single-election endpoints survive only as shims under `/api/legacy/` (`election/info`, `vote`, `election/close`, `tally`), which act on the first election.
