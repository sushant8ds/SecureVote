# Interface Specification

## Overview

This document defines the interface formats, required fields, validation rules, and error codes for the Secure Digital Voting System.

The goal of this specification is to ensure clarity, consistency, and misuse prevention in how system components communicate.

**Version 2.** The Week 5 freeze described a single-election API (`/register`, `/login`, `/vote`, `/tally`). The implementation moved to multiple elections, an email allowlist, OTP login, and per-election access approval; the changes are listed in section 9. All endpoints are under the `/api` prefix and exchange JSON unless noted.

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
  "public_key_pem": "string (optional)"
}

## Fields

- voter_id: college email ending in `@umsystem.edu`, present in `STUDENT_EMAIL_ALLOWLIST`; stored lowercase
- password: minimum 8 characters
- public_key_pem: voter RSA public key (SPKI PEM, at least 2048 bits) generated on the voter's device. If omitted, the server generates the key pair and returns the private key once.

## Response (201)

{
  "voter_id": "string",
  "voter_private_key_pem": "string or null",
  "message": "string"
}

`voter_private_key_pem` is null when the client supplied `public_key_pem`.

## Processing Rules

- Password must be hashed using bcrypt before storage.
- Duplicate voter_id must be rejected.
- Plaintext passwords and voter private keys must never be stored.

## Error Codes

- 400 – Not a `@umsystem.edu` address, or invalid public key
- 403 – Email not on the allowlist
- 409 – Voter already exists
- 422 – Malformed request body

`POST /api/register/precheck` with `{ "voter_id": "string" }` runs only the email checks (400 / 403) without creating an account.

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

- 400 – Not a `@umsystem.edu` address
- 401 – Wrong password, wrong / expired / missing OTP, or too many wrong OTP attempts
- 403 – Email not on the allowlist
- 404 – Voter not found

## Related Voter Endpoints

- `GET /api/voter/session` – returns `{ "voter_id" }` for a valid voter token.
- `POST /api/voter/restore-signing-key` – body `{ "password", "public_key_pem" (optional) }`. Replaces the voter's public key after a password check. Earlier ballots stay verifiable because each stored ballot keeps the public key used when it was cast.

---

# 4. Election Access Interface

- `GET /api/elections` – list of elections. With a voter token, each entry includes `my_registration_status` (`pending`, `approved`, `rejected`, or null) and `my_voted`.
- `GET /api/elections/{id}/detail` – election metadata and contestants (`id`, `name`, `image_url`). `public_key_pem` is included only for an authenticated voter.
- `POST /api/elections/{id}/register` – voter requests access; creates a `pending` registration. Errors: 403 election closed, 404 election not found, 409 already requested.

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

- The election must exist and must not be closed.
- The server clock must be within the election window.
- The timestamp must be within the election window and within 5 minutes of the server clock.
- The voter must have an approved registration for this election.
- The voter must not have already voted in this election.
- Signature must be verified before accepting the vote.
- Encrypted vote must be valid Base64 of exactly 256 bytes.
- The server does not decrypt the ballot at submission.

## Error Codes

- 400 – Invalid vote format
- 401 – Unauthorized (not logged in, or voter_id does not match the session)
- 403 – Election closed, voter not approved, or voter has already voted
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
- The election private key is stored encrypted with AES-256-GCM (key derived from `KEY_ENCRYPTION_SECRET`).

---

# 8. Security Constraints

- All data is encrypted in transit: the server is started with TLS 1.2+ and plain HTTP only redirects to HTTPS (see `network_security.md`).
- Replay attacks are prevented by the server-clock window check, the timestamp tolerance, and the one-ballot rule.
- Duplicate voting is blocked at application level and by a database constraint.
- The email allowlist is re-checked on every voter-authenticated request.

---

# 9. Changes Since the Week 5 Freeze

| Change | Justification |
|--------|---------------|
| `/api` prefix; `/vote` became `/api/elections/{id}/vote`; `/tally` became `publish-results` | Multiple elections and a web UI served at `/` |
| Email allowlist and `@umsystem.edu` check | Restrict registration to authorized students |
| OTP second login step with attempt limit | Password alone was a single factor |
| Per-election access request and admin approval | Elections are scoped to class / department / campus |
| Optional `public_key_pem` at registration | Voter private key no longer has to leave the device |
| Window checked against server clock; 5-minute timestamp tolerance | A client-chosen timestamp alone allowed backdated ballots |
| No decryption at submission | Matches the key lifecycle rule that decryption happens only at tally |

The original unprefixed single-election endpoints survive only as shims under `/api/legacy/` (`election/info`, `vote`, `election/close`, `tally`), which act on the first election.
