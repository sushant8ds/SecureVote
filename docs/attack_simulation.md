# Simulated Attack: Signature Replay and Forgery

## Threat

An attacker tries to submit a vote using another voter’s identity by reusing or forging a digital signature, or by replaying a previously captured payload.

## Mechanisms Tested

1. **Forged signature** — Random or incorrectly generated RSA-PSS signature over the submission digest is rejected during `POST /api/elections/{id}/vote` (HTTP 409, invalid signature).
2. **Binding to ciphertext and timestamp** — RSA-PSS + SHA-256 signs the UTF-8 string `encrypted_vote ‖ '|' ‖ timestamp` as a single message. Changing the timestamp after signing invalidates the signature (see unit test `test_reject_signature_on_tampered_timestamp`).
3. **Replay or backdating of a vote** — The election window is enforced against the server clock, and the signed timestamp must be inside the window and within 5 minutes of the server clock (HTTP 422 otherwise, see `test_backdated_timestamp_rejected`). A captured ballot therefore cannot be resubmitted later, and a voter cannot backdate a ballot after the window ends. A replay inside the 5-minute tolerance is stopped by the one-ballot rule below.
4. **OTP guessing** — A login code is invalidated after 5 wrong attempts (`test_otp_burned_after_too_many_wrong_guesses`).

## Mitigation Summary

| Control | Purpose |
|--------|---------|
| RSA-PSS + SHA-256 | Ensures signatures are unforgeable without the voter’s private key |
| Server-clock window check + 5-minute timestamp tolerance | Stops backdated and late-replayed ballots |
| `UNIQUE(election_id, voter_id)` on `election_votes` | Prevents a second accepted ballot from the same voter in an election |
| JWT session for the vote endpoint | Ensures the `voter_id` in the body matches the authenticated subject |
| OTP attempt limit | Stops brute-forcing the 6-digit login code |

This aligns with the proposal success criterion: *at least one simulated attack is documented and mitigated*.

## Security lab: all seven attacks, live

The web app has a **Security lab** page (`/#lab`, any signed-in user) that runs each attack against the running server and shows every step and the server's answer. Attacks 1–4 are real API calls from the browser, acting as the signed-in voter; attacks 5–7 need raw sockets or the database file, so the server runs them against its own public ports (`src/attack_lab.py`). A rejected ballot never uses up the voter's real vote.

| # | Attack | What the lab does | Stopped by | Server answer |
|---|--------|-------------------|------------|---------------|
| 1 | Forged signature | Real ballot, signed with a fresh attacker key | RSA-PSS verify with the registered voter key | 409 |
| 2 | Replayed / backdated ballot | Validly signed ballot dated two hours ago | Server clock + 5-minute timestamp limit | 422 |
| 3 | Second vote | Fresh valid ballot after the voter has voted | One ballot per voter per election (DB unique key) | 403 |
| 4 | Login-code guessing | Correct (stolen) password, then 5 random codes, then the real code | Code burned after 5 misses | 401 |
| 5 | Wi-Fi sniffing | Records every byte of an HTTPS login and searches it for the password; repeats on plain HTTP port 8000 | TLS 1.3 (ECDHE + AES-GCM); port 8000 never processes requests | 308 on HTTP |
| 6 | Old protocol / fake server | Client limited to TLS 1.0/1.1; impostor server with a self-signed certificate | TLS 1.2 minimum; certificate must chain to the SecureVote CA | handshake refused / verify failed |
| 7 | Stolen database | Copies `voting.db`, guesses the key-wrap secret (including every value printed in the repo), decrypts, runs a bcrypt dictionary attack, looks for ID numbers | AES-256-GCM keys with a secret outside the DB, bcrypt cost 12, HMAC'd ID numbers | — |

The probes report honestly: if a defence fails (for example an election key still wrapped with the old public default secret), the card says **Not stopped**. `tests/test_identity_and_alerts.py::test_db_theft_probe_is_honest` checks this.

## Admin alerts

Alerts are written by the code that stops the attack, so a real attack raises the same alert as a lab run:

| Alert | Raised by |
|-------|-----------|
| Forged ballot signature, Replayed or backdated ballot, Second vote attempt, Ballot in another voter's name | Ballot intake (`POST /api/elections/{id}/vote`) |
| Login code guessing | Sign-in, when a code is burned after 5 misses |
| Identity check failed / Repeated identity check failures | Registration and identity verification |
| Credentials sent over plain HTTP | The port-8000 listener, for API requests carrying a body or token |
| Old TLS version refused, Impostor server certificate rejected, Stolen database file examined | Security lab probes (labelled as such) |

Repeats by the same actor within 60 seconds are merged into one alert with a counter. The admin screen polls every 4 seconds and shows a pop-up, a banner and a red count on the *Security alerts* tab. Passive sniffing on its own can't be detected by any server; that is why TLS matters.
