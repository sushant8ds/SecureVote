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
