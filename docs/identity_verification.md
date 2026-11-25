# Identity verification against the college roster

## Goal

An email account on its own does not prove who is voting. Before an account is created, the student must give the details printed on their **Aadhaar card** or **college ID card**, and the server compares them with the college's record for that email.

## The roster

`config/voter_roster.csv` (setting `VOTER_ROSTER_FILE`) is the college's list of eligible voters:

```
email,full_name,date_of_birth,aadhaar,college_id
```

It is imported into the `voter_roster` table at start-up whenever the file changes. Administrators can also add and remove entries on the *Voter roster* tab. Only roster emails can register or sign in; the roster replaces the old `STUDENT_EMAIL_ALLOWLIST`. The demo file contains made-up names and checksum-valid test Aadhaar numbers.

## How numbers are stored

ID numbers are never stored. For each card the roster keeps:

- `HMAC-SHA256(pepper, "aadhaar:<12 digits>")` (or `"college_id:<ID>"`), and
- the last four digits, for display as `•••• 1234`.

The pepper (`IDENTITY_PEPPER`, or a random value in `data/secrets/identity_pepper`) is not in the database. A stolen database therefore cannot be used to test guessed Aadhaar numbers offline. Each HMAC column is `UNIQUE`, so one card cannot belong to two roster entries, and so cannot be used for two accounts.

## The check

1. **Format.** Aadhaar numbers must have 12 digits, must not start with 0 or 1, and must pass the **Verhoeff** check digit that UIDAI uses. A typo is reported as a format error (HTTP 400), checked first in the browser, and does not count as a failed attempt.
2. **Compare.** The HMAC of the typed number is compared with the stored one using `hmac.compare_digest`. The name is compared ignoring case, spacing, dots and accents, and the date of birth exactly.
3. **Answer.** On a mismatch the voter only sees "These details don't match the college record", with the attempts left. The response does not say which field was wrong, so it can't be used to confirm a guessed date of birth one field at a time. The administrator's alert does say which field.
4. **Lockout.** Three failures for one email within 15 minutes pause identity checks for that email (HTTP 429) and raise a high-severity *Repeated identity check failures* alert.

On success the `voters` row records `identity_method` and `identity_verified_at`. Requesting access to an election and voting both require a verified identity. Accounts created before this feature verify once through `POST /api/voter/verify-identity`; the Elections page shows that form.

## Limits

This checks knowledge of the card's details against the college record. It is not a check of the physical card or of the person's face, and it is not UIDAI's online Aadhaar authentication. Someone who has a student's card details and email password could still register as them. Higher assurance would need Aadhaar OTP/e-KYC through a licensed provider, or an in-person check.
