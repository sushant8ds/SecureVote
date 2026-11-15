#!/usr/bin/env python3
"""Walk through the demo story against a running server.

register -> password + OTP login -> admin creates election -> voter requests access ->
admin approves -> encrypted + signed vote -> double vote blocked -> close -> publish results.

Start the server first (demo OTP mode, the default without SMTP settings):
  .venv/bin/python run.py

The script talks HTTPS and verifies the server against the local CA in data/tls/ca_cert.pem.

Then:
  .venv/bin/python scripts/demo_flow.py [--voter you@umsystem.edu] [--password ...]

The voter email must be on STUDENT_EMAIL_ALLOWLIST. Admin credentials come from
ADMIN_USERNAME / ADMIN_PASSWORD in the environment, else you are prompted.
"""

from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.crypto_service import encrypt_vote_plaintext, generate_rsa_keypair, sign_submission  # noqa: E402

PNG_1X1 = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
)


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def check(r: httpx.Response, what: str) -> dict:
    if r.is_error:
        try:
            detail = r.json().get("detail")
        except Exception:
            detail = r.text
        raise SystemExit(f"{what} failed: HTTP {r.status_code}: {detail}")
    return r.json()


def voter_login(client: httpx.Client, voter_id: str, password: str) -> str:
    step1 = check(client.post("/api/login", json={"voter_id": voter_id, "password": password}), "Login (password)")
    otp = step1.get("dev_otp") or input("Enter the OTP sent to the voter (see email / server log): ").strip()
    step2 = check(
        client.post("/api/login", json={"voter_id": voter_id, "password": password, "otp": otp}),
        "Login (OTP)",
    )
    return step2["access_token"]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", default="https://127.0.0.1:8443")
    ap.add_argument(
        "--cacert",
        default=str(ROOT / "data" / "tls" / "ca_cert.pem"),
        help="CA certificate used to verify the server (default: the local CA created by run.py)",
    )
    ap.add_argument("--voter", default="bayd6@umsystem.edu")
    ap.add_argument("--password", default="demopass12")
    args = ap.parse_args()

    verify: object = True
    if args.base.startswith("https://") and Path(args.cacert).exists():
        import ssl

        verify = ssl.create_default_context(cafile=args.cacert)
    with httpx.Client(base_url=args.base, timeout=30.0, verify=verify) as client:
        # The signing key pair is generated here, on the "voter device"; the server only gets the public key.
        priv_pem, pub_pem = generate_rsa_keypair()
        pub_text = pub_pem.decode("utf-8")

        r = client.post(
            "/api/register",
            json={"voter_id": args.voter, "password": args.password, "public_key_pem": pub_text},
        )
        already = r.status_code == 409
        if not already:
            check(r, "Register")
            print(f"1. Registered {args.voter} (bcrypt password hash + voter public key stored).")
        else:
            print(f"1. {args.voter} already registered; signing in with --password.")

        token = voter_login(client, args.voter, args.password)
        vh = {"Authorization": f"Bearer {token}"}
        print("2. Signed in with password + one-time code.")
        if already:
            check(
                client.post(
                    "/api/voter/restore-signing-key",
                    headers=vh,
                    json={"password": args.password, "public_key_pem": pub_text},
                ),
                "Rotate signing key",
            )
            print("   Rotated the voter signing key to one held by this script.")

        admin_user = os.environ.get("ADMIN_USERNAME") or input("Admin username [admin]: ").strip() or "admin"
        admin_pw = os.environ.get("ADMIN_PASSWORD") or getpass.getpass("Admin password: ")
        adm = check(
            client.post("/api/admin/login", json={"username": admin_user, "password": admin_pw}), "Admin login"
        )["access_token"]
        ah = {"Authorization": f"Bearer {adm}"}

        now = datetime.now(timezone.utc)
        created = check(
            client.post(
                "/api/admin/elections",
                headers=ah,
                data={
                    "title": f"Demo election {iso(now)}",
                    "category": "class",
                    "starts_at": iso(now - timedelta(hours=1)),
                    "ends_at": iso(now + timedelta(days=1)),
                    "contestant_names": json.dumps(["Alice", "Bob"]),
                },
                files=[
                    ("photos", ("alice.png", PNG_1X1, "image/png")),
                    ("photos", ("bob.png", PNG_1X1, "image/png")),
                ],
            ),
            "Create election",
        )
        eid = created["election_id"]
        print(f"3. Admin created election #{eid} with its own RSA-2048 key pair.")

        check(client.post(f"/api/elections/{eid}/register", headers=vh), "Request access")
        regs = check(client.get("/api/admin/registrations?status_filter=pending", headers=ah), "List registrations")
        reg = next(x for x in regs["registrations"] if x["election_id"] == eid and x["voter_id"] == args.voter)
        check(client.post(f"/api/admin/registrations/{reg['id']}/approve", headers=ah), "Approve")
        print("4. Voter requested access; admin approved.")

        detail = check(client.get(f"/api/elections/{eid}/detail", headers=vh), "Election detail")
        choice = detail["contestants"][0]

        def ballot(contestant_id: int) -> dict:
            ts = iso(datetime.now(timezone.utc))
            plain = json.dumps({"contestant_id": contestant_id}).encode("utf-8")
            enc = encrypt_vote_plaintext(plain, detail["public_key_pem"].encode("utf-8"))
            sig = sign_submission(enc, ts, priv_pem)
            return {"voter_id": args.voter, "encrypted_vote": enc, "signature": sig, "timestamp": ts}

        good = ballot(choice["id"])
        forged = dict(good, signature=base64.b64encode(b"\x00" * 256).decode("ascii"))
        r = client.post(f"/api/elections/{eid}/vote", headers=vh, json=forged)
        print(f"5. Forged signature rejected: HTTP {r.status_code} ({r.json().get('detail')}).")

        check(client.post(f"/api/elections/{eid}/vote", headers=vh, json=good), "Vote")
        print(f"6. Vote for {choice['name']!r} submitted (RSA-OAEP ciphertext + RSA-PSS signature).")

        r = client.post(f"/api/elections/{eid}/vote", headers=vh, json=ballot(detail["contestants"][1]["id"]))
        print(f"7. Second vote rejected: HTTP {r.status_code} ({r.json().get('detail')}).")

        check(client.post(f"/api/admin/elections/{eid}/close", headers=ah), "Close election")
        tally = check(client.post(f"/api/admin/elections/{eid}/publish-results", headers=ah), "Publish results")
        print("8. Election closed; ballots verified, decrypted and tallied:")
        print(json.dumps(tally, indent=2))

        results = check(client.get(f"/api/elections/{eid}/results"), "Public results")
        print("9. Public results:", json.dumps(results["by_name"]))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except httpx.HTTPError as e:
        print("HTTP error:", e, file=sys.stderr)
        raise SystemExit(1)
