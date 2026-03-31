"""
Test script — full workflow:
  1. Paste your OIDC token when prompted
  2. Reads deployment_info.json from the current directory
  3. POST /auth/oidc  → get session token
  4. POST /api/deployments → job written to Redis queue

Usage:
    python test_enqueue.py
    python test_enqueue.py --api http://192.168.1.10:8000
    python test_enqueue.py --file my_deployment.json
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

# ── CLI args ──────────────────────────────────────────────────────────────────

parser = argparse.ArgumentParser(description="Laniakea Queue API — test enqueue")
parser.add_argument("--api",  default="http://localhost:8000", help="API base URL")
parser.add_argument("--file", default="deployment_info.json",  help="Deployment JSON file")
args = parser.parse_args()

API = args.api.rstrip("/")

# ── Step 1: get OIDC token from user ─────────────────────────────────────────

print("\n=== Laniakea Queue API — test enqueue ===\n")
print("Paste your OIDC token (from RecaCAS or wherever you normally get it),")
print("then press Enter:\n")
oidc_token = input("OIDC token: ").strip()

if not oidc_token:
    print("ERROR: no token provided.")
    sys.exit(1)

# ── Step 2: load deployment config ───────────────────────────────────────────

deployment_file = Path(args.file)
if not deployment_file.exists():
    print(f"ERROR: file not found: {deployment_file}")
    sys.exit(1)

with deployment_file.open() as f:
    deployment = json.load(f)

# Inject the OIDC token into auth (workers need it to get the Keystone token)
deployment.setdefault("auth", {})
deployment["auth"]["aai_token"] = oidc_token

# Always stamp with current time
deployment["timestamp"] = datetime.now(timezone.utc).isoformat()

print(f"\n✓ Loaded deployment '{deployment.get('deployment_uuid', '?')}'"
      f" (provider: {deployment.get('selected_provider', '?')})")

# ── Step 3: authenticate → session token ─────────────────────────────────────

print("\n[1/2] Authenticating with API...")
try:
    r = requests.post(
        f"{API}/auth/oidc",
        json={"oidc_token": oidc_token},
        timeout=15,
    )
    r.raise_for_status()
except requests.exceptions.ConnectionError:
    print(f"ERROR: cannot reach API at {API}. Is it running?")
    sys.exit(1)
except requests.exceptions.HTTPError as exc:
    print(f"ERROR: authentication failed ({exc.response.status_code})")
    print(exc.response.text)
    sys.exit(1)

session_token = r.json()["session_token"]
user_info     = r.json()["user_info"]
expires_in    = r.json()["expires_in"]

print(f"✓ Authenticated as '{user_info.get('username') or user_info.get('sub')}'")
print(f"  Session token valid for {expires_in // 60} minutes")

# ── Step 4: enqueue job ───────────────────────────────────────────────────────

print("\n[2/2] Enqueueing deployment job...")
try:
    r = requests.post(
        f"{API}/api/deployments",
        json=deployment,
        headers={"Authorization": f"Bearer {session_token}"},
        timeout=15,
    )
    r.raise_for_status()
except requests.exceptions.HTTPError as exc:
    print(f"ERROR: enqueue failed ({exc.response.status_code})")
    print(exc.response.text)
    sys.exit(1)

result = r.json()

print(f"✓ Job enqueued!")
print(f"  Job ID    : {result['job_id']}")
print(f"  Queue     : {result['queue_name']}")
print(f"  Deployment: {result['deployment_uuid']}")
print(f"\nThe worker will pick it up from the '{result['queue_name']}' queue.\n")
