"""
Test script — simulates dashboard behavior:

  Step 0 (OPTIONAL): Write profile credentials to Vault via POST /profile/credentials
  Step 1: Authenticate with OIDC token -> get session token
  Step 2: Read deployment_info.json
  Step 3: POST /api/deployments -> job written to Redis

Usage:
    python test_enqueue.py                          # enqueue only
    python test_enqueue.py --setup-credentials      # write credentials to Vault + enqueue
    python test_enqueue.py --api http://IP:8000
    python test_enqueue.py --file my_deployment.json
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

# ── CLI args ──────────────────────────────────────────────────────────────────

# XXX: REMOVE THIS OPTION -> the dashboard should manage this?
parser = argparse.ArgumentParser(description="Laniakea Queue API — test script")
parser.add_argument("--api",               default="http://localhost:8000", help="API base URL")
parser.add_argument("--file",              default="deployment_info.json",  help="Deployment JSON file")
parser.add_argument("--setup-credentials", action="store_true",
                    help="Write user credentials to Vault before enqueuing (first-time setup)")
args = parser.parse_args()

API = args.api.rstrip("/")

# ── Step 0: get OIDC token ────────────────────────────────────────────────────

# insert oidc token on cli
print("\n=== Laniakea Queue API — test script ===\n")
print("Paste your OIDC token (from ReCaS IAM),")
print("then press Enter:\n")
oidc_token = input("OIDC token: ").strip()

if not oidc_token:
    print("ERROR: no token provided.")
    sys.exit(1)

# ── Step 1: authenticate -> session token ────────────────────────────────────

print("\n[1] Authenticating with API...")
try:
    r = requests.post(f"{API}/auth/oidc", json={"oidc_token": oidc_token}, timeout=15,)
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

# INSERT HERE some debug info 
print(f"✓ Authenticated as '{user_info.get('username') or user_info.get('sub')}'")
print(f"  sub          : {user_info.get('sub')}")
print(f"  Session token: valid for {expires_in // 60} minutes")

AUTH_HEADER = {"Authorization": f"Bearer {session_token}"}

# ── Step 2 (optional): write credentilas on Vault ──────────────────────────

if args.setup_credentials:
    print("\n[2] Credential setup — write to Vault via POST /profile/credentials")
    print("    Leave a field empty to skip it.\n")

    def _ask(label: str) -> str | None:
        val = input(f"  {label}: ").strip()
        return val if val else None

    print("  --- OpenStack ---")
    os_ssh_key      = _ask("openstack_ssh_key (private key content or path)")
    os_app_cred_id  = _ask("openstack_app_credential_id     (leave empty if using AAI token)")
    os_app_cred_sec = _ask("openstack_app_credential_secret (leave empty if using AAI token)")
    os_proxy        = _ask("openstack_proxy_host             (bastion IP, leave empty if public net)")

    print("\n  --- AWS ---")
    aws_ssh_key    = _ask("aws_ssh_key")
    aws_access_key = _ask("aws_access_key")
    aws_secret_key = _ask("aws_secret_key")
    aws_bastion    = _ask("aws_bastion_ip (leave empty if not needed)")

    # Leggi la chiave SSH da file se sembra un path
    def _maybe_read_file(value: str | None) -> str | None:
        if value and Path(value).exists():
            print(f"    → reading key from file: {value}")
            return Path(value).read_text().strip()
        return value

    os_ssh_key  = _maybe_read_file(os_ssh_key)
    aws_ssh_key = _maybe_read_file(aws_ssh_key)

    credentials = {
        "openstack_ssh_key":               os_ssh_key,
        "openstack_app_credential_id":     os_app_cred_id,
        "openstack_app_credential_secret": os_app_cred_sec,
        "openstack_proxy_host":            os_proxy,
        "aws_ssh_key":                     aws_ssh_key,
        "aws_access_key":                  aws_access_key,
        "aws_secret_key":                  aws_secret_key,
        "aws_bastion_ip":                  aws_bastion,
    }
    
    credentials = {k: v for k, v in credentials.items() if v is not None}

    if not credentials:
        print("  No credentials entered, skipping Vault write.")
    else:
        try:
            r = requests.post(
                f"{API}/profile/credentials",
                json=credentials,
                headers=AUTH_HEADER,
                timeout=15,
            )
            r.raise_for_status()
            result = r.json()
            print(f"\n  ✓ Credentials saved!")
            print(f"    Vault path : {result['vault_path']}")
            print(f"    User       : {result['user']}")
        except requests.exceptions.HTTPError as exc:
            print(f"  ERROR: credential save failed ({exc.response.status_code})")
            print(exc.response.text)
            sys.exit(1)
else:
    print("\n[2] Skipping credential setup (use --setup-credentials for first-time setup)")

# ── Step 3: load deployment config ───────────────────────────────────────────

print("\n[3] Loading deployment config...")
deployment_file = Path(args.file)
if not deployment_file.exists():
    print(f"ERROR: file not found: {deployment_file}")
    sys.exit(1)

with deployment_file.open() as f:
    deployment = json.load(f)

# Inject OIDC token into auth
deployment.setdefault("auth", {})
deployment["auth"]["aai_token"] = oidc_token
deployment["auth"]["sub"]       = user_info.get("sub", "")

# Timestamp 
deployment["timestamp"] = datetime.now(timezone.utc).isoformat()

print(f"✓ Loaded deployment '{deployment.get('deployment_uuid', '?')}'"
      f" (provider: {deployment.get('selected_provider', '?')})")

# ── Step 4: enqueue job ───────────────────────────────────────────────────────

print("\n[4] Enqueueing deployment job...")
try:
    r = requests.post(
        f"{API}/api/deployments",
        json=deployment,
        headers=AUTH_HEADER,
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
print(f"  Message   : {result['message']}")
print(f"\nThe worker will pick it up from the '{result['queue_name']}' queue.\n")
