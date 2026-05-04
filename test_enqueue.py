"""
Test script — simulates dashboard behavior:

  Step 0 (OPTIONAL): Write profile credentials to Vault via POST /profile/credentials
  Step 1: Authenticate with OIDC token -> get session token
  Step 2: Read deployment_info.json
  Step 3: POST /api/deployments -> job written to Redis

Usage:
    python test_enqueue.py
    python test_enqueue.py --api https://212.189.205.167.cloud.ba.infn.it:8443 --cacert certs/ca.crt
    python test_enqueue.py --setup-credentials
    python test_enqueue.py --setup-credentials --credential-file openrc.sh
    python test_enqueue.py --setup-credentials --credential-file clouds.yaml --cloud openstack
    python test_enqueue.py --no-verify
    python test_enqueue.py --file my_deployment.json
"""

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
import requests

# ── CLI args ──────────────────────────────────────────────────────────────────

parser = argparse.ArgumentParser(description="Laniakea Queue API — test script")
parser.add_argument(
    "--api",
    default="https://212.189.205.167.cloud.ba.infn.it:8443",
    help="API base URL",
)
parser.add_argument(
    "--cacert",
    default="certs/ca.crt",
    help="CA cert to verify the API server TLS cert (default: certs/ca.crt)",
)
parser.add_argument(
    "--no-verify",
    action="store_true",
    help="Disable TLS certificate verification (testing only)",
)
parser.add_argument("--file", default="deployment_info.json", help="Deployment JSON file")
parser.add_argument(
    "--setup-credentials",
    action="store_true",
    help="Write user credentials to Vault before enqueuing",
)
parser.add_argument(
    "--credential-file",
    default=None,
    metavar="PATH",
    help="RC file (.sh) or clouds.yaml to auto-import OpenStack credentials",
)
parser.add_argument(
    "--cloud",
    default=None,
    metavar="NAME",
    help="Cloud name inside clouds.yaml (only needed if the file has multiple clouds)",
)
args = parser.parse_args()

API = args.api.rstrip("/")

# TLS verification
if args.no_verify:
    TLS_VERIFY = False
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
elif Path(args.cacert).exists():
    TLS_VERIFY = args.cacert
else:
    TLS_VERIFY = True
    print(f"WARNING: CA cert not found at '{args.cacert}', using system CA bundle.")

# ── Step 0: get OIDC token ────────────────────────────────────────────────────

print("\n=== Laniakea Queue API — test script ===\n")
print(f"API endpoint : {API}")
print(f"TLS verify   : {TLS_VERIFY}\n")
print("Paste your OIDC token (from ReCaS IAM), then press Enter:\n")
oidc_token = input("OIDC token: ").strip()

if not oidc_token:
    print("ERROR: no token provided.")
    sys.exit(1)

# ── Step 1: authenticate -> session token ────────────────────────────────────

print("\n[1] Authenticating with API...")
try:
    r = requests.post(
        f"{API}/auth/oidc",
        json={"oidc_token": oidc_token},
        verify=TLS_VERIFY,
        timeout=15,
    )
    r.raise_for_status()

except requests.exceptions.SSLError as exc:
    print(f"ERROR: TLS/SSL error — {exc}")
    print("  Use --cacert certs/ca.crt or --no-verify for testing.")
    sys.exit(1)
except requests.exceptions.ConnectionError:
    print(f"ERROR: cannot reach API at {API}")
    print("  Is uvicorn running with --ssl-keyfile/--ssl-certfile/--ssl-ca-certs?")
    print("  Is port 8443 open in the firewall?")
    sys.exit(1)
except requests.exceptions.HTTPError as exc:
    print(f"ERROR: authentication failed ({exc.response.status_code})")
    print(exc.response.text)
    sys.exit(1)

session_token = r.json()["session_token"]
user_info     = r.json()["user_info"]
expires_in    = r.json()["expires_in"]

print(f"✓ Authenticated as '{user_info.get('username') or user_info.get('sub')}'")
print(f"  sub          : {user_info.get('sub')}")
print(f"  Session token: valid for {expires_in // 60} minutes")

AUTH_HEADER = {"Authorization": f"Bearer {session_token}"}

# ── Step 2 (optional): write credentials to Vault ────────────────────────────

if args.setup_credentials:
    print("\n[2] Credential setup — POST /profile/credentials")

    credentials = {}

    # ── auto-import from file ─────────────────────────────────────────────────
    if args.credential_file:
        print(f"\n  Importing from file: {args.credential_file}")
        try:
            from credential_parser import parse_credential_file, _print_parsed
            parsed = parse_credential_file(args.credential_file, cloud_name=args.cloud)
            _print_parsed(parsed)
            credentials.update(parsed)

            # still ask for SSH key and proxy since they are never in RC/clouds.yaml
            print("  The following fields are not in RC/clouds.yaml files.")
            print("  Leave empty to skip.\n")

            def _ask(label: str):
                val = input(f"  {label}: ").strip()
                return val if val else None

            ssh_key   = _ask("openstack_ssh_key (public key content or path to file)")
            proxy     = _ask("openstack_proxy_host (bastion IP, leave empty if public net)")

            def _maybe_read_file(value):
                if value and Path(value).exists():
                    print(f"    → reading key from file: {value}")
                    return Path(value).read_text().strip()
                return value

            ssh_key = _maybe_read_file(ssh_key)
            if ssh_key:
                credentials["openstack_ssh_key"] = ssh_key
            if proxy:
                credentials["openstack_proxy_host"] = proxy

        except FileNotFoundError as exc:
            print(f"  ERROR: {exc}")
            sys.exit(1)
        except Exception as exc:
            print(f"  ERROR parsing credential file: {exc}")
            sys.exit(1)

    # ── manual input fallback ─────────────────────────────────────────────────
    else:
        print("  No --credential-file specified. Enter values manually.")
        print("  Leave a field empty to skip.\n")

        def _ask(label: str):
            val = input(f"  {label}: ").strip()
            return val if val else None

        def _maybe_read_file(value):
            if value and Path(value).exists():
                print(f"    → reading key from file: {value}")
                return Path(value).read_text().strip()
            return value

        print("  --- OpenStack ---")
        credentials["openstack_auth_url"]               = _ask("auth_url (e.g. https://keystone.../v3)")
        credentials["openstack_app_credential_id"]      = _ask("application_credential_id")
        credentials["openstack_app_credential_secret"]  = _ask("application_credential_secret")
        credentials["openstack_region_name"]            = _ask("region_name (e.g. garr-pa1)")
        credentials["openstack_interface"]              = _ask("interface (public / internal)")
        credentials["openstack_ssh_key"]                = _maybe_read_file(_ask("ssh_key (content or path)"))
        credentials["openstack_proxy_host"]             = _ask("proxy_host (bastion IP, empty if public net)")

        print("\n  --- AWS (leave all empty to skip) ---")
        credentials["aws_ssh_key"]    = _maybe_read_file(_ask("aws_ssh_key"))
        credentials["aws_access_key"] = _ask("aws_access_key")
        credentials["aws_secret_key"] = _ask("aws_secret_key")
        credentials["aws_bastion_ip"] = _ask("aws_bastion_ip")

    # remove None / empty values
    credentials = {k: v for k, v in credentials.items() if v}

    if not credentials:
        print("  No credentials entered, skipping Vault write.")
    else:
        try:
            r = requests.post(
                f"{API}/profile/credentials",
                json=credentials,
                headers=AUTH_HEADER,
                verify=TLS_VERIFY,
                timeout=15,
            )
            r.raise_for_status()
            result = r.json()
            print(f"\n  ✓ Credentials saved to Vault!")
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

deployment.setdefault("auth", {})
deployment["auth"]["aai_token"] = oidc_token
deployment["auth"]["sub"]       = user_info.get("sub", "")
deployment["timestamp"]         = datetime.now(timezone.utc).isoformat()
user_email = user_info.get("email")
if not user_email:
    # NOTE:TEST
    user_email = "riccardo.caccia3@studenti.unimi.it"

print(f"✓ Loaded deployment '{deployment.get('deployment_uuid', '?')}'"
      f" (provider: {deployment.get('selected_provider', '?')})")

# ── Step 4: enqueue job ───────────────────────────────────────────────────────

print("\n[4] Enqueueing deployment job...")
try:
    r = requests.post(
        f"{API}/api/deployments",
        json=deployment,
        headers=AUTH_HEADER,
        verify=TLS_VERIFY,
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
print(f"  Status    : {result['status']}")
print(f"  Message   : {result['message']}")
print(f"\nThe worker will pick it up from the '{result['queue_name']}' queue.\n")
