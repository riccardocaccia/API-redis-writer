"""
credential_parser.py
Parses OpenStack credential files (.sh RC file or clouds.yaml) and returns
a structured dict ready to be sent to POST /profile/credentials.

Supports:
  - RC file  (export OS_APPLICATION_CREDENTIAL_ID=xxx ...)
  - clouds.yaml (single or multi-cloud)

Usage (standalone):
    python3 credential_parser.py openrc.sh
    python3 credential_parser.py clouds.yaml
    python3 credential_parser.py clouds.yaml --cloud openstack

Or import and use in your script:
    from credential_parser import parse_credential_file
    creds = parse_credential_file("openrc.sh")
"""

import argparse
import os
import re
import sys
from pathlib import Path
from typing import Optional

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False

###################################################
# RC file parser
###################################################

# Maps RC env var names → our internal credential field names
_RC_FIELD_MAP = {
    "OS_AUTH_URL":                      "openstack_auth_url",
    "OS_APPLICATION_CREDENTIAL_ID":     "openstack_app_credential_id",
    "OS_APPLICATION_CREDENTIAL_SECRET": "openstack_app_credential_secret",
    "OS_REGION_NAME":                   "openstack_region_name",
    "OS_INTERFACE":                     "openstack_interface",
    "OS_IDENTITY_API_VERSION":          "openstack_identity_api_version",
}

def _parse_rc_file(path: Path) -> dict:
    """
    Parse a bash RC file like:
        export OS_AUTH_URL=https://keystone...
        export OS_APPLICATION_CREDENTIAL_ID=abc123
    """
    result = {}
    # matches:  export KEY=value  or  KEY=value  (with optional quotes)
    pattern = re.compile(r"""^\s*(?:export\s+)?(\w+)=["\']?([^"\';\n]*)["\']?\s*$""")

    for line in path.read_text().splitlines():
        m = pattern.match(line)
        if not m:
            continue
        env_key, value = m.group(1).strip(), m.group(2).strip()
        field = _RC_FIELD_MAP.get(env_key)
        if field and value:
            result[field] = value

    return result

################################################
#clouds.yaml parser
################################################

def _parse_clouds_yaml(path: Path, cloud_name: Optional[str] = None) -> dict:
    """
    Parse a clouds.yaml file.
    If cloud_name is None and there is only one cloud entry, use that one.
    """
    if not HAS_YAML:
        raise ImportError("PyYAML is required to parse clouds.yaml. Run: pip install pyyaml")

    raw = yaml.safe_load(path.read_text())
    clouds = raw.get("clouds", {})

    if not clouds:
        raise ValueError("No 'clouds' section found in the file.")

    # auto-select if only one cloud
    if cloud_name is None:
        if len(clouds) == 1:
            cloud_name = next(iter(clouds))
        else:
            raise ValueError(
                f"Multiple clouds found: {list(clouds.keys())}. "
                "Specify one with --cloud <name>."
            )

    if cloud_name not in clouds:
        raise ValueError(f"Cloud '{cloud_name}' not found. Available: {list(clouds.keys())}")

    entry = clouds[cloud_name]
    auth  = entry.get("auth", {})

    result = {}

    # auth block
    if auth.get("auth_url"):
        result["openstack_auth_url"] = auth["auth_url"]
    if auth.get("application_credential_id"):
        result["openstack_app_credential_id"] = auth["application_credential_id"]
    if auth.get("application_credential_secret"):
        result["openstack_app_credential_secret"] = auth["application_credential_secret"]

    # top-level fields
    if entry.get("region_name"):
        result["openstack_region_name"] = entry["region_name"]
    if entry.get("interface"):
        result["openstack_interface"] = entry["interface"]
    if entry.get("identity_api_version"):
        result["openstack_identity_api_version"] = str(entry["identity_api_version"])

    return result


####################################################
# Public API
####################################################

def parse_credential_file(path: str, cloud_name: Optional[str] = None) -> dict:
    """
    Auto-detect file type (.sh / .yaml / .yml) and return a dict of credentials.

    Returns dict with any of:
        openstack_auth_url
        openstack_app_credential_id
        openstack_app_credential_secret
        openstack_region_name
        openstack_interface
        openstack_identity_api_version
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Credential file not found: {path}")

    suffix = p.suffix.lower()

    if suffix in (".yaml", ".yml"):
        creds = _parse_clouds_yaml(p, cloud_name)
    elif suffix in (".sh", ".env", ""):
        creds = _parse_rc_file(p)
    else:
        # try RC first, fall back to YAML
        try:
            creds = _parse_rc_file(p)
            if not creds:
                raise ValueError("No RC fields found")
        except Exception:
            creds = _parse_clouds_yaml(p, cloud_name)

    if not creds:
        raise ValueError(f"No recognizable OpenStack credentials found in '{path}'.")

    return creds


def _print_parsed(creds: dict) -> None:
    print("\nParsed credentials:")
    for k, v in creds.items():
        # mask the secret
        display = v[:4] + "***" if "secret" in k and len(v) > 4 else v
        print(f"  {k:<45} {display}")
    print()


########################################################
# CLI
########################################################

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Parse OpenStack RC or clouds.yaml credential file")
    parser.add_argument("file",  help="Path to the RC file (.sh) or clouds.yaml")
    parser.add_argument("--cloud", default=None, help="Cloud name to use (clouds.yaml only)")
    args = parser.parse_args()

    try:
        creds = parse_credential_file(args.file, cloud_name=args.cloud)
        _print_parsed(creds)
    except Exception as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
