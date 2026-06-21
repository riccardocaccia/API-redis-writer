"""
Installation script executed ONCE on the API VM.
It does three things:
  1. Adds ~/.local/bin to PATH in ~/.bashrc
  2. Creates the working directory and the .env template
  3. Creates the log directory

Usage:
    laniakea-api-install
    laniakea-api-install --workdir /opt/laniakea-api
"""

import argparse
import os
import sys


def _add_to_path():
    """
    This function opens your Bash shell configuration file (~/.bashrc).
    It checks whether the ~/.local/bin folder is already present. If it isn't, 
    it adds the following line to the bottom of the file: export PATH=$HOME/.local/bin:$PATH
    """
    bashrc = os.path.expanduser("~/.bashrc")
    line = 'export PATH=$HOME/.local/bin:$PATH'

    if os.path.exists(bashrc):
        with open(bashrc, "r") as f:
            content = f.read()
        if ".local/bin" in content:
            print("[path] ~/.local/bin already in PATH — skip")
            return

    with open(bashrc, "a") as f:
        f.write(f"\n# added by laniakea-api-install\n{line}\n")
    print("[path] added ~/.local/bin to PATH in ~/.bashrc")
    print("[path] run: source ~/.bashrc")


def _create_workdir(workdir: str):
    """
    Create the main folder where the application will run (by default, ~/laniakea-api) 
    and create a certs subfolder within it to host future (optional) SSL certificates.
    
    The most important part is generating the .env file. If the file doesn't already exist, it will 
    be created using the default values managed in the CONFIG.py
    """
    os.makedirs(workdir, exist_ok=True)
    os.makedirs(os.path.join(workdir, "certs"), exist_ok=True)

    env_path = os.path.join(workdir, ".env")
    if os.path.exists(env_path):
        print(f"[workdir] .env already exists... skipping the creation")
    else:
        # NOTE: MOD. HERE THE TEMPLATE
        template = """\
# ── Auth ──────────────────────────────────────────────────────────────────────
# Generate with: python3 -c "import secrets; print(secrets.token_hex(32))"
SECRET_KEY=
SESSION_TTL_MINUTES=60
OIDC_DISCOVERY_URL=https://example.it/.well-known/openid-configuration

# ── Agent pool password (must match the agent .env) ───────────────────────────
AGENT_MASTER_PASSWORD=

# ── Redis ─────────────────────────────────────────────────────────────────────
REDIS_HOST=127.0.0.1
REDIS_PORT=
REDIS_PASSWORD=

# ── PostgreSQL ────────────────────────────────────────────────────────────────
PG_HOST=
PG_PORT=5432
PG_DATABASE=
PG_USER=
PG_PASSWORD=

# ── Vault ─────────────────────────────────────────────────────────────────────
VAULT_ADDR=
VAULT_WRITER_TOKEN=
VAULT_TLS_VERIFY=false

# ── TLS (only with laniakea-api --ssl) ────────────────────────────────────────
SSL_KEYFILE=certs/api.key
SSL_CERTFILE=certs/api.crt

# ── Deployment logs ───────────────────────────────────────────────────────────
DEPLOYMENT_LOG_DIR=/var/log/laniakea-agent
"""
        with open(env_path, "w") as f:
            f.write(template)
        os.chmod(env_path, 0o600)
        print(f"[workdir] .env template created in {env_path}")

    print(f"[workdir] working directory: {workdir}")


def _create_log_dir():
    """
    The API and agents need to write deployment logs to /var/log/laniakea-agent.
    The script create this system folder if needed.
    """
    log_dir = "/var/log/laniakea-agent"
    if os.path.exists(log_dir):
        print(f"[logs] {log_dir} already exists... skipping the creation")
        return
    try:
        os.makedirs(log_dir, exist_ok=True)
        os.chown(log_dir, os.getuid(), os.getgid())
        print(f"[logs] log directory created: {log_dir}")
    except PermissionError:
        print(f"[logs] insufficient permissions! Please run:")
        print(f"       sudo mkdir -p {log_dir} && sudo chown $USER:$USER {log_dir}")


def main():
    """
    Once the installation is completed this function print
    a guide for the user.
    """
    parser = argparse.ArgumentParser(
        prog="laniakea-api-install",
        description="Initial setup of the VM for laniakea-api-server.",
    )
    parser.add_argument(
        "--workdir", "-w",
        default=os.path.expanduser("~/laniakea-api"),
        help="API working directory (default: ~/laniakea-api)",
    )
    args = parser.parse_args()

    print("\n=== laniakea-api-install ===\n")

    _add_to_path()
    _create_log_dir()
    _create_workdir(args.workdir)

    # FIXME: implement a guide for certifacete (non-self-signed)
    print(f"""
=== Setup completed ===

  1. Reload your PATH:
       source ~/.bashrc

  2. Fill in the .env file:
       nano {args.workdir}/.env

  3. (optional) Generate self-signed certificate for testing:
       cd {args.workdir}
       openssl req -x509 -newkey rsa:2048 -nodes \\
         -keyout certs/api.key -out certs/api.crt \\
         -days 365 -subj "/CN=localhost"

  4. Start the API:
       cd {args.workdir}
       laniakea-api --port 8000              # HTTP 
       laniakea-api --port 8443 --ssl        # HTTPS
""")


if __name__ == "__main__":
    main()
