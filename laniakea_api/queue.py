"""
Redis connection and RQ queue setup
"""

import hvac
from fastapi import HTTPException, status
from redis import Redis
from rq import Queue
from laniakea_api.config import (REDIS_HOST, REDIS_PORT, REDIS_PASSWORD,
                    VAULT_ADDR, VAULT_WRITER_TOKEN, VAULT_TLS_VERIFY, VAULT_MOUNT,)

# Redis
redis_conn = Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    password=REDIS_PASSWORD,
    decode_responses=False,  # RQ uses binary pickle
)

# NOTE: need a final decision over the queues names
queues: dict = {
    "openstack": Queue("openstack", connection=redis_conn),
    "aws":       Queue("aws",       connection=redis_conn),
}

# NOTE: is this necessary? check 
PROVIDER_TO_QUEUE: dict = {
    "openstack": "openstack",
    "Openstack": "openstack",
    "OpenStack": "openstack",
    "aws":       "aws",
    "AWS":       "aws",
    "Aws":       "aws",
}

def get_queue(provider: str) -> tuple:
    """
    Returns (queue_name, Queue) for the given provider string.
    Raises HTTP 400 if the provider is not supported.
    """
    queue_name = PROVIDER_TO_QUEUE.get(provider)
    if not queue_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported provider '{provider}'. Supported: {list(PROVIDER_TO_QUEUE.keys())}",
        )
    return queue_name, queues[queue_name]

def check_redis() -> str:
    """
    Returns 'connected' or an error string. 
    Used by /health.
    """
    try:
        redis_conn.ping()
        return "connected"
    except Exception as exc:
        return f"error: {exc}"

# Vault
# see config.py
vault_client = hvac.Client(
    url=VAULT_ADDR,
    token=VAULT_WRITER_TOKEN,
    verify=VAULT_TLS_VERIFY,
)


def vault_write_credentials(user_sub: str, creds: dict) -> str:
    """
    Write user credentials to Vault under secret/data/<sub>/credentials.

    MERGE semantics: the existing secret is read first and only the fields
    provided in `creds` are overwritten. Fields already in Vault but not in
    this request are preserved (e.g. ssh_private_key must survive a
    GARR-only app-credentials update).

    Returns the vault path on success; raises HTTP 502 on failure.
    """
    vault_path = f"{user_sub}/credentials"
    try:
        # Read existing secret (if any) to merge with incoming fields
        try:
            existing = vault_client.secrets.kv.v2.read_secret_version(
                path=vault_path,
                mount_point=VAULT_MOUNT,
                raise_on_deleted_version=True,
            )["data"]["data"]
        except Exception:
            existing = {}

        merged = {**existing, **creds}

        vault_client.secrets.kv.v2.create_or_update_secret(
            path=vault_path,
            secret=merged,
            mount_point=VAULT_MOUNT,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Vault write failed: {exc}",
        )
    return vault_path

def check_vault() -> str:
    """
    Returns 'authenticated' or an error string.
    Used by /health.
    """
    try:
        return "authenticated" if vault_client.is_authenticated() else "unauthenticated"
    except Exception as exc:
        return f"error: {exc}"

#per-cloud credentials: secret/<sub>/service_creds/<name>

def _sc_path(user_sub: str, name: str = "") -> str:
    base = f"{user_sub}/service_creds"
    return f"{base}/{name}" if name else base

def _infer_service_type(data: dict) -> str:
    """
    Derive the credential type from the field names themselves —
    nothing but secrets is stored in Vault.
    """
    if any(k.startswith("aws_") for k in data):
        return "aws"
    if any(k.startswith("openstack_") for k in data):
        return "openstack"
    return "unknown"


def vault_list_service_creds(user_sub: str) -> list:
    client = vault_client()
    try:
        resp = client.secrets.kv.v2.list_secrets(path=_sc_path(user_sub), mount_point=VAULT_MOUNT)
        names = [k.rstrip("/") for k in resp["data"]["keys"]]
    except Exception:
        return []
    out = []
    for n in names:
        data = vault_read_service_creds(user_sub, n)
        out.append({"name": n, "service_type": _infer_service_type(data)})
    return out

def vault_read_service_creds(user_sub: str, name: str) -> dict:
    client = vault_client()
    try:
        resp = client.secrets.kv.v2.read_secret_version(path=_sc_path(user_sub, name), mount_point=VAULT_MOUNT)
        return resp["data"]["data"] or {}
    except Exception:
        return {}

def vault_write_service_creds(user_sub: str, name: str, data: dict) -> None:
    client = vault_client()
    client.secrets.kv.v2.create_or_update_secret(
        path=_sc_path(user_sub, name), secret=data, mount_point=VAULT_MOUNT)

def vault_delete_service_creds(user_sub: str, name: str) -> None:
    client = vault_client()
    client.secrets.kv.v2.delete_metadata_and_all_versions(
        path=_sc_path(user_sub, name), mount_point=VAULT_MOUNT)


def vault_read_global(user_sub: str) -> dict:
    client = vault_client()
    try:
        resp = client.secrets.kv.v2.read_secret_version(
            path=f"{user_sub}/credentials", mount_point=VAULT_MOUNT)
        return resp["data"]["data"] or {}
    except Exception:
        return {}

def vault_strip_global_keys(user_sub: str, keys: list) -> None:
    """Remove specific fields from the global path, keep the rest."""
    data = vault_read_global(user_sub)
    for k in keys:
        data.pop(k, None)
    client = vault_client()
    client.secrets.kv.v2.create_or_update_secret(
        path=f"{user_sub}/credentials", secret=data, mount_point=VAULT_MOUNT)
