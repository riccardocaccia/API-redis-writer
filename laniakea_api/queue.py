"""
Redis connection and RQ queue setup
"""

import hvac
from fastapi import HTTPException, status
from redis import Redis
from rq import Queue
from config import (REDIS_HOST, REDIS_PORT, REDIS_PASSWORD,
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
    Returns the vault path on success; raises HTTP 502 on failure.
    """
    vault_path = f"{user_sub}/credentials"
    try:
        vault_client.secrets.kv.v2.create_or_update_secret(
            path=vault_path,
            secret=creds,
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

