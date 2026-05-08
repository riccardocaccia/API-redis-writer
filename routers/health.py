"""
health check endpoint.
### no auth required,used by load balancers and monitoring.

GET /health
"""

from datetime import datetime
from fastapi import APIRouter
from database import check_connection
from queue import check_redis, check_vault

router = APIRouter()

@router.get("/health")
async def health():
    """Verify Redis, Vault and PostgreSQL connectivity."""
    redis_status = check_redis()
    vault_status = check_vault()
    pg_status    = check_connection()

    healthy = all(
        s in ("connected", "authenticated")
        for s in [redis_status, vault_status, pg_status]
    )

    return {
        "status":    "healthy" if healthy else "unhealthy",
        "redis":     redis_status,
        "vault":     vault_status,
        "postgres":  pg_status,
        "timestamp": datetime.utcnow().isoformat(),
    }

