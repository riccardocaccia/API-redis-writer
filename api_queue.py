"""
Laniakea Queue API
FastAPI service that authenticates via OIDC and enqueues deployment jobs to Redis.
"""

import os
from datetime import datetime, timedelta
from typing import Optional

import httpx
import jwt
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from redis import Redis
from rq import Queue

# ============================================================
# Configuration (override with environment variables)
# ============================================================

SECRET_KEY          = os.getenv("SECRET_KEY", "change-me-in-production")
ALGORITHM           = "HS256"
SESSION_TTL_MINUTES = int(os.getenv("SESSION_TTL_MINUTES", "60"))

OIDC_DISCOVERY_URL  = os.getenv(
    "OIDC_DISCOVERY_URL",
    "https://iam.recas.ba.infn.it/.well-known/openid-configuration"
)

REDIS_HOST          = os.getenv("REDIS_HOST", "212.189.205.167")
REDIS_PORT          = int(os.getenv("REDIS_PORT", "6379"))
REDIS_PASSWORD      = os.getenv("REDIS_PASSWORD", "admin")

# ============================================================
# Redis / RQ setup
# ============================================================

redis_conn = Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    password=REDIS_PASSWORD,
    decode_responses=True,
)

queues: dict[str, Queue] = {
    "openstack": Queue("openstack", connection=redis_conn),
    "aws":       Queue("aws",       connection=redis_conn),
}

PROVIDER_TO_QUEUE: dict[str, str] = {
    "openstack": "openstack",
    "Openstack": "openstack",
    "OpenStack": "openstack",
    "aws":       "aws",
    "AWS":       "aws",
}

# ============================================================
# Pydantic models
# ============================================================

class OIDCLoginRequest(BaseModel):
    """OIDC access token obtained by the caller from the identity provider."""
    oidc_token: str


class SessionTokenResponse(BaseModel):
    session_token: str
    token_type:    str = "bearer"
    expires_in:    int  # seconds
    user_info:     dict


class DeploymentRequest(BaseModel):
    """
    Full deployment configuration, matching the structure used by workers.
    The auth.aai_token field carries the OIDC token so that workers can
    exchange it for a Keystone token when they process the job.
    """
    deployment_uuid:   str
    timestamp:         str
    description:       str
    auth:              dict   # { aai_token, sub, group }
    orchestrator:      dict   # { target_provider, desired_orchestrator, endpoint }
    selected_provider: str    # "Openstack" | "AWS"
    cloud_providers:   dict


class JobResponse(BaseModel):
    job_id:          str
    queue_name:      str
    deployment_uuid: str
    status:          str
    message:         str

# ============================================================
# FastAPI app
# ============================================================

app = FastAPI(
    title="Laniakea Queue API",
    description="OIDC-authenticated gateway for enqueuing deployment jobs on Redis.",
    version="1.0.0",
)

security = HTTPBearer()

# ============================================================
# Auth helpers
# ============================================================

async def _fetch_userinfo(oidc_token: str) -> dict:
    """
    Validate the OIDC token by calling the identity provider's userinfo endpoint.
    Returns the userinfo claims on success; raises HTTPException otherwise.
    """
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            # Resolve the userinfo endpoint via OIDC discovery
            discovery_resp = await client.get(OIDC_DISCOVERY_URL)
            discovery_resp.raise_for_status()
            userinfo_url = discovery_resp.json()["userinfo_endpoint"]

            # Call userinfo with the caller's token
            userinfo_resp = await client.get(
                userinfo_url,
                headers={"Authorization": f"Bearer {oidc_token}"},
            )

            if userinfo_resp.status_code == 401:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="OIDC token is invalid or expired.",
                )
            userinfo_resp.raise_for_status()
            return userinfo_resp.json()

    except HTTPException:
        raise
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"OIDC provider unreachable: {exc}",
        )


def _create_session_token(user_info: dict) -> tuple[str, int]:
    """
    Mint a short-lived JWT session token from the verified userinfo claims.
    Returns (encoded_token, expires_in_seconds).
    """
    expire = datetime.utcnow() + timedelta(minutes=SESSION_TTL_MINUTES)
    payload = {
        "sub":                user_info.get("sub"),
        "preferred_username": user_info.get("preferred_username"),
        "email":              user_info.get("email"),
        "groups":             user_info.get("groups", []),
        "exp":                expire,
        "iat":                datetime.utcnow(),
        "user_info":          user_info,
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token, SESSION_TTL_MINUTES * 60


def _verify_session_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    """
    Dependency: decode and validate the session JWT.
    Returns the decoded user context.
    """
    try:
        payload = jwt.decode(
            credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM]
        )
        if not payload.get("sub"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token: missing subject.",
            )
        return {
            "sub":      payload["sub"],
            "username": payload.get("preferred_username"),
            "groups":   payload.get("groups", []),
        }
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session token has expired.",
        )
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid session token: {exc}",
        )

# ============================================================
# Endpoints
# ============================================================

@app.post("/auth/oidc", response_model=SessionTokenResponse)
async def login_oidc(req: OIDCLoginRequest):
    """
    Exchange a valid OIDC access token for a short-lived API session token.

    Flow:
        1. Caller authenticates with the OIDC provider and obtains an access token.
        2. POST /auth/oidc  { "oidc_token": "<access_token>" }
        3. This endpoint verifies the token against the provider's userinfo endpoint.
        4. On success, returns a signed JWT session token (valid for SESSION_TTL_MINUTES).
        5. Use the session token as a Bearer token on all subsequent requests.
    """
    user_info = await _fetch_userinfo(req.oidc_token)
    session_token, expires_in = _create_session_token(user_info)

    return SessionTokenResponse(
        session_token=session_token,
        expires_in=expires_in,
        user_info={
            "sub":      user_info.get("sub"),
            "username": user_info.get("preferred_username"),
            "email":    user_info.get("email"),
            "groups":   user_info.get("groups", []),
        },
    )


@app.post("/api/deployments", response_model=JobResponse)
async def enqueue_deployment(
    deployment: DeploymentRequest,
    caller: dict = Depends(_verify_session_token),
):
    """
    Enqueue a deployment job on the Redis queue that matches the selected provider.

    The full deployment dict (including auth.aai_token) is stored as the job
    argument so that workers can exchange it for a Keystone token at runtime.

    Requires a valid session token in the Authorization header.
    """
    # Resolve provider → queue name
    queue_name = PROVIDER_TO_QUEUE.get(deployment.selected_provider)
    if not queue_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"Unsupported provider '{deployment.selected_provider}'. "
                f"Supported values: {list(PROVIDER_TO_QUEUE.keys())}"
            ),
        )

    job_data = {
        "deployment_uuid":   deployment.deployment_uuid,
        "timestamp":         deployment.timestamp,
        "description":       deployment.description,
        "auth":              deployment.auth,
        "orchestrator":      deployment.orchestrator,
        "selected_provider": deployment.selected_provider,
        "cloud_providers":   deployment.cloud_providers,
        # Audit fields added by the API
        "requested_by":      caller["username"],
        "requested_at":      datetime.utcnow().isoformat(),
    }

    try:
        job = queues[queue_name].enqueue(
            "worker_wrapper.run_from_dict",
            job_data,
            job_timeout="10h",
            description=(
                f"Deployment {deployment.deployment_uuid} "
                f"by {caller['username']}"
            ),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to enqueue job: {exc}",
        )

    return JobResponse(
        job_id=job.id,
        queue_name=queue_name,
        deployment_uuid=deployment.deployment_uuid,
        status="queued",
        message=f"Job enqueued on '{queue_name}' queue.",
    )


@app.get("/api/deployments/{job_id}")
async def get_job_status(
    job_id: str,
    caller: dict = Depends(_verify_session_token),
):
    """
    Return the current status of a previously enqueued deployment job.
    Requires a valid session token.
    """
    try:
        from rq.job import Job
        job = Job.fetch(job_id, connection=redis_conn)
        return {
            "job_id":     job.id,
            "status":     job.get_status(),
            "result":     job.result if job.is_finished else None,
            "error":      job.exc_info if job.is_failed else None,
            "created_at": job.created_at,
            "started_at": job.started_at,
            "ended_at":   job.ended_at,
        }
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Job not found: {exc}",
        )


@app.get("/health")
async def health():
    """
    Health check — verifies connectivity to Redis.
    No authentication required.
    """
    try:
        redis_conn.ping()
        redis_status = "connected"
    except Exception as exc:
        redis_status = f"error: {exc}"

    return {
        "status":       "healthy" if redis_status == "connected" else "unhealthy",
        "redis":        redis_status,
        "timestamp":    datetime.utcnow().isoformat(),
    }

# ============================================================
# Entrypoint
# ============================================================

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
