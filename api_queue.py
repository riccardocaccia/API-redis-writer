"""
Laniakea Queue API
FastAPI service that authenticates via OIDC and enqueues deployment jobs to Redis.
Vault integration: credentials are stored per-user under secret/data/<sub>/credentials
"""

import copy
import os
from datetime import datetime, timedelta
from typing import Optional
import httpx
import hvac
import jwt
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from redis import Redis
from rq import Queue

# ============================================================
# Configuration (saved in .env)
# ============================================================

SECRET_KEY          = os.getenv("SECRET_KEY", "")
ALGORITHM           = "HS256"
SESSION_TTL_MINUTES = int(os.getenv("SESSION_TTL_MINUTES", "60")) # 1h validity

# authentication informations json url
OIDC_DISCOVERY_URL  = os.getenv("OIDC_DISCOVERY_URL", "https://iam.recas.ba.infn.it/.well-known/openid-configuration")

# redis block
REDIS_HOST     = os.getenv("REDIS_HOST", "")          # ip
REDIS_PORT     = int(os.getenv("REDIS_PORT", "6379")) # suggested
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "admin") # NOTE: sample

# vault block
VAULT_ADDR         = os.getenv("VAULT_ADDR", "")      # ip
VAULT_WRITER_TOKEN = os.getenv("VAULT_WRITER_TOKEN", "") 
VAULT_TLS_VERIFY   = os.getenv("VAULT_TLS_VERIFY", "false").lower() == "true"
VAULT_MOUNT        = "secret"                         # secrets path in Ansible Vault

# ============================================================
# Redis setup
# ============================================================

# connection pool
redis_conn = Redis(
    host=REDIS_HOST,
    port=REDIS_PORT,
    password=REDIS_PASSWORD,
    # converting results in 
    decode_responses=True,
)

# NOTE: now in my redis only 2 queues are present aws & openstack
queues: dict[str, Queue] = {
                            "openstack": Queue("openstack", connection=redis_conn),
                            "aws":       Queue("aws",       connection=redis_conn),
                           }

# NOTE: check the dashboard if all the controls are necessary
PROVIDER_TO_QUEUE: dict[str, str] = {
    "openstack": "openstack",
    "Openstack": "openstack",
    "OpenStack": "openstack",
    "aws":       "aws",
    "AWS":       "aws",
    "Aws":       "aws",
}

# ============================================================
# Vault client
# ============================================================

vault_client = hvac.Client(
    url=VAULT_ADDR,
    token=VAULT_WRITER_TOKEN, # NOTE: the api will need the token to write secrets inside the vault.
                              #       it has the WRITE ONLY permission, so it cannot read secrets! 
    verify=VAULT_TLS_VERIFY,  # T/F
)

# ============================================================
# Pydantic models
# ============================================================

class OIDCLoginRequest(BaseModel):
    """
    Only the aai token is needed.
    """
    oidc_token: str


class SessionTokenResponse(BaseModel):
    """
    If the token check is OK returns:
    """
    session_token: str
    token_type:    str = "bearer" # check if the user has the correct permission
    expires_in:    int            # seconds
    user_info:     dict

class UserCredentials(BaseModel):
    """
    Provider credentials associated with the user
    Stored in Vault in secret/data/<sub>/credentials.
    OpenStack: app_credentials or aai_token.
    AWS: app_credentials
    """
    # NOTE: now no credentials is essential. Consider changing this logic
    # OpenStack
    openstack_ssh_key:               Optional[str] = None
    openstack_app_credential_id:     Optional[str] = None
    openstack_app_credential_secret: Optional[str] = None
    openstack_proxy_host:            Optional[str] = None
    # AWS
    aws_ssh_key:    Optional[str] = None  # NOTE: mmmm I already have one in openstack, change key name ecc
    aws_access_key: Optional[str] = None
    aws_secret_key: Optional[str] = None
    aws_bastion_ip: Optional[str] = None


class DeploymentRequest(BaseModel):
    """
    Full deployment configuration (deployment_info.json), matching the structure used by workers.
    The auth.aai_token field carries the OIDC token so that workers can exchange it for a Keystone 
    token when they process the job.
    """
    deployment_uuid:   str    # NOTE: the dashboard needs to create a uuid for each job
    timestamp:         str 
    description:       str    # optional or mandatory? check teams
    auth:              dict   # { aai_token, sub, group }
    orchestrator:      dict   # { target_provider, desired_orchestrator, endpoint }
    selected_provider: str    # OpenStack | AWS 
    cloud_providers:   dict   


class JobResponse(BaseModel):
    """
    Job successfully enqueued..now: 
    """
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
    version="1.1.0",    # NOTE: I guess..
)

security = HTTPBearer() # users must authenticate by the Bearer Token Protocol (JWT standard)

# ============================================================
# Auth helpers
# ============================================================

async def _fetch_userinfo(oidc_token: str) -> dict:
    """
    Validate the OIDC token by calling the identity provider's userinfo endpoint.
    Returns the userinfo claims on success; raises HTTPException otherwise.
    """
    try:
        async with httpx.AsyncClient(timeout=10) as client:       # async + wait -> do not block the api 
            discovery_resp = await client.get(OIDC_DISCOVERY_URL)
            discovery_resp.raise_for_status()                     # http result -> if ok does nothing
            userinfo_url = discovery_resp.json()["userinfo_endpoint"]

            userinfo_resp = await client.get(userinfo_url,
                            headers={"Authorization": f"Bearer {oidc_token}"},  # bearer + token -> handle the jwt token
                            )

            # invalid token error
            if userinfo_resp.status_code == 401:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="OIDC token is invalid/expired.",)
            userinfo_resp.raise_for_status()
            return userinfo_resp.json()

    # exceptions
    except HTTPException:
        raise

    except httpx.HTTPError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"OIDC provider unreachable: {exc}",)


def _create_session_token(user_info: dict) -> tuple[str, int]:
    """
    Mint a short-lived JWT session token from the verified userinfo claims.
    Returns (encoded_token, expires_in_seconds).
    This token is signed by the API and allows the user's action until valid (1h).
    """
    # calculate the expire by adding to the current time the inserted expiration
    expire = datetime.utcnow() + timedelta(minutes=SESSION_TTL_MINUTES)
    # user info in the token
    payload = {
        "sub":                user_info.get("sub"),                
        "preferred_username": user_info.get("preferred_username"), 
        "email":              user_info.get("email"),
        "groups":             user_info.get("groups", []),
        "exp":                expire,
        "iat":                datetime.utcnow(),  # issued at
        "user_info":          user_info,
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)  # Generates a signed JWT. 
                                                                  # only this API can verify its integrity.
    return token, SESSION_TTL_MINUTES * 60


def _verify_session_token(credentials: HTTPAuthorizationCredentials = Depends(security),) -> dict:
    """
    Decode and validate the session JWT -> Returns the decoded user context.
    Depends(security) -> searches for the HTTP header: Authorization: Bearer <token>. If not present = UNAUTHORIZED
    """
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])

        # error: no user informations retrievable
        if not payload.get("sub"):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token: missing subject.",)

        # The endpoint receives these informations about the user
        return {
            "sub":      payload["sub"],
            "username": payload.get("preferred_username"),
            "groups":   payload.get("groups", []),         # one or more
            "email":    payload.get("email"),
        }

    # exceptions
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session token has expired.",)

    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid session token: {exc}",)

# ============================================================
# Vault helpers
# ============================================================

def _vault_write_credentials(user_sub: str, creds: dict) -> str:
    """
    Write users credentials in the Vault.
    Path: secret/data/<sub>/credentials.
    Use create_or_update to update if already present.
    """
    # NOTE: to be discussed if ok
    vault_path = f"{user_sub}/credentials"
    try:
        vault_client.secrets.kv.v2.create_or_update_secret(
            path=vault_path,
            secret=creds,
            mount_point=VAULT_MOUNT,
        )
      
    # NOTE: usually write_token not valid or fail to connect to vault    
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Vault write failed: {exc}",
        )

    return vault_path


def _strip_secrets_from_job(deployment: DeploymentRequest) -> dict:
    """
    Return deployment_dict without sensible fields.
    """
    d = copy.deepcopy(deployment.dict())
    provider_key = deployment.selected_provider.lower()
    provider     = d.get("cloud_providers", {}).get(provider_key, {})

    for field in [
        "ssh_key",
        "aws_access_key",
        "aws_secret_key",
        "bastion_ip",
        "private_network_proxy_host",
        "os_application_credential_id",
        "os_application_credential_secret",
    ]:
        provider.pop(field, None)

    return d

# ============================================================
# Endpoints
# ============================================================

# NOTE: the path is only temporary, to be added /v1.0/ and more articulate path
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

    # NOTE for me: why not changing directly the token with keystone? 
    # for example we want to put 50 job in the queue, our token will always has 
    # 1 h life span, and if we exceed all the job managed after 60 minutes would fail.
    # WHEN TO CHANGE the token? the worker must manage the exchange
    
    # return a session token with the user info and his expire date
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


@app.post("/profile/credentials", status_code=201)
async def save_credentials(creds: UserCredentials, caller: dict = Depends(_verify_session_token),):
    # XXX: to be removed
    # i've implemented a parser that, specified the lag in the input allows you to set your credential
    # is it a function for the dashboard? 
    """
    OPTIONAL
    Saves or updates credenzials for the associated provider.

    Le credenziali vengono scritte su Vault sotto:
        secret/data/<sub>/credentials
    """
    secret_data = {k: v for k, v in creds.dict().items() if v is not None}

    if not secret_data:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No credentials provided.",)

    vault_path = _vault_write_credentials(caller["sub"], secret_data)

    return {
        "message":    "Credentials saved to Vault.",
        "vault_path": f"{VAULT_MOUNT}/data/{vault_path}",
        "user":       caller["username"],
    }


@app.post("/api/deployments", response_model=JobResponse)
async def enqueue_deployment(deployment: DeploymentRequest, caller: dict = Depends(_verify_session_token),):
    # NOTE: the exchange at runtime! 
    """
    Enqueue a deployment job on the Redis queue that matches the selected provider.

    The full deployment dict (including auth.aai_token) is stored as the job
    argument so that workers can exchange it for a Keystone token at runtime.

    Requires a valid session token in the Authorization header.
    """
    # take the provider and put the provider name as queue name
    queue_name = PROVIDER_TO_QUEUE.get(deployment.selected_provider)
    if not queue_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(f"Unsupported provider '{deployment.selected_provider}'. "
                    f"Supported: {list(PROVIDER_TO_QUEUE.keys())}"),
                   )

    # Remove sensible fields
    clean_deployment = _strip_secrets_from_job(deployment)

    job_data = {
        **clean_deployment,
        # user_sub explicit: agent uses it to access Vault credentials
        "user_sub":      caller["sub"],
        "user_email":    caller.get("email"),
        "requested_by":  caller["username"],
        "requested_at":  datetime.utcnow().isoformat(),
    }

    try:
        job = queues[queue_name].enqueue(
            "worker_wrapper.run_from_dict",
            job_data,
            job_timeout="10h",
            description=f"Deployment {deployment.deployment_uuid} by {caller['username']}",
        )

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to enqueue job: {exc}",)

    return JobResponse(
        job_id=job.id,
        queue_name=queue_name,
        deployment_uuid=deployment.deployment_uuid,
        status="queued",
        message=f"Job enqueued on '{queue_name}' queue. Credentials will be read from Vault at runtime.",
    )


@app.get("/api/deployments/{job_id}")
async def get_job_status(job_id: str, caller: dict = Depends(_verify_session_token),):
    """    
    Return the current status of a previously enqueued deployment job.
    Require session token.
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
    Health check.
    verify Redis e Vault connectivity. 
    No auth required."""
    # Redis check
    try:
        redis_conn.ping()
        redis_status = "connected"
    except Exception as exc:
        redis_status = f"error: {exc}"

    # Vault check
    try:
        vault_ok = vault_client.is_authenticated()
        vault_status = "authenticated" if vault_ok else "unauthenticated"
    except Exception as exc:
        vault_status = f"error: {exc}"

    healthy = redis_status == "connected" and vault_status == "authenticated"

    return {
        "status":    "healthy" if healthy else "unhealthy",
        "redis":     redis_status,
        "vault":     vault_status,
        "timestamp": datetime.utcnow().isoformat(),
    }


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
