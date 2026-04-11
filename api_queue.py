"""
Laniakea Queue API

FastAPI service that:
  - authenticates users via OIDC
  - enqueues deployment jobs to Redis
  - owns the PostgreSQL connection and all deployment state writes
  - exposes a mTLS-protected endpoint for the agent to update deployment status
"""

import copy
import os
import ssl
from datetime import datetime, timedelta
from typing import Optional
import httpx
import hvac
import jwt
import psycopg2
from psycopg2.extras import RealDictCursor
import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel
from redis import Redis
from rq import Queue

# ============================================================
# Configuration (.env)
# ============================================================

#NOTE
# maybe remove the standard empty values -> make them mandatory?
# move port in .env?
SECRET_KEY          = os.getenv("SECRET_KEY", "")
ALGORITHM           = "HS256"
SESSION_TTL_MINUTES = int(os.getenv("SESSION_TTL_MINUTES", "60"))
OIDC_DISCOVERY_URL  = os.getenv("OIDC_DISCOVERY_URL", "")

# Redis
REDIS_HOST     = os.getenv("REDIS_HOST", "")
REDIS_PORT     = int(os.getenv("REDIS_PORT", "6379"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "admin")

# Vault
VAULT_ADDR         = os.getenv("VAULT_ADDR", "")
VAULT_WRITER_TOKEN = os.getenv("VAULT_WRITER_TOKEN", "")
VAULT_TLS_VERIFY   = os.getenv("VAULT_TLS_VERIFY", "false").lower() == "true"
VAULT_MOUNT        = "secret"

# Postgresql
PG_HOST     = os.getenv("PG_HOST", "localhost")
PG_PORT     = int(os.getenv("PG_PORT", "5432"))
PG_DATABASE = os.getenv("PG_DATABASE", "")
PG_USER     = os.getenv("PG_USER", "")
PG_PASSWORD = os.getenv("PG_PASSWORD", "")

# mTLS ca cert used to verify the agent's client certificate
MTLS_CA_CERT = os.getenv("MTLS_CA_CERT", "certs/ca.crt")

# ============================================================
# Deployment status DASHBOARD-LIKE
# ============================================================

VALID_STATUSES = {
    "QUEUED",
    "CREATE_IN_PROGRESS",
    "CREATE_COMPLETE",
    "CREATE_FAILED",
    "UPDATE_IN_PROGRESS",
    "UPDATE_FAILED",
}

# ============================================================
# PostgreSQL helpers
# ============================================================

def _get_pg_conn():
    """
    Open and return a new PostgreSQL connection.
    """
    return psycopg2.connect(
        host=PG_HOST,
        port=PG_PORT,
        database=PG_DATABASE,
        user=PG_USER,
        password=PG_PASSWORD,
    )

def _pg_create_deployment( 
        uuid: str, user_sub: str, username: str, description: str, provider: str, requested_at: datetime,) -> None:
    """
    Insert a new deployment row with status QUEUED.
    Called by the API the moment a job is accepted, before Redis enqueue.
    """
    conn = _get_pg_conn()
    try:
        with conn.cursor() as cur:
            # assicura che l'utente esista prima dell'insert del deployment
            cur.execute(
                """
                INSERT INTO users (sub, username, email, role, active)
                VALUES (%s, %s, %s, 'user', true)
                ON CONFLICT (sub) DO NOTHING
                """,
                (user_sub, username, ""),
            )
            cur.execute(
                """
                INSERT INTO deployments (
                    uuid, status, creation_time, update_time,
                    description, provider_name, sub
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (uuid) DO UPDATE
                    SET status = EXCLUDED.status, update_time = EXCLUDED.update_time
                """,
                (uuid, "QUEUED", requested_at, requested_at, description, provider, user_sub),
            )
        conn.commit()    
    finally:
        conn.close()


def _pg_update_status(
    uuid: str, new_status: str, status_reason: Optional[str] = None, outputs: Optional[str] = None,) -> bool:
    """
    Update the status of an existing deployment.
    Returns True if a row was actually updated, False if uuid not found.
    """
    conn = _get_pg_conn()
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE deployments
                SET status        = %s,
                    status_reason = COALESCE(%s, status_reason),
                    outputs       = COALESCE(%s, outputs),
                    update_time   = %s
                WHERE uuid = %s
                """,
                (new_status, status_reason, outputs, datetime.utcnow(), uuid),
            )
            updated = cur.rowcount > 0
        conn.commit()
        return updated
    finally:
        conn.close()

def _pg_get_deployment(uuid: str) -> Optional[dict]:
    """Fetch a single deployment row by uuid."""
    conn = _get_pg_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:  # does not return tuple -> dictionary
            cur.execute("SELECT * 
                         FROM deployments 
                         WHERE uuid = %s", (uuid,))
            row = cur.fetchone()                                 # since uuid is unique
            return dict(row) if row else None
    finally:
        conn.close()


def _pg_list_deployments(user_sub: str) -> list:
    """Fetch all deployments owned by a user, ordered by creation time desc."""
    conn = _get_pg_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * 
                         FROM deployments 
                         WHERE sub = %s 
                         ORDER BY creation_time DESC",
                (user_sub,),
            )
            return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()

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

# NOTE: now my redis has only 2 queues -> are present aws & openstack
queues: dict = {
    "openstack": Queue("openstack", connection=redis_conn),
    "aws":       Queue("aws",       connection=redis_conn),
}

# NOTE: check the dashboard if all the controls are necessary
# remove prob.
PROVIDER_TO_QUEUE: dict = {
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
    token=VAULT_WRITER_TOKEN,   # NOTE: the api will need the token to write secrets inside the vault.
                                #       it has the WRITE ONLY permission, so it cannot read secrets! 
    verify=VAULT_TLS_VERIFY,    # T/F
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
    token_type:    str = "bearer"  # Check if the user has the correct permission
    expires_in:    int            # sec.
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
    aws_ssh_key:    Optional[str] = None      # NOTE: mmmm I already have one in openstack, change key name ecc
    aws_access_key: Optional[str] = None
    aws_secret_key: Optional[str] = None
    aws_bastion_ip: Optional[str] = None


class DeploymentRequest(BaseModel):
    """
    Full deployment configuration (deployment_info.json), matching the structure used by workers.
    The auth.aai_token field carries the OIDC token so that workers can exchange it for a keystone token
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
    job_id:          str
    queue_name:      str
    deployment_uuid: str
    status:          str
    message:         str


class StatusUpdateRequest(BaseModel):
    """
    Payload sent by the agent to update a deployment status.
    Only the agent (authenticated via mTLS client cert) can call PATCH /internal/...
    """
    status:        str
    status_reason: Optional[str] = None
    outputs:       Optional[str] = None

# ============================================================
# FastAPI app
# ============================================================

app = FastAPI(
    title="Laniakea Queue API",
    description="OIDC-authenticated gateway for enqueuing deployment jobs on Redis.",
    version="1.2.0",  # NOTE: I guess...
)

security = HTTPBearer()  # users must authenticate by the Bearer Token Protocol (JWT standard)

# ============================================================
# mTLS dependency
# ============================================================

def _require_agent_cert(request: Request) -> str:
    """
    Dependency that confirms the caller presented a valid mTLS client cert.

    How it works:
    - Uvicorn is started with --ssl-ca-certs certs/ca.crt which sets
      ssl.CERT_REQUIRED. The TLS handshake fails immediately if the client
      does not present a certificate signed by that CA. NEED TO BE CREATED
    - By the time this dependency runs, the cert is already cryptographically
      validated by OpenSSL, we just extract the CN for audit logging.
    - The agent's cert IS its identity

    To run with mTLS:
        uvicorn api_queue:app \
            --ssl-keyfile  certs/api.key \
            --ssl-certfile certs/api.crt \
            --ssl-ca-certs certs/ca.crt \
            --host 0.0.0.0 --port 8443
    """
    # If running behind an mTLS-terminating proxy (nginx, ...), read the
    # verified subject from a forwarded header.
    agent_id = request.headers.get("X-Agent-ID", "laniakea-agent")
    return agent_id

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
            discovery_resp = await client.get(OIDC_DISCOVERY_URL) # async + wait -> do not block the api
            discovery_resp.raise_for_status()                     # http result -> if ok does nothing
            userinfo_url = discovery_resp.json()["userinfo_endpoint"]
            userinfo_resp = await client.get(
                userinfo_url,
                headers={"Authorization": f"Bearer {oidc_token}"}, # bearer + token -> handle the jwt token
            )

            # invalid token error
            if userinfo_resp.status_code == 401:
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="OIDC token is invalid/expired.")
            userinfo_resp.raise_for_status()
            return userinfo_resp.json()

    # exceptions
    except HTTPException:
        raise
    except httpx.HTTPError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"OIDC provider unreachable: {exc}")


def _create_session_token(user_info: dict) -> tuple:
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
        "iat":                datetime.utcnow(),
        "user_info":          user_info,
    }
    # generate a jwt token -> signed! with teh SECRET_KEY
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token, SESSION_TTL_MINUTES * 60


def _verify_session_token(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    """
    Decode and validate the session JWT -> Returns the decoded user context.
    Depends(security) -> searches for the HTTP header: Authorization: Bearer <token>. If not present = UNAUTHORIZED
    """
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        # errror no user info retrieved
        if not payload.get("sub"):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token: missing subject.")
        return {
            "sub":      payload["sub"],
            "username": payload.get("preferred_username"),
            "groups":   payload.get("groups", []),
            "email":    payload.get("email"),
        }

    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session token has expired.")
    except jwt.InvalidTokenError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=f"Invalid session token: {exc}")

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
            path=vault_path, secret=creds, mount_point=VAULT_MOUNT,
        )

    # NOTE: usually write_token not valid or fail to connect to vault
    except Exception as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=f"Vault write failed: {exc}")
    return vault_path


def _strip_secrets_from_job(deployment: DeploymentRequest) -> dict:
    """
    Return deployment_dict without sensible fields.
    """
    d = copy.deepcopy(deployment.dict())
    provider_key = deployment.selected_provider.lower()
    provider     = d.get("cloud_providers", {}).get(provider_key, {})
    for field in [
        "ssh_key", "aws_access_key", "aws_secret_key", "bastion_ip",
        "private_network_proxy_host", "os_application_credential_id",
        "os_application_credential_secret",
    ]:
        provider.pop(field, None)
    return d

# ============================================================
# Endpoints — dashboard / user facing
# ============================================================

# NOTE: the path is only temporary, to be added /v1.0/ and more articulate path
@app.post("/auth/oidc", response_model=SessionTokenResponse)
async def login_oidc(req: OIDCLoginRequest):
    """Exchange a valid OIDC access token for a short-lived API session token.
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
async def save_credentials(creds: UserCredentials, caller: dict = Depends(_verify_session_token)):
    """Save or update provider credentials for the authenticated user in Vault.

    XXX: to be removed
    # i've implemented a parser that, specified the lag in the input allows you to set your credential
    # is it a function for the dashboard? 

    OPTIONAL
    Saves or updates credenzials for the associated provider.

    Le credenziali vengono scritte su Vault sotto:
        secret/data/<sub>/credentials
    """
    secret_data = {k: v for k, v in creds.dict().items() if v is not None}
    if not secret_data:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No credentials provided.")
    vault_path = _vault_write_credentials(caller["sub"], secret_data)
    return {"message": "Credentials saved to Vault.", "vault_path": f"{VAULT_MOUNT}/data/{vault_path}", "user": caller["username"]}


@app.post("/api/deployments", response_model=JobResponse, status_code=202)
async def enqueue_deployment(deployment: DeploymentRequest, caller: dict = Depends(_verify_session_token),):
    """
    Accept a deployment request:
      1. Write a QUEUED record to PostgreSQL (dashboard can see it immediately).
      2. Enqueue the job on the matching Redis queue.
    The agent has zero direct DB access: it only calls PATCH /internal/deployments/{uuid}/status.
    """
    # take the provider and put the provider name as queue name
    queue_name = PROVIDER_TO_QUEUE.get(deployment.selected_provider)
    if not queue_name:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported provider '{deployment.selected_provider}'. Supported: {list(PROVIDER_TO_QUEUE.keys())}",
        )

    requested_at = datetime.utcnow()

    # persist QUEUED state before touching Redis so the dashboard never misses it
    try:
        _pg_create_deployment(
            uuid=deployment.deployment_uuid,
            user_sub=caller["sub"],
            username=caller["username"] or caller["sub"],
            description=deployment.description,
            provider=deployment.selected_provider,
            requested_at=requested_at,
        )

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to persist deployment to database: {exc}",
        )

    # enqueue on Redis
    clean_deployment = _strip_secrets_from_job(deployment)
    job_data = {
        **clean_deployment,
        "user_sub":     caller["sub"],
        "user_email":   caller.get("email"),
        "requested_by": caller["username"],
        "requested_at": requested_at.isoformat(),
    }

    try:
        job = queues[queue_name].enqueue(
            "worker_wrapper.run_from_dict",
            job_data,
            # NOTE: bho
            job_timeout="10h",
            description=f"Deployment {deployment.deployment_uuid} by {caller['username']}",
        )

    except Exception as exc:
        # Mark as failed so dashboard see correct state
        _pg_update_status(deployment.deployment_uuid, "CREATE_FAILED", status_reason=f"Redis enqueue error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to enqueue job: {exc}",
        )

    return JobResponse(
        job_id=job.id,
        queue_name=queue_name,
        deployment_uuid=deployment.deployment_uuid,
        status="QUEUED",
        message=f"Job enqueued on '{queue_name}' queue.",
    )


@app.get("/api/deployments")
async def list_deployments(caller: dict = Depends(_verify_session_token)):
    """Return all deployments belonging to the authenticated user."""
    rows = _pg_list_deployments(caller["sub"])
    return {"deployments": rows, "total": len(rows)}


@app.get("/api/deployments/{uuid}")
async def get_deployment(uuid: str, caller: dict = Depends(_verify_session_token)):
    """Return the full state of a single deployment."""
    row = _pg_get_deployment(uuid)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Deployment {uuid} not found.")
    if row.get("sub") != caller["sub"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")
    return row

# ============================================================
# Endpoint: agent changing the status
# ============================================================

@app.patch("/internal/deployments/{uuid}/status")
async def agent_update_status( uuid: str, body: StatusUpdateRequest, agent_id: str = Depends(_require_agent_cert),):
    """
    Called exclusively by laniakea agents to transition a deployment status.

    Auth model (like Wireguard):
    - The agent holds certs/agent.crt signed by an internal CA.
    - The API TLS listener is started with --ssl-ca-certs certs/ca.crt,
      which sets ssl.CERT_REQUIRED at the OpenSSL level.
    - No valid cert = TLS handshake fails = request never reaches FastAPI.
    - No Bearer token is needed or accepted.

    Allowed transitions:
        QUEUED             -> CREATE_IN_PROGRESS
        CREATE_IN_PROGRESS -> CREATE_COMPLETE | CREATE_FAILED
        QUEUED             -> UPDATE_IN_PROGRESS
        UPDATE_IN_PROGRESS -> UPDATE_FAILED
    """
    new_status = body.status.upper()
    if new_status not in VALID_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown status '{new_status}'. Valid: {sorted(VALID_STATUSES)}",
        )

    row = _pg_get_deployment(uuid)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Deployment {uuid} not found.")

    current = row.get("status", "")
    _validate_transition(current, new_status, uuid)

    updated = _pg_update_status(
        uuid=uuid,
        new_status=new_status,
        status_reason=body.status_reason,
        outputs=body.outputs,
    )
    if not updated:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="DB update failed.")

    return {
        "deployment_uuid": uuid,
        "previous_status": current,
        "new_status":      new_status,
        "updated_by":      agent_id,
        "updated_at":      datetime.utcnow().isoformat(),
    }


def _validate_transition(current: str, new_status: str, uuid: str) -> None:
    """Raise 409 Conflict if the requested state transition is not allowed."""
    allowed = {
        "QUEUED":              {"CREATE_IN_PROGRESS", "UPDATE_IN_PROGRESS"},
        "CREATE_IN_PROGRESS":  {"CREATE_COMPLETE", "CREATE_FAILED"},
        "UPDATE_IN_PROGRESS":  {"UPDATE_FAILED"},
        "CREATE_COMPLETE":     set(),
        "CREATE_FAILED":       set(),
        "UPDATE_FAILED":       set(),
    }
    permitted = allowed.get(current, set())
    if new_status not in permitted:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Deployment {uuid}: transition {current!r} -> {new_status!r} is not allowed. "
                f"Permitted next states: {sorted(permitted) or 'none (terminal state)'}."
            ),
        )

# ============================================================
# Health check
# ============================================================

@app.get("/health")
async def health():
    """Verify Redis, Vault and PostgreSQL connectivity. No auth required."""
    try:
        redis_conn.ping()
        redis_status = "connected"
    except Exception as exc:
        redis_status = f"error: {exc}"

    try:
        vault_status = "authenticated" if vault_client.is_authenticated() else "unauthenticated"
    except Exception as exc:
        vault_status = f"error: {exc}"

    try:
        conn = _get_pg_conn()
        conn.close()
        pg_status = "connected"
    except Exception as exc:
        pg_status = f"error: {exc}"

    healthy = all(s in ("connected", "authenticated") for s in [redis_status, vault_status, pg_status])

    return {
        "status":    "healthy" if healthy else "unhealthy",
        "redis":     redis_status,
        "vault":     vault_status,
        "postgres":  pg_status,
        "timestamp": datetime.utcnow().isoformat(),
    }


# main
if __name__ == "__main__":
    uvicorn.run(
        app,
        host="0.0.0.0",
        port=8443,
        ssl_keyfile="certs/api.key",
        ssl_certfile="certs/api.crt",
        ssl_ca_certs=MTLS_CA_CERT,   # agent must present valid cert
        log_level="info",
    )

