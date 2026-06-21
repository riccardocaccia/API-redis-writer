"""
Authentication helpers

It is responsible for verifying the identity of those who knock on 
the server's door distinguishing between two types of users: 
human users (who pass through an OIDC Sign-in system) and worker agents
"""
import time
import httpx
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from laniakea_api.config import (
                                 SECRET_KEY, ALGORITHM, SESSION_TTL_MINUTES,
                                 OIDC_DISCOVERY_URL, AGENT_MASTER_PASSWORD,
                                )

# Initialize security OAuth2 Bearer Token
_bearer = HTTPBearer()

async def fetch_userinfo(oidc_token: str) -> dict:
    """
    Takes an authentication token provided by a user and asks an external identity server 
    (the OIDC Provider) who that user actually is, retriving user info
    """
    try:
        # asynchronous HTTP to avoid waste of server resources
        async with httpx.AsyncClient(timeout=10) as client:
            # OIDC discovery
            discovery = await client.get(OIDC_DISCOVERY_URL)    
            discovery.raise_for_status()                         # status 200: OK
            userinfo_url = discovery.json()["userinfo_endpoint"] # now final url is known
            # USER info request
            resp = await client.get(
                userinfo_url,
                headers={"Authorization": f"Bearer {oidc_token}"},
            )
        if resp.status_code != 200:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"OIDC userinfo returned {resp.status_code}",
            )
        return resp.json()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"OIDC validation failed: {exc}",
        )


def create_session_token(user_info: dict) -> tuple:
    """
    Querying the external OIDC server for every single request would slow down the API. 
    To avoid this behaviour, once the user has been verified by fetch_userinfo, this function 
    generates an internal JWT token:
 
             It takes the user's data (sub, username, email, groups).
             It adds an expiration date based on the minutes configured in SESSION_TTL_MINUTES.
             It cryptographically signs everything with a secret key (SECRET_KEY)
             It returns a compact token that the user will use for subsequent requests.
    """
    #NOTE: act here for expiration
    expires_in = SESSION_TTL_MINUTES * 60
    now = int(time.time())
    #NOTE: PAYLOAD 
    payload = {
        "sub":      user_info.get("sub"),
        "username": user_info.get("preferred_username") or user_info.get("sub"),
        "email":    user_info.get("email"),
        "groups":   user_info.get("groups", []),
        "iat":      now,
        "exp":      now + expires_in,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM), expires_in


async def verify_session_token(credentials: HTTPAuthorizationCredentials = Depends(_bearer),) -> dict:
    """
    Check that the HTTP request contains an authorization header.
    Takes the internal JWT token created in the previous step and checks 
    whether the signature is authentic (using the SECRET_KEY).
    """
    try:
        return jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session token expired",
        )

    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid session token: {exc}",
        )


async def verify_agent_token(credentials: HTTPAuthorizationCredentials = Depends(_bearer),) -> str:
    """
    This function validates the tokens used by workers.
    It doesn't use the user's key, but a dedicated secret key 
    called AGENT_MASTER_PASSWORD.
    If the worker sends a valid token signed with this master password, 
    the API trusts the worker and allows it to fetch or update the status of deployment jobs.

    HTCondor pool-password like.
    """
    if not AGENT_MASTER_PASSWORD:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="AGENT_MASTER_PASSWORD not configured, set it as an ambient variable or in the .env",
        )
    try:
        payload = jwt.decode(
            credentials.credentials,
            AGENT_MASTER_PASSWORD,
            algorithms=["HS256"],
        )
        # NOTE: unknown-agent default value
        return payload.get("sub", "unknown-agent")

    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Agent token expired.",
        )
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid agent token: {exc}",
        )
