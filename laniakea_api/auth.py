"""
Authentication helpers.
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

_bearer = HTTPBearer()


async def fetch_userinfo(oidc_token: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            discovery = await client.get(OIDC_DISCOVERY_URL)
            discovery.raise_for_status()
            userinfo_url = discovery.json()["userinfo_endpoint"]
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
    expires_in = SESSION_TTL_MINUTES * 60
    now = int(time.time())
    payload = {
        "sub":      user_info.get("sub"),
        "username": user_info.get("preferred_username") or user_info.get("sub"),
        "email":    user_info.get("email"),
        "groups":   user_info.get("groups", []),
        "iat":      now,
        "exp":      now + expires_in,
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM), expires_in


async def verify_session_token(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
) -> dict:
    try:
        return jwt.decode(
            credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM]
        )
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session token expired.",
        )
    except jwt.InvalidTokenError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Invalid session token: {exc}",
        )


async def verify_agent_token(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
) -> str:
    """
    Validates the agent JWT signed with AGENT_MASTER_PASSWORD.
    HTCondor pool-password model — one shared secret for all agents.
    """
    if not AGENT_MASTER_PASSWORD:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="AGENT_MASTER_PASSWORD not configured.",
        )
    try:
        payload = jwt.decode(
            credentials.credentials,
            AGENT_MASTER_PASSWORD,
            algorithms=["HS256"],
        )
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
