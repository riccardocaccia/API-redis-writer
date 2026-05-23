"""
Authentication helpers:
  - fetch_userinfo       : validate OIDC access token via provider's userinfo endpoint
  - create_session_token : mint a short-lived HS256 JWT
  - verify_session_token : FastAPI dependency — validates session JWT from Bearer header
  - verify_agent_token   : FastAPI dependency — validates agent JWT (pool password model)
"""

import time
from typing import Optional

import httpx
import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from laniakea_api.config import (
    SECRET_KEY, ALGORITHM, SESSION_TTL_MINUTES,
    OIDC_DISCOVERY_URL, AGENT_MASTER_PASSWORD,
)

_bearer = HTTPBearer()

# OIDC helpers

async def fetch_userinfo(oidc_token: str) -> dict:
    """
    Validate an OIDC access token by calling the provider's userinfo endpoint.
    Returns the userinfo claims dict on success; raises HTTP 401 on failure.
    """
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
                detail=f"OIDC userinfo returned {resp.status_code}: {resp.text}",
            )
        return resp.json()
    except HTTPException:
        raise
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"OIDC validation failed: {exc}",
        )

# Session token (HS256 JWT)

def create_session_token(user_info: dict) -> tuple[str, int]:
    """
    Mint a short-lived HS256 JWT from OIDC userinfo claims.
    Returns (token_string, expires_in_seconds).
    """
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
    token = jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)
    return token, expires_in


async def verify_session_token(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
) -> dict:
    """
    FastAPI dependency. Validates the session JWT sent as Bearer token.
    Returns the decoded payload dict (sub, username, email, groups, …).
    """
    token = credentials.credentials
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload
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

# Agent token (JWT pool password — HTCondor style)

async def verify_agent_token(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
) -> str:
    """
    FastAPI dependency. Validates the agent JWT signed with the shared AGENT_MASTER_PASSWORD.
    Returns the agent_id (sub field) on success.
    """
    if not AGENT_MASTER_PASSWORD:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="AGENT_MASTER_PASSWORD not configured on this API.",
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
