"""
Terraform HTTP backend endpoints.

Terraform (backend "http") calls these endpoints on every operation:

  GET    /internal/tfstate/{uuid}        -> fetch current state (404 if none)
  POST   /internal/tfstate/{uuid}        -> push updated state
  DELETE /internal/tfstate/{uuid}        -> remove state (after destroy)
  POST   /internal/tfstate/{uuid}/lock   -> acquire lock (423 if already locked)
  DELETE /internal/tfstate/{uuid}/lock   -> release lock

Auth: the Terraform http backend only supports HTTP Basic auth
(username/password). The agent passes username="agent" and
password=<agent JWT>; _verify_basic_agent() extracts the password and
validates it with the same logic used for the Bearer-based internal
endpoints.
"""

import base64
import json
from fastapi import APIRouter, HTTPException, Request, Response, status

from laniakea_api import database as db
from laniakea_api.auth import decode_agent_token  # see note in PR: thin wrapper around the JWT check used by verify_agent_token

router = APIRouter()


def _verify_basic_agent(request: Request) -> str:
    """
    Validate HTTP Basic credentials where the password is the agent JWT.
    Also accepts a standard Bearer token for convenience.
    Returns the agent id.
    """
    auth_header = request.headers.get("Authorization", "")

    if auth_header.startswith("Basic "):
        try:
            decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
            _username, _, password = decoded.partition(":")
        except Exception:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                                detail="Malformed Basic credentials.")
        token = password
    elif auth_header.startswith("Bearer "):
        token = auth_header[7:]
    else:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Missing credentials.")

    agent_id = decode_agent_token(token)   # raises HTTPException(401) if invalid
    return agent_id


@router.get("/internal/tfstate/{uuid}")
async def get_state(uuid: str, request: Request):
    _verify_basic_agent(request)
    row = db.tfstate_get(uuid)
    if row is None:
        # Terraform expects 404 (or an empty body) when no state exists yet
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="No state for this deployment.")
    return Response(content=row["state"], media_type="application/json")


@router.post("/internal/tfstate/{uuid}")
async def push_state(uuid: str, request: Request):
    _verify_basic_agent(request)
    # Terraform may append ?ID=<lock-id> — verify it matches the current lock
    lock_id = request.query_params.get("ID")
    current_lock = db.tfstate_get_lock(uuid)
    if current_lock and lock_id:
        try:
            if json.loads(current_lock).get("ID") != lock_id:
                raise HTTPException(status_code=status.HTTP_423_LOCKED,
                                    detail="State is locked by another operation.")
        except json.JSONDecodeError:
            pass
    body = await request.body()
    if not body:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Empty state payload.")
    db.tfstate_set(uuid, body)
    return {"uuid": uuid, "saved": True}


@router.delete("/internal/tfstate/{uuid}")
async def delete_state(uuid: str, request: Request):
    _verify_basic_agent(request)
    db.tfstate_delete(uuid)
    return {"uuid": uuid, "deleted": True}


@router.post("/internal/tfstate/{uuid}/lock")
async def lock_state(uuid: str, request: Request):
    _verify_basic_agent(request)
    body = await request.body()          # Terraform sends lock info JSON
    current = db.tfstate_get_lock(uuid)
    if current:
        # already locked: return 423 with the existing lock info
        return Response(content=current, media_type="application/json",
                        status_code=status.HTTP_423_LOCKED)
    db.tfstate_set_lock(uuid, body.decode("utf-8") if body else "{}")
    return {"uuid": uuid, "locked": True}


@router.delete("/internal/tfstate/{uuid}/lock")
async def unlock_state(uuid: str, request: Request):
    _verify_basic_agent(request)
    db.tfstate_clear_lock(uuid)
    return {"uuid": uuid, "unlocked": True}
