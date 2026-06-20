"""
internal endpoints called exclusively by laniakea-agent.

PATCH /internal/deployments/{uuid}/status
POST  /internal/deployments/{uuid}/logs
"""

import os
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, status
from laniakea_api import database as db
from laniakea_api.auth import verify_agent_token
from laniakea_api.config import VALID_STATUSES, LOG_DIR
from laniakea_api.models import StatusUpdateRequest, LogLineRequest

router = APIRouter()

def _validate_transition(current: str, new_status: str, uuid: str) -> None:
    """
    Raise 409 Conflict if the requested state transition is not allowed
    """
    allowed = {
        "QUEUED":              {"CREATE_IN_PROGRESS", "UPDATE_IN_PROGRESS"},
        "CREATE_IN_PROGRESS":  {"CREATE_COMPLETE", "CREATE_FAILED", "QUEUED"},
        "UPDATE_IN_PROGRESS":  {"UPDATE_FAILED"},
        "CREATE_COMPLETE":     set(),
        "CREATE_FAILED":       set(),
        "UPDATE_FAILED":       set(),}

    permitted = allowed.get(current, set())
    if new_status not in permitted:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"Deployment {uuid}: transition {current!r} -> {new_status!r} is not allowed. "
                f"Permitted next states: {sorted(permitted) or 'none (terminal state)'}."
            ),
        )


@router.patch("/deployments/{uuid}/status")
async def agent_update_status(
    uuid: str, body: StatusUpdateRequest, agent_id: str = Depends(verify_agent_token),):
    """
    Called exclusively by laniakea-agent to transition a deployment status.

    Auth: the agent sends a short-lived token signed with AGENT_MASTER_PASSWORD. 
    No client certificates needed.

    If the token is invalid (wrong/rotated password) the API updates the
    deployment to CREATE_FAILED before returning 401, so the dashboard
    always shows a meaningful state instead of QUEUED forever.
    """
    new_status = body.status.upper()
    if new_status not in VALID_STATUSES:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unknown status '{new_status}'. Valid: {sorted(VALID_STATUSES)}",
        )

    row = db.get_deployment(uuid)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Deployment {uuid} not found.")

    current = row.get("status", "")
    _validate_transition(current, new_status, uuid)

    updated = db.update_status(
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

@router.post("/deployments/{uuid}/logs", status_code=204)
async def agent_push_log(
    uuid: str, body: LogLineRequest,agent_id: str = Depends(verify_agent_token),):
    """
    Receive a single log line from the agent and append it to
    /var/log/laniakea-agent/terraform_{uuid}.log on the API VM.
    The dashboard reads these logs via GET /api/deployments/{uuid}/logs.
    """
    os.makedirs(LOG_DIR, exist_ok=True)
    log_path = os.path.join(LOG_DIR, f"terraform_{uuid}.log")
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    line      = f"{timestamp} [{body.level}] {body.message}\n"
    with open(log_path, "a") as f:
        f.write(line)
