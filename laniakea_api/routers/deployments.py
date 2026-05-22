"""
user deployment endpoints:

GET  /api/deployments
GET  /api/deployments/{uuid}
POST /api/deployments
GET  /api/deployments/{uuid}/logs
"""

import copy
import os
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
import database as db
from laniakea_api.auth import verify_session_token
from laniakea_api.config import LOG_DIR
from laniakea_api.models import DeploymentRequest, JobResponse
from laniakea_api.queue import get_queue

router = APIRouter()

def _strip_secrets(deployment: DeploymentRequest) -> dict:
    """
    Return deployment dict without sensitive credential fields.
    """
    d = copy.deepcopy(deployment.model_dump())
    provider_key = deployment.selected_provider.lower()
    provider     = d.get("cloud_providers", {}).get(provider_key, {})
    for field in [
        "ssh_key", "aws_access_key", "aws_secret_key", "bastion_ip",
        "private_network_proxy_host", "os_application_credential_id",
        "os_application_credential_secret",
    ]:
        provider.pop(field, None)
    return d


@router.get("/api/deployments")
async def list_deployments(caller: dict = Depends(verify_session_token)):
    """
    Return all deployments belonging to the authenticated user.
    """
    rows = db.list_deployments(caller["sub"])
    return {"deployments": rows, "total": len(rows)}


# depends on session token: verify the sign on the token
@router.get("/api/deployments/{uuid}")
async def get_deployment(uuid: str, caller: dict = Depends(verify_session_token)):
    """
    Return the full state of a single deployment.
    """
    row = db.get_deployment(uuid)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Deployment {uuid} not found.")
    if row.get("sub") != caller["sub"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")
    return row


@router.post("/api/deployments", response_model=JobResponse, status_code=202)
async def enqueue_deployment(
    deployment: DeploymentRequest, caller: dict = Depends(verify_session_token),):
    """
    Accept a deployment request:
      1. Write QUEUED to PostgreSQL (dashboard can see it immediately)
      2. eenqueue the job on the matching Redis queue.
    """
    queue_name, q = get_queue(deployment.selected_provider)
    requested_at  = datetime.utcnow()

    # persist QUEUED state before touching Redis
    try:
        db.create_deployment(
            uuid=deployment.deployment_uuid,
            user_sub=caller["sub"],
            username=caller["username"] or caller["sub"],
            description=deployment.description,
            provider=deployment.selected_provider,
            requested_at=requested_at,)
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to persist deployment to database: {exc}",)

    # Enqueue on Redis
    job_data = {
        **_strip_secrets(deployment),
        "user_sub":     caller["sub"],
        "user_email":   caller.get("email"),
        "requested_by": caller["username"],
        "requested_at": requested_at.isoformat(),
    }

    try:
        job = q.enqueue(
            # NOTE: agent: worker_wrapper.py
            "worker_wrapper.run_from_dict",
            job_data,
            job_timeout="10h",
            description=f"Deployment {deployment.deployment_uuid} by {caller['username']}",
        )
    except Exception as exc:
        db.update_status(deployment.deployment_uuid, "CREATE_FAILED", 
                         status_reason=f"Redis enqueue error: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to enqueue job: {exc}",
        )

    return JobResponse(
        job_id=job.id,
        queue_name=queue_name,
        deployment_uuid=deployment.deployment_uuid,
        status="QUEUED",
        message=f"Job enqueued on '{queue_name}' queue.",)


@router.get("/api/deployments/{uuid}/logs")
async def get_deployment_logs(
    uuid: str, tail: Optional[int] = None, caller: dict = Depends(verify_session_token),):
    """
    Return the log lines for a deployment.
    Optional ?tail=N returns only the last N lines.
    """
    row = db.get_deployment(uuid)
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, 
                            detail=f"Deployment {uuid} not found.")
    if row.get("sub") != caller["sub"]:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")

    log_path = os.path.join(LOG_DIR, f"terraform_{uuid}.log")
    if not os.path.exists(log_path):
        return {"uuid": uuid, "lines": [], "message": "No logs yet, deployment may still be queued."}

    with open(log_path, "r") as f:
        lines = f.read().splitlines()

    if tail:
        lines = lines[-tail:]

    return {"uuid": uuid, "lines": lines, "total": len(lines)}

