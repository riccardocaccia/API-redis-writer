"""
Internal agent info:
  POST /internal/agents/heartbeat   — agent reports its quota
  GET  /internal/agents/status      — dashboard reads all agents status (also public)
"""

import json
from datetime import datetime, timezone
from typing import Optional
from fastapi import APIRouter, Depends
from pydantic import BaseModel
from laniakea_api.auth import verify_agent_token, verify_session_token
from laniakea_api.queue import redis_conn

router = APIRouter()

# Redis key prefix and TTL for heartbeat
_HB_PREFIX = "heartbeat:"
_HB_TTL    = 60   # if agent misses 2 heartbeat (seconds) it's considered offline

# Pydantic models
class QuotaInfo(BaseModel):
    instances_available:   Optional[int] = None
    ram_mb_available:      Optional[int] = None
    cores_available:       Optional[int] = None
    floating_ips_available: Optional[int] = None


# NOTE: is it ok every 30 sec? 
class HeartbeatRequest(BaseModel):
    """
    Sent by the agent every 30 seconds
    contains the agent's current available quota on the cloud provider.
    """
    provider: str          # openstack | NOTE: aws (necessary for aws, how it works)
    quota:    QuotaInfo
    version:  Optional[str] = None   # agent package version for monitoring


class AgentStatus(BaseModel):
    agent_id:  str
    online:    bool
    last_seen: Optional[str] = None
    provider:  Optional[str] = None
    quota:     Optional[QuotaInfo] = None
    version:   Optional[str] = None


# Endpoints
@router.post("/agents/heartbeat", status_code=204)
async def agent_heartbeat(
    body: HeartbeatRequest,
    agent_id: str = Depends(verify_agent_token),
):
    """
    Called by laniakea-agent every 30 seconds.
    Stores the agent's quota info in Redis with a 60 second TTL.
    If the agent stops sending heartbeats, the key expires and the
    dashboard shows the agent as offline.
    """
    payload = {
        "agent_id":  agent_id,
        "provider":  body.provider,
        "quota":     body.quota.model_dump(),
        "version":   body.version,
        "last_seen": datetime.now(timezone.utc).isoformat(),
    }
    redis_conn.setex(
        f"{_HB_PREFIX}{agent_id}",
        _HB_TTL,
        json.dumps(payload),
    )


@router.get("/agents/status")
async def agents_status(caller: dict = Depends(verify_session_token)):
    """
    Returns the status of all agents that have sent a heartbeat
    in the last 60 seconds.
    Called by the dashboard to show agent health and available quota.
    """
    keys = redis_conn.keys(f"{_HB_PREFIX}*")
    agents = []

    for key in keys:
        raw = redis_conn.get(key)
        if not raw:
            continue
        try:
            data = json.loads(raw)
            agents.append(AgentStatus(
                agent_id=data["agent_id"],
                online=True,
                last_seen=data.get("last_seen"),
                provider=data.get("provider"),
                quota=QuotaInfo(**data["quota"]) if data.get("quota") else None,
                version=data.get("version"),
            ))
        except Exception:
            continue

    return {
        "agents": [a.model_dump() for a in agents],
        "total":  len(agents),
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
