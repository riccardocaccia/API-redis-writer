"""
Import the .env vars
Inizialize all the service: Redis, Vault, Posgre
"""

import os

# Authentication
SECRET_KEY          = os.getenv("SECRET_KEY", "")
ALGORITHM           = "HS256"
SESSION_TTL_MINUTES = int(os.getenv("SESSION_TTL_MINUTES", "60")) # NOTE: maybe longer
OIDC_DISCOVERY_URL  = os.getenv("OIDC_DISCOVERY_URL", "")

# Agent pool password
# to revoke ALL agents: change this value and restart API + all agents.
AGENT_MASTER_PASSWORD = os.getenv("AGENT_MASTER_PASSWORD", "")

# Redis
REDIS_HOST     = os.getenv("REDIS_HOST", "")
# NOTE: mod. port
REDIS_PORT     = int(os.getenv("REDIS_PORT", "1908"))
REDIS_PASSWORD = os.getenv("REDIS_PASSWORD", "")

# vault 
VAULT_ADDR         = os.getenv("VAULT_ADDR", "")
VAULT_WRITER_TOKEN = os.getenv("VAULT_WRITER_TOKEN", "")
VAULT_TLS_VERIFY   = os.getenv("VAULT_TLS_VERIFY", "false").lower() == "true"
VAULT_MOUNT        = "secret"

# PostgreSQL
PG_HOST     = os.getenv("PG_HOST", "localhost")
PG_PORT     = int(os.getenv("PG_PORT", "5432"))
PG_DATABASE = os.getenv("PG_DATABASE", "")
PG_USER     = os.getenv("PG_USER", "")
PG_PASSWORD = os.getenv("PG_PASSWORD", "")

# Deployment logs
# One file per deployment: terraform_{uuid}.log
# Agent pushes lines via POST /internal/deployments/{uuid}/logs.
# Dashboard reads via GET /api/deployments/{uuid}/logs.
LOG_DIR = os.getenv("DEPLOYMENT_LOG_DIR", "/var/log/laniakea-agent")

# NOTE: UPDATE.. still not used
# deployment status
VALID_STATUSES = {
    "QUEUED",
    "CREATE_IN_PROGRESS",
    "CREATE_COMPLETE",
    "CREATE_FAILED",
    "UPDATE_IN_PROGRESS",
    "UPDATE_FAILED",
    "DELETE_IN_PROGRESS", 
    "DELETE_COMPLETE", 
    "DELETE_FAILED",
}

