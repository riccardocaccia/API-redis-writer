"""
Registers all routers and starts uvicorn
"""

import os
import uvicorn
from fastapi import FastAPI
from laniakea_api.routers import agent, agents,credentials, deployments, health

# FastAPI App

app = FastAPI(
    title="Laniakea Queue API",
    description="OIDC-authenticated gateway for enqueuing cloud deployment jobs.",
    version="1.4.0",
)

# NOTE: CHANGE HERE for path
# Route prefixes
BASE    = "/laniakea_core/v1.0"
INTERNAL = BASE + "/internal"

app.include_router(credentials.router, prefix=BASE)
app.include_router(deployments.router, prefix=BASE)
app.include_router(agent.router, prefix=INTERNAL)
app.include_router(agents.router, prefix=INTERNAL)   # POST /internal/agents/heartbeat
app.include_router(agents.router, prefix=BASE)        # GET /api/agents/status
app.include_router(health.router)       # /health:no prefix

############ Routes registered ############################
#NOTE: Add or remove every new modification
#
# Public (dashboard):
#   POST   /laniakea_core/v1.0/auth/oidc
#   POST   /laniakea_core/v1.0/profile/credentials
#   POST   /laniakea_core/v1.0/profile/credentials/test
#   POST   /laniakea_core/v1.0/api/deployments
#   GET    /laniakea_core/v1.0/api/deployments
#   GET    /laniakea_core/v1.0/api/deployments/{uuid}
#   GET    /laniakea_core/v1.0/api/deployments/{uuid}/logs
#
# Internal (agent only):
#   PATCH  /laniakea_core/v1.0/internal/deployments/{uuid}/status
#   POST   /laniakea_core/v1.0/internal/deployments/{uuid}/logs
#
# Monitoring:
#   GET    /health

# Entry point uvicorn 
if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8443,
        ssl_keyfile=os.getenv("SSL_KEYFILE", "certs/api.key"),
        ssl_certfile=os.getenv("SSL_CERTFILE", "certs/api.crt"),
        log_level="info",
        reload=False,
    )

