"""
User credential management.

POST /auth/oidc
POST /profile/credentials
POST /profile/credentials/test
"""

from fastapi import APIRouter, Depends, HTTPException, status
from laniakea_api.auth import fetch_userinfo, create_session_token, verify_session_token
from laniakea_api.models import (OIDCLoginRequest, SessionTokenResponse,UserCredentials,
                    CredentialTestRequest, CredentialTestResponse,)
from laniakea_api.queue import vault_write_credentials, VAULT_MOUNT
from laniakea_api.queue import (vault_list_service_creds, vault_read_service_creds,
                                vault_write_service_creds, vault_delete_service_creds)
from laniakea_api.queue import vault_read_global, vault_strip_global_keys


router = APIRouter()

@router.post("/auth/oidc", response_model=SessionTokenResponse)
async def login_oidc(req: OIDCLoginRequest):
    """
    exchange a valid OIDC access token for a short-lived API session token.

    Flow:
      1. Caller authenticates with the OIDC provider and obtains an access token.
      2. POST /auth/oidc { "oidc_token": "<access_token>" }
      3. This endpoint verifies the token against the provider's userinfo endpoint.
      4. On success, returns a signed JWT session token
      5. Use the session token as Bearer on all subsequent requests.
    """
    user_info = await fetch_userinfo(req.oidc_token)
    session_token, expires_in = create_session_token(user_info)
    return SessionTokenResponse(session_token=session_token, expires_in=expires_in,
        # Add here additional information to include in the token
        user_info={
            "sub":      user_info.get("sub"),
            "username": user_info.get("preferred_username"),
            "email":    user_info.get("email"),
            "groups":   user_info.get("groups", []),
        },
    )

@router.post("/profile/credentials", status_code=201)
async def save_credentials(creds: UserCredentials, caller: dict = Depends(verify_session_token),):
    """
    Save or update provider credentials for the authenticated user in Vault
    """
    secret_data = {k: v for k, v in creds.model_dump().items() if v is not None}
    if not secret_data:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="No credentials provided.",)
    vault_path = vault_write_credentials(caller["sub"], secret_data)
    return {
        "message":    "Credentials saved to Vault.",
        "vault_path": f"{VAULT_MOUNT}/data/{vault_path}",
        "user":       caller["username"],
    }

# TEST CREDENTIALS
@router.post("/profile/credentials/test", response_model=CredentialTestResponse,
    summary="Test OpenStack application credentials",
    description=(
        "Attempts to list servers on OpenStack using the provided app credentials. "
        "Equivalent to running `openstack server list` on the CLI."),
)
async def test_openstack_credentials(body: CredentialTestRequest, 
                                     caller: dict = Depends(verify_session_token),):
    """
    Test OpenStack application credentials without storing them

    Flow:
      1. Build an OpenStack connection with the provided credentials.
      2. Call conn.compute.servers(), equivalent to *openstack server list*
      3. If it returns (even empty) credentials are valid.
      4. If it raises credentials are invalid or endpoint unreachable.
    """
    try:
        import openstack
        conn    = openstack.connect(
            auth_url=body.os_auth_url,
            auth_type="v3applicationcredential",
            application_credential_id=body.os_application_credential_id,
            application_credential_secret=body.os_application_credential_secret,
            region_name=body.os_region_name,
            interface=body.os_interface,
            identity_api_version=3,
        )
        servers = list(conn.compute.servers())
        #NOTE: now returns a printed message
        return CredentialTestResponse(
            success=True,
            message=f"Credentials are valid. {len(servers)} server(s) visible in region {body.os_region_name}.",
            server_count=len(servers),)

    except Exception as exc:
        return CredentialTestResponse(
            success=False,
            message="Could not authenticate to OpenStack, check credentials and auth_url.",
            detail=str(exc),
        )

@router.get("/profile/service_creds")
async def list_service_creds(caller: dict = Depends(verify_session_token)):
    return vault_list_service_creds(caller["sub"])

@router.get("/profile/service_creds/{name}")
async def read_service_creds(name: str, caller: dict = Depends(verify_session_token)):
    return vault_read_service_creds(caller["sub"], name)

@router.put("/profile/service_creds/{name}")
async def write_service_creds(name: str, body: dict, caller: dict = Depends(verify_session_token)):
    import re
    if not re.fullmatch(r"[A-Za-z0-9_-]+", name or ""):
        raise HTTPException(status_code=400,
            detail="Invalid name: only letters, digits, '_' and '-' (e.g. openstack_garr).")
    body = {k: v for k, v in body.items()
            if v not in (None, "") and k not in ("name", "service_type")}
    vault_write_service_creds(caller["sub"], name, body)   # KV2: ogni write = nuova versione
    return {"name": name, "saved": True}

@router.delete("/profile/service_creds/{name}")
async def delete_service_creds(name: str, caller: dict = Depends(verify_session_token)):
    vault_delete_service_creds(caller["sub"], name)
    return {"name": name, "deleted": True}


@router.get("/profile/ssh_key")
async def get_ssh_key(caller: dict = Depends(verify_session_token)):
    data = vault_read_global(caller["sub"])
    return {"ssh_key": data.get("ssh_key", "")}

@router.get("/profile/ssh_key/private")
async def get_ssh_private_key(caller: dict = Depends(verify_session_token)):
    data = vault_read_global(caller["sub"])
    if not data.get("ssh_private_key"):
        raise HTTPException(status_code=404, detail="No private key stored.")
    return {"ssh_private_key": data["ssh_private_key"]}

@router.put("/profile/ssh_key")
async def put_ssh_key(body: dict, caller: dict = Depends(verify_session_token)):
    fields = {k: v for k, v in body.items()
              if k in ("ssh_key", "ssh_private_key") and v}
    if not fields:
        raise HTTPException(status_code=400, detail="Nothing to store.")
    vault_write_credentials(caller["sub"], fields)   # merge-write sul path globale
    return {"saved": sorted(fields.keys())}

@router.delete("/profile/ssh_key")
async def delete_ssh_key(caller: dict = Depends(verify_session_token)):
    vault_strip_global_keys(caller["sub"], ["ssh_key", "ssh_private_key"])
    return {"deleted": True}
