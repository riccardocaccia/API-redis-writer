"""
User credential management.

POST /auth/oidc
POST /profile/credentials
POST /profile/credentials/test
"""

from fastapi import APIRouter, Depends, HTTPException, status
from auth import fetch_userinfo, create_session_token, verify_session_token
from models import (OIDCLoginRequest, SessionTokenResponse,UserCredentials,
                    CredentialTestRequest, CredentialTestResponse,)
from queue import vault_write_credentials, VAULT_MOUNT

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

