"""
All Pydantic models used across the api.

Defines the data structure of everything that enters/exits from the API 
"""

from typing import Optional
from pydantic import BaseModel


class OIDCLoginRequest(BaseModel):
    """
    Only the aai token is needed.
    From idp.
    """
    oidc_token: str


class SessionTokenResponse(BaseModel):
    """
    If the token check is OK returns a JWT containing:
    """
    session_token: str
    token_type:    str = "bearer" # checks if the user has the correct permission
    expires_in:    int            # sec.
    user_info:     dict


class UserCredentials(BaseModel):
    """
    Provider credentials associated with the user
    Stored in Vault in secret/data/<sub>/credentials.
    OpenStack: app_credentials or aai_token.
    AWS: app_credentials
    """
    # NOTE: now no credentials is essential. Consider changing this logic
    # OpenStack
    ssh_private_key: Optional[str] = None
    openstack_ssh_key:               Optional[str] = None
    openstack_app_credential_id:     Optional[str] = None
    openstack_app_credential_secret: Optional[str] = None
    openstack_proxy_host:            Optional[str] = None
    openstack_auth_url:              Optional[str] = None
    openstack_region_name:           Optional[str] = None
    openstack_interface:             Optional[str] = None
    openstack_identity_api_version:  Optional[str] = None
    # AWS
    aws_ssh_key:    Optional[str] = None #NOTE:mmmm I already have one in openstack, change key name ecc
    aws_access_key: Optional[str] = None
    aws_secret_key: Optional[str] = None
    aws_bastion_ip: Optional[str] = None


class DeploymentRequest(BaseModel):
    """
    Full deployment configuration (deployment_info.json), matching the structure used by workers.
    The auth.aai_token field carries the OIDC token so that workers can exchange it for a keystone token
    token when they process the job.
    """
    deployment_uuid:   str    # NOTE: the dashboard needs to create a uuid for each job
    timestamp:         str
    description:       str    # NOTE: optional or mandatory? check teams
    auth:              dict   # { aai_token, sub, group }
    orchestrator:      dict   # target_provider, desired_orchestrator, endpoint
    selected_provider: str    # OpenStack | AWS
    service_type:      Optional[str] = "galaxy"
    cloud_providers:   dict
    credentials_name: Optional[str] = ""  # NOTE: remove here if no cred selection 


class JobResponse(BaseModel):
    job_id:          str
    queue_name:      str
    deployment_uuid: str
    status:          str
    message:         str


class StatusUpdateRequest(BaseModel):
    """
    Payload sent by the agent to update a deployment status.
    Only the agent (authenticated via mTLS client cert) can call PATCH /internal/...
    """
    status:        str
    status_reason: Optional[str] = None
    outputs:       Optional[str] = None


class LogLineRequest(BaseModel):
    """
    A single log line pushed by the agent.
    The API appends it to logs/orchestrator-{uuid}.log on the API VM.
    """
    level:   str   # INFO, ERROR, WARNING, ...
    message: str


class CredentialTestRequest(BaseModel):
    """
    Tests users app credential communicating with OpenStack.
    Object used in credential.py
    """
    os_auth_url:                      str
    os_application_credential_id:     str
    os_application_credential_secret: str
    os_region_name:                   str = "RegionOne"
    os_interface:                     str = "public"


class CredentialTestResponse(BaseModel):
    """
    Give back the check over the app credential validity, after
    the user requests the test on the Dashboard.
    """
    success:      bool
    message:      str
    server_count: int = 0
    detail:       str = ""

