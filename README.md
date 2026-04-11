# Laniakea Queue API

FastAPI service that authenticates callers via OIDC and enqueues deployment
jobs on a Redis queue for downstream workers to consume.

---

## Architecture

```
Caller (dashboard / script)
        │
        │  1. POST /auth/oidc  { oidc_token }
        ▼
┌──────────────────────────┐
│   Laniakea Queue API     │
│  - verifies token with   │
│    OIDC provider userinfo│
│  - issues JWT session    │
│    token (60 min)        │
└────────────┬─────────────┘
             │  2. POST /api/deployments  (Bearer session_token)
             ▼
┌────────────────────────┐
│      Redis Queues      │
│   openstack  |  aws    │
└────────────┬───────────┘
             │  3. job pop
             ▼
┌────────────────────────┐
│       Workers          │
│  consume job_data,     │
│  exchange aai_token    │
│  for Keystone token,   │
│  run deployment        │
└────────────────────────┘
```

---

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `POST` | `/auth/oidc` | — | Exchange OIDC token for session JWT |
| `POST` | `/api/deployments` | Bearer | Enqueue a deployment job |
| `GET`  | `/api/deployments/{job_id}` | Bearer | Poll job status |
| `GET`  | `/health` | — | Redis connectivity check |

---

## Authentication flow

```
1.  Caller obtains an OIDC access token from the identity provider
    (e.g. RecaCAS / iam.recas.ba.infn.it).

2.  POST /auth/oidc
    Body: { "oidc_token": "<access_token>" }

    The API hits the provider's userinfo endpoint to verify the token,
    then mints a signed JWT session token (HS256, valid SESSION_TTL_MINUTES).

3.  All subsequent requests carry:
    Authorization: Bearer <session_token>
```

---

## Enqueue a deployment

```bash
TOKEN="<session_token>"

curl -X POST http://localhost:8000/api/deployments \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "deployment_uuid": "deploy-001",
    "timestamp": "2026-03-31T12:00:00Z",
    "description": "My deployment",
    "auth": {
      "aai_token": "<oidc_access_token>",
      "sub": "user-id",
      "group": "admin"
    },
    "orchestrator": {
      "target_provider": "openstack",
      "desired_orchestrator": "terraform",
      "endpoint": "https://terraform.example.com"
    },
    "selected_provider": "Openstack",
    "cloud_providers": {
      "openstack": { ... },
      "aws": { ... }
    }
  }'
```

Response:
```json
{
  "job_id": "abc123",
  "queue_name": "openstack",
  "deployment_uuid": "deploy-001",
  "status": "queued",
  "message": "Job enqueued on 'openstack' queue."
}
```

The full deployment dict (including `auth.aai_token`) is stored verbatim as
the job argument. Workers receive it as-is and can exchange `aai_token` for a
Keystone token at execution time.

---

## Configuration

All settings can be overridden via environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `SECRET_KEY` | `change-me-in-production` | HS256 signing key for session JWTs |
| `SESSION_TTL_MINUTES` | `60` | Session token lifetime |
| `OIDC_DISCOVERY_URL` | RecaCAS discovery URL | OIDC provider discovery document |
| `REDIS_HOST` | `212.189.205.167` | Redis host |
| `REDIS_PORT` | `6379` | Redis port |
| `REDIS_PASSWORD` | `admin` | Redis password |

---

## Installation

```bash
pip install -r requirements.txt
python api_queue.py
```

### systemd unit (production)

```ini
[Unit]
Description=Laniakea Queue API
After=network.target redis-server.service

[Service]
User=ubuntu
WorkingDirectory=/opt/laniakea-api
EnvironmentFile=/opt/laniakea-api/.env
ExecStart=/usr/bin/python3 /opt/laniakea-api/api_queue.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

---

## Security notes

- **Protect Redis** — the full deployment payload (including the OIDC token)
  is stored in Redis. Restrict access with a firewall and a strong password.
- **Use HTTPS** in production so session tokens are not exposed in transit.
- **Rotate `SECRET_KEY`** — invalidates all existing session tokens; users
  must re-authenticate.

