# laniakea-api-server

Laniakea Queue API — OIDC-authenticated gateway for cloud deployment orchestration.

## Installation

```bash
pip install laniakea-api-server
```

## Configuration

Create a `.env` file:

```bash
# Auth
SECRET_KEY=generate-with-python3-secrets-token-hex-32
SESSION_TTL_MINUTES=60
OIDC_DISCOVERY_URL=https://iam.your-provider.it/.well-known/openid-configuration

# Agent pool password
AGENT_MASTER_PASSWORD=generate-with-python3-secrets-token-hex-32

# Redis
REDIS_HOST=your-redis-host
REDIS_PORT=6379
REDIS_PASSWORD=your-redis-password

# PostgreSQL
PG_HOST=your-pg-host
PG_PORT=5432
PG_DATABASE=your-db-name
PG_USER=your-db-user
PG_PASSWORD=your-db-password

# Vault
VAULT_ADDR=https://your-vault:8200
VAULT_WRITER_TOKEN=hvs.xxxxxxxxxxxx
VAULT_TLS_VERIFY=false

# TLS (only needed with --ssl flag)
SSL_KEYFILE=certs/api.key
SSL_CERTFILE=certs/api.crt

# Logs
DEPLOYMENT_LOG_DIR=/var/log/laniakea-agent
```

## Usage

```bash
# HTTP (testing)
laniakea-api --port 8000

# HTTPS (production)
laniakea-api --port 8443 --ssl

# Custom env file
laniakea-api --env /etc/laniakea/api.env --ssl
```

