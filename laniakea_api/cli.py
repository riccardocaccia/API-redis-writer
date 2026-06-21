"""
after pip install laniakea-api-server, the user can throw:
    laniakea-api
    laniakea-api --port 8000          # HTTP, no TLS (test)
    laniakea-api --port 8443 --ssl    # HTTPS con TLS
    laniakea-api --env /etc/laniakea/api.env
"""

import argparse
import os
import sys


def main():
    """
    Which option is accepted in the cli
    """
    parser = argparse.ArgumentParser(
        prog="laniakea-api",
        description="Laniakea Queue API server.",
    )
    
    parser.add_argument("--host",    default="0.0.0.0",  help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port",    default=8443, type=int, help="Bind port (default: 8443)")
    parser.add_argument("--env",     default=".env", metavar="FILE", help="Path to .env file")
    parser.add_argument("--ssl",     action="store_true", help="Enable TLS (requires SSL_KEYFILE and SSL_CERTFILE in .env)")
    #FIXME: reload to be mantained? 
    parser.add_argument("--reload",  action="store_true", help="Enable auto-reload (development only)")
    parser.add_argument("--version", action="store_true", help="Print version and exit.")
    args = parser.parse_args()

    if args.version:
        from laniakea_api import __version__
        print(f"laniakea-api {__version__}")
        sys.exit(0)

    # load .env
    # NOTE: if .env not specified local ambient variable are used
    env_path = os.path.abspath(args.env)
    if os.path.exists(env_path):
        from dotenv import load_dotenv
        load_dotenv(env_path)
        print(f"[config] loaded {env_path}")
    else:
        print(f"[config] .env not found at {env_path}... using environment variables")

    # validate required env vars
    # NOTE: Check if all required vars
    required = [
        "SECRET_KEY", "AGENT_MASTER_PASSWORD",
        "REDIS_HOST", "REDIS_PASSWORD",
        "OIDC_DISCOVERY_URL",
        "PG_HOST", "PG_DATABASE", "PG_USER", "PG_PASSWORD",
        "VAULT_ADDR", "VAULT_WRITER_TOKEN",
    ]
    missing = [v for v in required if not os.getenv(v)]
    if missing:
        print(f"[error] missing required variables: {', '.join(missing)}")
        sys.exit(1)

    # FIXME: check if the destination for this dir is ok
    # create a log dir
    log_dir = os.getenv("DEPLOYMENT_LOG_DIR", "/var/log/laniakea-agent")
    os.makedirs(log_dir, exist_ok=True)

    import uvicorn

    uvicorn_kwargs = dict(
        app="laniakea_api.main:app",  # App instance in the main file
        host=args.host,
        port=args.port,
        log_level="info",
        reload=args.reload,           # NOTE: To be removed if argparse removed
    )

    if args.ssl:
        # if ssl option specified searches for SSL certificates and private key
        ssl_key  = os.getenv("SSL_KEYFILE",  "certs/api.key")
        ssl_cert = os.getenv("SSL_CERTFILE", "certs/api.crt")
        if not os.path.exists(ssl_key) or not os.path.exists(ssl_cert):
            print(f"[error] TLS enabled but cert files not found: {ssl_key}, {ssl_cert}")
            sys.exit(1)
        uvicorn_kwargs["ssl_keyfile"]  = ssl_key
        uvicorn_kwargs["ssl_certfile"] = ssl_cert
        print(f"[api] HTTPS on {args.host}:{args.port}")
    else:
        print(f"[api] HTTP on {args.host}:{args.port} (no TLS)")

    # Starting the application
    uvicorn.run(**uvicorn_kwargs)


if __name__ == "__main__":
    main()

