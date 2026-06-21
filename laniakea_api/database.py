"""
PostgreSQL connection.
The agent has NO direct DB access:
                  **all writes go through the API**
The Dashboard is stateless.
"""

import os
from datetime import datetime
from typing import Optional
import psycopg2
from psycopg2.extras import RealDictCursor
from laniakea_api.config import PG_HOST, PG_PORT, PG_DATABASE, PG_USER, PG_PASSWORD


def get_conn():
    """
    Open and return a new PostgreSQL connection.
    """
    # act over config.py before changing here
    return psycopg2.connect(
        host=PG_HOST,
        port=PG_PORT,
        database=PG_DATABASE,
        user=PG_USER,
        password=PG_PASSWORD,
    )

def create_deployment(
    uuid: str, user_sub: str, username: str, description: str, provider: str, requested_at: datetime,
    ) -> None:
    """
    Insert a new deployment row with status QUEUED.
    Called by the API the moment a job is accepted, 
    (db before redis)
    """
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            # If the user making the request doesn't yet exist in the local database, it inserts them. 
            #if they already exist (subprimary key conflict), it does nothing.
            cur.execute(
                """
                INSERT INTO users (sub, username, email, role, active)
                VALUES (%s, %s, %s, 'user', true)
                ON CONFLICT (sub) DO NOTHING
                """,
                (user_sub, username, ""),
            )
            #Create a row in the deployments table with the initial state set to "QUEUED." 
            # if, by chance, that UUID already exists, simply update the state and date.
            cur.execute(
                """
                INSERT INTO deployments (
                    uuid, status, creation_time, update_time,
                    description, provider_name, sub
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (uuid) DO UPDATE
                    SET status      = EXCLUDED.status,
                        update_time = EXCLUDED.update_time
                """,
                (uuid, "QUEUED", requested_at, requested_at, description, provider, user_sub),
            )
        conn.commit()
    finally:
        conn.close()

def update_status(
    uuid: str, new_status: str, status_reason: Optional[str] = None, outputs: Optional[str] = None,
    ) -> bool:
    """
    Update the status of an existing deployment.
    Returns True if a row was updated, False if uuid not found.
    """
    conn = get_conn()
    try:
        with conn.cursor() as cur:
            # COALESCE causes the database to keep old value already present 
            # without overwriting them with an empty value.
            cur.execute(
                """
                UPDATE deployments
                SET status        = %s,
                    status_reason = COALESCE(%s, status_reason),
                    outputs       = COALESCE(%s, outputs),
                    update_time   = %s
                WHERE uuid = %s
                """,
                (new_status, status_reason, outputs, datetime.utcnow(), uuid),
            )
            updated = cur.rowcount > 0
        conn.commit()
        return updated
    finally:
        conn.close()

def get_deployment(uuid: str) -> Optional[dict]:
    """
    Fetch a single deployment row by uuid. Returns None if not found.
    """
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT * FROM deployments WHERE uuid = %s", (uuid,))
            row = cur.fetchone()
            return dict(row) if row else None
    finally:
        conn.close()

def list_deployments(user_sub: str) -> list:
    """
    Fetch all deployments owned by a user, ordered by creation time desc.
    """
    conn = get_conn()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute(
                "SELECT * FROM deployments WHERE sub = %s ORDER BY creation_time DESC",
                (user_sub,),
            )
            return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()

def check_connection() -> str:
    """
    Returns 'connected' or an error string. 
    Used by /health.
    """
    try:
        conn = get_conn()
        conn.close()
        return "connected"
    except Exception as exc:
        return f"error: {exc}"

