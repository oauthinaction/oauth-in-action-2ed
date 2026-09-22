"""Small SQLite token store shared by the authorization and resource servers."""

from pathlib import Path
from typing import TypedDict

try:
    import sqlite3
except ModuleNotFoundError as error:
    if error.name != "_sqlite3":
        raise
    import pysqlite3 as sqlite3


DatabaseError = sqlite3.DatabaseError
DB_PATH = Path(__file__).resolve().parent / "database.sqlite3"
SQLITE_TIMEOUT_SECONDS = 5.0
SQLITE_BUSY_TIMEOUT_MS = int(SQLITE_TIMEOUT_SECONDS * 1000)


class AccessToken(TypedDict):
    access_token: str
    client_id: str
    scope: str


class RefreshToken(TypedDict):
    refresh_token: str
    client_id: str
    scope: str


def _connect() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH, timeout=SQLITE_TIMEOUT_SECONDS)
    connection.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}")
    connection.row_factory = sqlite3.Row
    return connection


def initialize_schema() -> None:
    """Create the token tables if they do not already exist."""
    with _connect() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS access_tokens (
                access_token TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                scope TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                refresh_token TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                scope TEXT NOT NULL
            );
            """
        )


def reset_schema() -> None:
    """Reset token data for a fresh authorization-server run."""
    with _connect() as connection:
        connection.executescript(
            """
            DROP TABLE IF EXISTS access_tokens;
            DROP TABLE IF EXISTS refresh_tokens;
            CREATE TABLE access_tokens (
                access_token TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                scope TEXT NOT NULL
            );
            CREATE TABLE refresh_tokens (
                refresh_token TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                scope TEXT NOT NULL
            );
            """
        )


def insert_refresh_token(refresh_token: str, client_id: str, scope: str) -> None:
    """Store a refresh token for later exchanges."""
    initialize_schema()
    with _connect() as connection:
        connection.execute(
            """INSERT INTO refresh_tokens (refresh_token, client_id, scope)
               VALUES (?, ?, ?)""",
            (refresh_token, client_id, scope),
        )


def find_refresh_token(refresh_token: str) -> RefreshToken | None:
    """Return a refresh-token record as a dictionary."""
    initialize_schema()
    with _connect() as connection:
        row = connection.execute(
            """SELECT refresh_token, client_id, scope FROM refresh_tokens
               WHERE refresh_token = ?""",
            (refresh_token,),
        ).fetchone()
    return RefreshToken(**dict(row)) if row else None


def insert_access_token(access_token: str, client_id: str, scope: str) -> None:
    """Store a non-expiring access token for resource-server validation."""
    initialize_schema()
    with _connect() as connection:
        connection.execute(
            """INSERT INTO access_tokens (access_token, client_id, scope)
               VALUES (?, ?, ?)""",
            (access_token, client_id, scope),
        )


def find_access_token(access_token: str) -> AccessToken | None:
    """Return an access-token record as a dictionary."""
    initialize_schema()
    with _connect() as connection:
        row = connection.execute(
            """SELECT access_token, client_id, scope FROM access_tokens
               WHERE access_token = ?""",
            (access_token,),
        ).fetchone()
    return AccessToken(**dict(row)) if row else None


def rotate_refresh_token(
    presented_refresh_token: str,
    new_access_token: str,
    new_refresh_token: str,
    client_id: str,
) -> RefreshToken | None:
    """Atomically consume a refresh token and persist its replacements."""
    initialize_schema()
    with _connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            """SELECT refresh_token, client_id, scope FROM refresh_tokens
               WHERE refresh_token = ? AND client_id = ?""",
            (presented_refresh_token, client_id),
        ).fetchone()
        if row is None:
            return None

        scope = row["scope"]
        connection.execute(
            "DELETE FROM refresh_tokens WHERE refresh_token = ?",
            (presented_refresh_token,),
        )
        connection.execute(
            """INSERT INTO access_tokens (access_token, client_id, scope)
               VALUES (?, ?, ?)""",
            (new_access_token, client_id, ""),
        )
        connection.execute(
            """INSERT INTO refresh_tokens (refresh_token, client_id, scope)
               VALUES (?, ?, ?)""",
            (new_refresh_token, client_id, scope),
        )

    return RefreshToken(
        refresh_token=new_refresh_token,
        client_id=client_id,
        scope=scope,
    )