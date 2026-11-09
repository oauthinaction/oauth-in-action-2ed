"""SQLite token store for Chapter 4 Exercise 4."""

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
    resource_owner: str


class RefreshToken(TypedDict):
    refresh_token: str
    client_id: str
    scope: str
    resource_owner: str


def _connect() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH, timeout=SQLITE_TIMEOUT_SECONDS)
    connection.execute(f"PRAGMA busy_timeout = {SQLITE_BUSY_TIMEOUT_MS}")
    connection.row_factory = sqlite3.Row
    return connection


def _add_owner_column_if_missing(
    connection: sqlite3.Connection, table_name: str
) -> None:
    """Upgrade a legacy exercise table without discarding its token rows."""
    columns = {
        row["name"]
        for row in connection.execute(f"PRAGMA table_info({table_name})")
    }
    if "resource_owner" not in columns:
        connection.execute(
            f"ALTER TABLE {table_name} "
            "ADD COLUMN resource_owner TEXT NOT NULL DEFAULT ''"
        )


def initialize_schema() -> None:
    """Create token tables and upgrade owner-unaware legacy exercise tables."""
    with _connect() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS access_tokens (
                access_token TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                scope TEXT NOT NULL,
                resource_owner TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                refresh_token TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                scope TEXT NOT NULL,
                resource_owner TEXT NOT NULL
            );
            """
        )
        _add_owner_column_if_missing(connection, "access_tokens")
        _add_owner_column_if_missing(connection, "refresh_tokens")


def reset_schema() -> None:
    """Deterministically reset token data with owner-aware tables."""
    with _connect() as connection:
        connection.executescript(
            """
            DROP TABLE IF EXISTS access_tokens;
            DROP TABLE IF EXISTS refresh_tokens;
            CREATE TABLE access_tokens (
                access_token TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                scope TEXT NOT NULL,
                resource_owner TEXT NOT NULL
            );
            CREATE TABLE refresh_tokens (
                refresh_token TEXT PRIMARY KEY,
                client_id TEXT NOT NULL,
                scope TEXT NOT NULL,
                resource_owner TEXT NOT NULL
            );
            """
        )


def insert_refresh_token(
    refresh_token: str,
    client_id: str,
    scope: str,
    resource_owner: str,
) -> None:
    """Store a refresh token and its validated resource owner."""
    initialize_schema()
    with _connect() as connection:
        connection.execute(
            """INSERT INTO refresh_tokens
                   (refresh_token, client_id, scope, resource_owner)
               VALUES (?, ?, ?, ?)""",
            (refresh_token, client_id, scope, resource_owner),
        )


def find_refresh_token(refresh_token: str) -> RefreshToken | None:
    """Return a refresh-token record as a dictionary."""
    initialize_schema()
    with _connect() as connection:
        row = connection.execute(
            """SELECT refresh_token, client_id, scope, resource_owner
               FROM refresh_tokens WHERE refresh_token = ?""",
            (refresh_token,),
        ).fetchone()
    return RefreshToken(**dict(row)) if row else None


def insert_access_token(
    access_token: str,
    client_id: str,
    scope: str,
    resource_owner: str,
) -> None:
    """Store a non-expiring access token with its validated owner."""
    initialize_schema()
    with _connect() as connection:
        connection.execute(
            """INSERT INTO access_tokens
                   (access_token, client_id, scope, resource_owner)
               VALUES (?, ?, ?, ?)""",
            (access_token, client_id, scope, resource_owner),
        )


def find_access_token(access_token: str) -> AccessToken | None:
    """Return the access-token record whose value matches exactly."""
    initialize_schema()
    with _connect() as connection:
        row = connection.execute(
            """SELECT access_token, client_id, scope, resource_owner
               FROM access_tokens WHERE access_token = ?""",
            (access_token,),
        ).fetchone()
    return AccessToken(**dict(row)) if row else None


def issue_token_pair(
    access_token: str,
    refresh_token: str,
    client_id: str,
    scope: str,
    resource_owner: str,
) -> None:
    """Atomically persist an owner-bound access/refresh token pair."""
    initialize_schema()
    with _connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            """INSERT INTO access_tokens
                   (access_token, client_id, scope, resource_owner)
               VALUES (?, ?, ?, ?)""",
            (access_token, client_id, scope, resource_owner),
        )
        connection.execute(
            """INSERT INTO refresh_tokens
                   (refresh_token, client_id, scope, resource_owner)
               VALUES (?, ?, ?, ?)""",
            (refresh_token, client_id, scope, resource_owner),
        )


def rotate_refresh_token(
    presented_refresh_token: str,
    new_access_token: str,
    new_refresh_token: str,
    client_id: str,
) -> RefreshToken | None:
    """Atomically rotate a pair while preserving stored scope and owner."""
    initialize_schema()
    with _connect() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            """SELECT refresh_token, client_id, scope, resource_owner
               FROM refresh_tokens
               WHERE refresh_token = ? AND client_id = ?""",
            (presented_refresh_token, client_id),
        ).fetchone()
        if row is None:
            return None

        scope = row["scope"]
        resource_owner = row["resource_owner"]
        connection.execute(
            "DELETE FROM refresh_tokens WHERE refresh_token = ?",
            (presented_refresh_token,),
        )
        connection.execute(
            """INSERT INTO access_tokens
                   (access_token, client_id, scope, resource_owner)
               VALUES (?, ?, ?, ?)""",
            (new_access_token, client_id, scope, resource_owner),
        )
        connection.execute(
            """INSERT INTO refresh_tokens
                   (refresh_token, client_id, scope, resource_owner)
               VALUES (?, ?, ?, ?)""",
            (new_refresh_token, client_id, scope, resource_owner),
        )

    return RefreshToken(
        refresh_token=new_refresh_token,
        client_id=client_id,
        scope=scope,
        resource_owner=resource_owner,
    )
