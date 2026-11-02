"""Small SQLite token store shared by authorization and resource servers."""

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


class RefreshToken(TypedDict):
    refresh_token: str
    client_id: str


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
                client_id TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS refresh_tokens (
                refresh_token TEXT PRIMARY KEY,
                client_id TEXT NOT NULL
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
                client_id TEXT NOT NULL
            );
            CREATE TABLE refresh_tokens (
                refresh_token TEXT PRIMARY KEY,
                client_id TEXT NOT NULL
            );
            """
        )


def seed_refresh_token(refresh_token: str, client_id: str) -> None:
    """Insert or replace a refresh token used by an exercise."""
    initialize_schema()
    with _connect() as connection:
        connection.execute(
            """INSERT OR REPLACE INTO refresh_tokens
               (refresh_token, client_id) VALUES (?, ?)""",
            (refresh_token, client_id),
        )


def find_refresh_token(refresh_token: str) -> RefreshToken | None:
    """Return a refresh-token record as a dictionary."""
    initialize_schema()
    with _connect() as connection:
        row = connection.execute(
            """SELECT refresh_token, client_id FROM refresh_tokens
               WHERE refresh_token = ?""",
            (refresh_token,),
        ).fetchone()
    return RefreshToken(**dict(row)) if row else None


def insert_access_token(access_token: str, client_id: str) -> None:
    """Store an access token for resource-server validation."""
    initialize_schema()
    with _connect() as connection:
        connection.execute(
            """INSERT INTO access_tokens (access_token, client_id)
               VALUES (?, ?)""",
            (access_token, client_id),
        )


def find_access_token(access_token: str) -> AccessToken | None:
    """Return an access-token record as a dictionary."""
    initialize_schema()
    with _connect() as connection:
        row = connection.execute(
            """SELECT access_token, client_id FROM access_tokens
               WHERE access_token = ?""",
            (access_token,),
        ).fetchone()
    return AccessToken(**dict(row)) if row else None
