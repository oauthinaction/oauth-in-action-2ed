import pytest


def test_schema_has_exact_token_tables_and_required_columns(oauth_store):
    with oauth_store._connect() as connection:
        tables = {
            row["name"]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            )
        }
        access_columns = {
            row["name"]: row
            for row in connection.execute("PRAGMA table_info(access_tokens)")
        }
        refresh_columns = {
            row["name"]: row
            for row in connection.execute("PRAGMA table_info(refresh_tokens)")
        }
    assert tables == {"access_tokens", "refresh_tokens"}
    assert set(access_columns) == {"access_token", "client_id", "scope"}
    assert set(refresh_columns) == {"refresh_token", "client_id", "scope"}
    assert access_columns["access_token"]["pk"] == 1
    assert refresh_columns["refresh_token"]["pk"] == 1
    assert all(access_columns[name]["notnull"] for name in ("client_id", "scope"))
    assert all(refresh_columns[name]["notnull"] for name in ("client_id", "scope"))


def test_insert_and_find_tokens_are_exact_and_return_records(oauth_store):
    oauth_store.insert_access_token("access-token", "client-a", "read write")
    oauth_store.insert_refresh_token("refresh-token", "client-a", "read write")
    assert oauth_store.find_access_token("access-token") == {
        "access_token": "access-token",
        "client_id": "client-a",
        "scope": "read write",
    }
    assert oauth_store.find_refresh_token("refresh-token") == {
        "refresh_token": "refresh-token",
        "client_id": "client-a",
        "scope": "read write",
    }
    assert oauth_store.find_access_token("access") is None
    assert oauth_store.find_refresh_token("refresh") is None


def test_issue_token_pair_is_atomic_on_refresh_collision(oauth_store):
    oauth_store.insert_refresh_token("collision", "client-a", "read")
    with pytest.raises(oauth_store.DatabaseError):
        oauth_store.issue_token_pair(
            "orphan-must-rollback", "collision", "client-a", "write"
        )
    assert oauth_store.find_access_token("orphan-must-rollback") is None
    assert oauth_store.find_refresh_token("collision")["scope"] == "read"


def test_refresh_rotation_preserves_scope_and_rejects_wrong_client(oauth_store):
    oauth_store.insert_refresh_token("old-refresh", "client-a", "read delete")
    assert oauth_store.rotate_refresh_token(
        "old-refresh", "wrong-access", "wrong-refresh", "client-b"
    ) is None
    rotated = oauth_store.rotate_refresh_token(
        "old-refresh", "new-access", "new-refresh", "client-a"
    )
    assert rotated == {
        "refresh_token": "new-refresh",
        "client_id": "client-a",
        "scope": "read delete",
    }
    assert oauth_store.find_refresh_token("old-refresh") is None
    assert oauth_store.find_access_token("new-access")["scope"] == "read delete"
    assert oauth_store.find_refresh_token("new-refresh")["scope"] == "read delete"


def test_refresh_rotation_rolls_back_consumption_on_collision(oauth_store):
    oauth_store.insert_refresh_token("old-refresh", "client-a", "read")
    oauth_store.insert_access_token("collision", "client-a", "other")
    with pytest.raises(oauth_store.DatabaseError):
        oauth_store.rotate_refresh_token(
            "old-refresh", "collision", "replacement-refresh", "client-a"
        )
    assert oauth_store.find_refresh_token("old-refresh")["scope"] == "read"
    assert oauth_store.find_refresh_token("replacement-refresh") is None
