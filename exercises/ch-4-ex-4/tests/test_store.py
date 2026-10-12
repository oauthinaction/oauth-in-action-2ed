def table_columns(oauth_store, table):
    with oauth_store._connect() as connection:
        return [dict(row) for row in connection.execute(f"PRAGMA table_info({table})")]


def test_reset_schema_creates_owner_aware_empty_tables(oauth_store):
    oauth_store.insert_access_token("discard-me", "client", "movies", "alice")
    oauth_store.insert_refresh_token("discard-refresh", "client", "movies", "alice")
    oauth_store.reset_schema()

    for table, token_column in (
        ("access_tokens", "access_token"),
        ("refresh_tokens", "refresh_token"),
    ):
        columns = table_columns(oauth_store, table)
        assert [column["name"] for column in columns] == [
            token_column,
            "client_id",
            "scope",
            "resource_owner",
        ]
        assert columns[0]["pk"] == 1
        assert all(column["notnull"] == 1 for column in columns[1:])
        with oauth_store._connect() as connection:
            assert connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0] == 0


def test_initialize_schema_migrates_legacy_rows_without_discarding_them(oauth_store):
    with oauth_store._connect() as connection:
        connection.executescript(
            """
            DROP TABLE access_tokens;
            DROP TABLE refresh_tokens;
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
            INSERT INTO access_tokens VALUES ('legacy-access', 'legacy-client', 'movies');
            INSERT INTO refresh_tokens VALUES ('legacy-refresh', 'legacy-client', 'foods');
            """
        )

    oauth_store.initialize_schema()
    assert oauth_store.find_access_token("legacy-access") == {
        "access_token": "legacy-access",
        "client_id": "legacy-client",
        "scope": "movies",
        "resource_owner": "",
    }
    assert oauth_store.find_refresh_token("legacy-refresh") == {
        "refresh_token": "legacy-refresh",
        "client_id": "legacy-client",
        "scope": "foods",
        "resource_owner": "",
    }


def test_issue_pair_persists_matching_scope_and_owner(oauth_store):
    oauth_store.issue_token_pair(
        "paired-access", "paired-refresh", "client", "music foods", "bob"
    )
    access = oauth_store.find_access_token("paired-access")
    refresh = oauth_store.find_refresh_token("paired-refresh")
    assert access == {
        "access_token": "paired-access",
        "client_id": "client",
        "scope": "music foods",
        "resource_owner": "bob",
    }
    assert refresh == {
        "refresh_token": "paired-refresh",
        "client_id": "client",
        "scope": "music foods",
        "resource_owner": "bob",
    }


def test_rotation_preserves_scope_owner_and_rejects_wrong_client_and_replay(oauth_store):
    oauth_store.issue_token_pair(
        "first-access", "first-refresh", "client", "foods music", "alice"
    )
    assert (
        oauth_store.rotate_refresh_token(
            "first-refresh", "wrong-access", "wrong-refresh", "other-client"
        )
        is None
    )
    assert oauth_store.find_refresh_token("first-refresh") is not None

    rotated = oauth_store.rotate_refresh_token(
        "first-refresh", "second-access", "second-refresh", "client"
    )
    assert rotated == {
        "refresh_token": "second-refresh",
        "client_id": "client",
        "scope": "foods music",
        "resource_owner": "alice",
    }
    assert oauth_store.find_refresh_token("first-refresh") is None
    assert oauth_store.find_access_token("second-access")["resource_owner"] == "alice"
    assert oauth_store.find_access_token("second-access")["scope"] == "foods music"
    assert oauth_store.rotate_refresh_token(
        "first-refresh", "third-access", "third-refresh", "client"
    ) is None
    assert oauth_store.find_access_token("third-access") is None
