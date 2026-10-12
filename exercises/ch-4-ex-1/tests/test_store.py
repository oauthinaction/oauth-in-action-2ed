import pytest


def test_token_pair_insert_is_atomic_when_refresh_insert_fails(oauth_store):
    oauth_store.insert_refresh_token("duplicate-refresh", "existing-client", "old")

    with pytest.raises(oauth_store.DatabaseError):
        oauth_store.issue_token_pair(
            "must-roll-back",
            "duplicate-refresh",
            "oauth-client-1",
            "",
        )

    assert oauth_store.find_access_token("must-roll-back") is None
    assert oauth_store.find_refresh_token("duplicate-refresh") == {
        "refresh_token": "duplicate-refresh",
        "client_id": "existing-client",
        "scope": "old",
    }


def test_refresh_rotation_is_client_bound_atomic_and_preserves_scope(oauth_store):
    oauth_store.issue_token_pair(
        "access-1", "refresh-1", "oauth-client-1", "read write"
    )

    wrong_client = oauth_store.rotate_refresh_token(
        "refresh-1", "wrong-access", "wrong-refresh", "other-client"
    )
    assert wrong_client is None
    assert oauth_store.find_refresh_token("refresh-1") is not None
    assert oauth_store.find_access_token("wrong-access") is None

    rotated = oauth_store.rotate_refresh_token(
        "refresh-1", "access-2", "refresh-2", "oauth-client-1"
    )
    assert rotated == {
        "refresh_token": "refresh-2",
        "client_id": "oauth-client-1",
        "scope": "read write",
    }
    assert oauth_store.find_refresh_token("refresh-1") is None
    assert oauth_store.find_refresh_token("refresh-2") == rotated
    assert oauth_store.find_access_token("access-2")["scope"] == "read write"
    assert oauth_store.find_access_token("access-1") is not None


def test_refresh_rotation_rolls_back_consumption_on_replacement_collision(oauth_store):
    oauth_store.issue_token_pair("access-1", "refresh-1", "oauth-client-1", "")
    oauth_store.insert_access_token("duplicate-access", "another-client", "")

    with pytest.raises(oauth_store.DatabaseError):
        oauth_store.rotate_refresh_token(
            "refresh-1",
            "duplicate-access",
            "refresh-2",
            "oauth-client-1",
        )

    assert oauth_store.find_refresh_token("refresh-1") is not None
    assert oauth_store.find_refresh_token("refresh-2") is None
