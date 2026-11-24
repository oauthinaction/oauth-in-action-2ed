def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def seed_access(oauth_store, token, owner, scope="movies foods music"):
    oauth_store.insert_access_token(token, "oauth-client-1", scope, owner)


def test_strict_bearer_and_exact_lookup_errors(resource_http, oauth_store):
    seed_access(oauth_store, "known-token", "alice")

    lowercase_name_and_scheme = resource_http.get(
        "/favorites",
        headers={"authorization": "bEaReR known-token"},
    )
    assert lowercase_name_and_scheme.status_code == 200

    for headers, query in (
        ({}, {}),
        (bearer("unknown-token"), {}),
        ({"Authorization": "Basic known-token"}, {}),
        ({"Authorization": "Bearer"}, {"access_token": "known-token"}),
        (
            {"Authorization": "Bearer known-token extra"},
            {"access_token": "known-token"},
        ),
    ):
        response = resource_http.get(
            "/favorites", headers=headers, query_string=query
        )
        assert response.status_code == 401
        assert response.get_json() == {"error": "invalid_token"}
        assert response.headers["WWW-Authenticate"] == (
            'Bearer realm="protected-resource"'
        )

    query_only = resource_http.get(
        "/favorites",
        query_string={"access_token": "known-token"},
    )
    assert query_only.status_code == 401
    assert query_only.get_json() == {"error": "invalid_token"}
    assert query_only.headers["WWW-Authenticate"] == (
        'Bearer realm="protected-resource"'
    )


def test_root_learner_owner_selection_returns_exact_alice_and_bob_fixtures(
    resource_http, oauth_store, protected_resource
):
    """One grouped milestone: the untouched starter fails only this test."""
    expected = {
        "alice": {
            "user": "Alice",
            "favorites": {
                "movies": [
                    "The Multidimensional Vector",
                    "Space Fights",
                    "Jewelry Boss",
                ],
                "foods": ["bacon", "pizza", "bacon pizza"],
                "music": ["techno", "industrial", "alternative"],
            },
        },
        "bob": {
            "user": "Bob",
            "favorites": {
                "movies": [
                    "An Unrequited Love",
                    "Several Shades of Turquoise",
                    "Think Of The Children",
                ],
                "foods": ["bacon", "kale", "gravel"],
                "music": ["baroque", "ukulele", "baroque ukulele"],
            },
        },
    }
    assert expected["alice"] == protected_resource.ALICE_FAVORITES
    assert expected["bob"] == protected_resource.BOB_FAVORITES
    for owner, fixture in expected.items():
        token = f"{owner}-access"
        seed_access(oauth_store, token, owner)
        response = resource_http.get("/favorites", headers=bearer(token))
        assert response.status_code == 200
        assert response.get_json() == fixture, (
            "Select the exact Favorites fixture from the validated "
            "access_record['resource_owner']; never trust request input"
        )

        other_owner = "bob" if owner == "alice" else "alice"
        spoofed = resource_http.get(
            "/favorites",
            headers={**bearer(token), "X-Resource-Owner": other_owner},
            query_string={"resource_owner": other_owner},
        )
        assert spoofed.get_json() == fixture, (
            "Favorites must use only the owner persisted on the validated "
            "token"
        )


def test_unknown_persisted_owner_has_explicit_empty_result(
    resource_http, oauth_store
):
    seed_access(oauth_store, "unknown-owner-token", "mallory")
    response = resource_http.get(
        "/favorites", headers=bearer("unknown-owner-token")
    )
    assert response.status_code == 200
    assert response.get_json() == {
        "user": "Unknown",
        "favorites": {"movies": [], "foods": [], "music": []},
    }


def test_owner_responses_are_200_without_scope_filtering_or_spoofing(
    resource_http, oauth_store
):
    for owner, scope, spoofed_owner in (
        ("alice", "", "bob"),
        ("bob", "foods", "alice"),
    ):
        token = f"valid-{owner}"
        seed_access(oauth_store, token, owner, scope)
        response = resource_http.get(
            "/favorites",
            headers={**bearer(token), "X-Resource-Owner": spoofed_owner},
            query_string={"resource_owner": spoofed_owner},
        )
        assert response.status_code == 200
        body = response.get_json()
        assert set(body["favorites"]) == {"movies", "foods", "music"}
        # Empty/narrow scope must not remove categories in this exercise.
        assert all(
            isinstance(body["favorites"][key], list)
            for key in body["favorites"]
        )


def test_resource_database_failure_is_a_retryable_503(
    monkeypatch, resource_http, protected_resource, oauth_store
):
    def fail(token):
        raise oauth_store.DatabaseError("database unavailable")

    monkeypatch.setattr(protected_resource, "find_access_token", fail)
    response = resource_http.get("/favorites", headers=bearer("any-token"))
    assert response.status_code == 503
    assert response.get_json() == {"error": "temporarily_unavailable"}
    assert response.headers["Retry-After"] == "1"


def test_favorites_fails_closed_when_validator_returns_no_record_or_error(
    monkeypatch,
    resource_http,
    protected_resource,
):
    monkeypatch.setattr(
        protected_resource,
        "validated_access_record",
        lambda: (None, None),
    )
    response = resource_http.get("/favorites")
    assert response.status_code == 401
    assert response.get_json() == {"error": "invalid_token"}
    assert response.headers["WWW-Authenticate"] == (
        'Bearer realm="protected-resource"'
    )
