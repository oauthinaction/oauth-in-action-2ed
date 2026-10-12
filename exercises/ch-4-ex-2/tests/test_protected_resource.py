from unittest.mock import Mock

import pytest


CLIENT_ID = "oauth-client-1"


def issue_access(oauth_store, token="access-1", scope="read write delete"):
    oauth_store.insert_access_token(token, CLIENT_ID, scope)
    return token


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def test_validated_access_record_returns_record_and_structured_errors(
    protected_resource,
    oauth_store,
    monkeypatch,
):
    token = "MiXeD-validation-token"
    expected_record = {
        "access_token": token,
        "client_id": CLIENT_ID,
        "scope": "read write delete",
    }
    oauth_store.insert_access_token(token, CLIENT_ID, "read write delete")

    with protected_resource.app.test_request_context(
        "/words",
        headers={"authorization": f"bEaReR {token}"},
    ):
        access_record, authentication_error = (
            protected_resource.validated_access_record()
        )
    assert authentication_error is None and access_record == expected_record, (
        "Inherited Exercise 1 contract: validated_access_record() must return "
        "the exact stored record and no error for a valid, case-sensitive "
        "access token"
    )

    with protected_resource.app.test_request_context(
        "/words",
        headers=bearer("unknown-token"),
    ):
        access_record, authentication_error = (
            protected_resource.validated_access_record()
        )
        assert access_record is None
        response, status = authentication_error
        assert status == 401
        assert response.get_json() == {"error": "invalid_token"}
        assert response.headers["WWW-Authenticate"] == (
            'Bearer realm="protected-resource"'
        )

    def fail_lookup(_token):
        raise protected_resource.DatabaseError("database unavailable")

    monkeypatch.setattr(protected_resource, "find_access_token", fail_lookup)
    with protected_resource.app.test_request_context(
        "/words",
        headers=bearer("database-token"),
    ):
        access_record, authentication_error = (
            protected_resource.validated_access_record()
        )
        assert access_record is None
        response, status = authentication_error
        assert status == 503
        assert response.get_json() == {"error": "temporarily_unavailable"}
        assert response.headers["Retry-After"] == "1"


def test_words_routes_apply_inherited_access_validation(resource_http):
    responses = {
        "GET": resource_http.get("/words"),
        "POST": resource_http.post("/words"),
        "DELETE": resource_http.delete("/words"),
    }
    actual_statuses = {
        method: response.status_code for method, response in responses.items()
    }
    assert actual_statuses == {"GET": 401, "POST": 401, "DELETE": 401}, (
        "Inherited Exercise 1 contract: every /words route must call "
        "validated_access_record(), return authentication_error when present, "
        f"and continue only with a non-None access_record; got {actual_statuses}"
    )
    for response in responses.values():
        assert response.get_json() == {"error": "invalid_token"}
        assert response.headers["WWW-Authenticate"] == (
            'Bearer realm="protected-resource"'
        )


def test_words_routes_fail_closed_when_validator_returns_no_record_or_error(
    protected_resource,
    resource_http,
    monkeypatch,
):
    monkeypatch.setattr(
        protected_resource,
        "validated_access_record",
        lambda: (None, None),
    )
    responses = (
        resource_http.get("/words"),
        resource_http.post("/words"),
        resource_http.delete("/words"),
    )
    for response in responses:
        assert response.status_code == 401
        assert response.get_json() == {"error": "invalid_token"}
        assert response.headers["WWW-Authenticate"] == (
            'Bearer realm="protected-resource"'
        )


@pytest.mark.parametrize(
    ("method", "kwargs"),
    [
        ("get", {"headers": {"authorization": "bEaReR transport-token"}}),
        ("post", {"data": {"access_token": "transport-token", "word": "form"}}),
    ],
    ids=["bearer-header", "form-body"],
)
def test_supported_token_transports_use_exact_lookup(
    method,
    kwargs,
    oauth_store,
    resource_http,
):
    issue_access(oauth_store, "transport-token")
    response = getattr(resource_http, method)("/words", **kwargs)
    assert response.status_code in {200, 201}


def test_query_string_token_is_rejected(oauth_store, resource_http):
    issue_access(oauth_store, "query-token", "read")
    response = resource_http.get(
        "/words",
        query_string={"access_token": "query-token"},
    )
    assert response.status_code == 401
    assert response.get_json() == {"error": "invalid_token"}
    assert response.headers["WWW-Authenticate"] == (
        'Bearer realm="protected-resource"'
    )


def test_malformed_authorization_header_never_falls_back_to_query(
    oauth_store, resource_http
):
    issue_access(oauth_store, "valid-query-token", "read")
    response = resource_http.get(
        "/words",
        query_string={"access_token": "valid-query-token"},
        headers={"Authorization": "Bearer"},
    )
    assert response.status_code == 401
    assert response.get_json() == {"error": "invalid_token"}
    assert response.headers["WWW-Authenticate"] == 'Bearer realm="protected-resource"'


@pytest.mark.parametrize(
    "authorization",
    [None, "Basic abc", "Bearer token with spaces", "Bearer token@invalid"],
    ids=["missing", "wrong-scheme", "embedded-spaces", "invalid-character"],
)
def test_missing_or_malformed_bearer_is_exact_401(
    authorization, resource_http
):
    headers = {} if authorization is None else {"Authorization": authorization}
    response = resource_http.get("/words", headers=headers)
    assert response.status_code == 401
    assert response.content_type == "application/json"
    assert response.get_json() == {"error": "invalid_token"}
    assert response.headers["WWW-Authenticate"] == 'Bearer realm="protected-resource"'


def test_unknown_token_is_exact_401(oauth_store, resource_http):
    issue_access(oauth_store, "known", "read")
    response = resource_http.get("/words", headers=bearer("unknown"))
    assert response.status_code == 401
    assert response.get_json() == {"error": "invalid_token"}
    assert response.headers["WWW-Authenticate"] == 'Bearer realm="protected-resource"'


def test_lookup_database_failure_is_exact_503(
    protected_resource,
    resource_http,
    monkeypatch,
):
    lookup = Mock(side_effect=protected_resource.DatabaseError("database down"))
    monkeypatch.setattr(protected_resource, "find_access_token", lookup)
    response = resource_http.get("/words", headers=bearer("access-1"))
    assert response.status_code == 503
    assert response.content_type == "application/json"
    assert response.get_json() == {"error": "temporarily_unavailable"}
    assert response.headers["Retry-After"] == "1"


def test_get_words_requires_read_and_returns_words_with_millisecond_timestamp(
    protected_resource,
    oauth_store,
    resource_http,
    monkeypatch,
):
    issue_access(oauth_store, scope="write read delete")
    protected_resource.SAVED_WORDS.extend(["alpha", "beta"])
    monkeypatch.setattr(protected_resource.time, "time", lambda: 1700000000.123)
    response = resource_http.get("/words", headers=bearer("access-1"))
    assert response.status_code == 200
    assert response.content_type == "application/json"
    assert response.get_json() == {
        "words": "alpha beta",
        "timestamp": 1700000000123,
    }
    assert isinstance(response.get_json()["timestamp"], int)


def test_post_requires_write_and_appends_only_truthy_word(
    protected_resource,
    oauth_store,
    resource_http,
):
    issue_access(oauth_store, scope="write")
    first = resource_http.post(
        "/words", data={"word": "gamma"}, headers=bearer("access-1")
    )
    empty = resource_http.post(
        "/words", data={"word": ""}, headers=bearer("access-1")
    )
    assert first.status_code == 201 and first.data == b""
    assert empty.status_code == 201 and empty.data == b""
    assert protected_resource.SAVED_WORDS == ["gamma"]


def test_delete_requires_delete_and_pops_lifo_safely_when_empty(
    protected_resource,
    oauth_store,
    resource_http,
):
    issue_access(oauth_store, scope="delete")
    protected_resource.SAVED_WORDS.extend(["first", "last"])
    first = resource_http.delete("/words", headers=bearer("access-1"))
    second = resource_http.delete("/words", headers=bearer("access-1"))
    empty = resource_http.delete("/words", headers=bearer("access-1"))
    assert [first.status_code, second.status_code, empty.status_code] == [204, 204, 204]
    assert first.data == second.data == empty.data == b""
    assert protected_resource.SAVED_WORDS == []


def test_get_words_requires_exact_read_scope(
    oauth_store,
    resource_http,
):
    issue_access(oauth_store, scope="bread write delete")
    response = resource_http.get("/words", headers=bearer("access-1"))
    assert response.status_code == 403, (
        "Milestone: GET /words must require exact whitespace-delimited read scope"
    )
    assert response.content_type == "application/json"
    assert response.get_json() == {"error": "insufficient_scope"}
    assert response.headers["WWW-Authenticate"] == (
        'Bearer realm="protected-resource", error="insufficient_scope", scope="read"'
    )
    assert "words" not in response.get_json()
    assert "timestamp" not in response.get_json()


def test_add_word_requires_exact_write_scope_without_mutation(
    protected_resource,
    oauth_store,
    resource_http,
):
    issue_access(oauth_store, scope="read overwrite delete")
    protected_resource.SAVED_WORDS[:] = ["keep"]
    response = resource_http.post(
        "/words", data={"word": "must-not-append"}, headers=bearer("access-1")
    )
    assert response.status_code == 403, (
        "Milestone: POST /words must require exact write scope before mutation"
    )
    assert response.content_type == "application/json"
    assert response.get_json() == {"error": "insufficient_scope"}
    assert response.headers["WWW-Authenticate"] == (
        'Bearer realm="protected-resource", error="insufficient_scope", scope="write"'
    )
    assert protected_resource.SAVED_WORDS == ["keep"]


def test_delete_word_requires_exact_delete_scope_without_mutation(
    protected_resource,
    oauth_store,
    resource_http,
):
    issue_access(oauth_store, scope="read write undelete")
    protected_resource.SAVED_WORDS[:] = ["keep", "last"]
    response = resource_http.delete("/words", headers=bearer("access-1"))
    assert response.status_code == 403, (
        "Milestone: DELETE /words must require exact delete scope before mutation"
    )
    assert response.content_type == "application/json"
    assert response.get_json() == {"error": "insufficient_scope"}
    assert response.headers["WWW-Authenticate"] == (
        'Bearer realm="protected-resource", error="insufficient_scope", scope="delete"'
    )
    assert protected_resource.SAVED_WORDS == ["keep", "last"]
