from helpers import (
    issue_authorization_code,
    oauth_form_headers,
    redirect_query,
)


CLIENT_ID = "oauth-client-1"
CLIENT_SECRET = "oauth-client-secret-1"
REDIRECT_URI = "http://localhost:9000/callback"


def token_request(authorization_http, data, secret=CLIENT_SECRET):
    return authorization_http.post(
        "/token",
        data=data,
        headers=oauth_form_headers(CLIENT_ID, secret),
    )


def issue_tokens(authorization_http, authorization_server):
    code, _, _ = issue_authorization_code(authorization_http, authorization_server)
    return token_request(
        authorization_http,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
        },
    )


def test_code_grant_issues_and_persists_access_only(
    authorization_http,
    authorization_server,
    oauth_store,
):
    response = issue_tokens(authorization_http, authorization_server)
    payload = response.get_json()
    assert response.status_code == 200
    assert set(payload) == {"access_token", "token_type", "scope"}, (
        "An approved code issues access only; Exercise 2 refresh uses its fixed fixture"
    )
    assert payload["access_token"]
    assert payload["token_type"] == "Bearer"
    assert payload["scope"] == "foo"
    assert oauth_store.find_access_token(payload["access_token"]) == {
        "access_token": payload["access_token"],
        "client_id": CLIENT_ID,
        "scope": "foo",
    }


def test_preconfigured_refresh_returns_same_refresh_and_new_access(
    authorization_http,
    authorization_server,
    oauth_store,
    client_module,
):
    fixture = authorization_server.PRECONFIGURED_REFRESH_TOKEN
    response = token_request(
        authorization_http,
        {"grant_type": "refresh_token", "refresh_token": fixture},
    )
    payload = response.get_json()
    assert response.status_code == 200
    assert set(payload) == {"access_token", "token_type", "refresh_token"}
    assert payload["access_token"] != client_module.INITIAL_ACCESS_TOKEN
    assert payload["token_type"] == "Bearer"
    assert payload["refresh_token"] == fixture
    assert oauth_store.find_access_token(payload["access_token"]) == {
        "access_token": payload["access_token"],
        "client_id": CLIENT_ID,
        "scope": "",
    }
    assert oauth_store.find_refresh_token(fixture) == {
        "refresh_token": fixture,
        "client_id": CLIENT_ID,
        "scope": "foo bar",
    }


def test_invalid_refresh_does_not_consume_fixture(
    authorization_http,
    authorization_server,
    oauth_store,
):
    fixture = authorization_server.PRECONFIGURED_REFRESH_TOKEN
    rejected = token_request(
        authorization_http,
        {"grant_type": "refresh_token", "refresh_token": "unknown-refresh"},
    )
    accepted = token_request(
        authorization_http,
        {"grant_type": "refresh_token", "refresh_token": fixture},
    )
    assert rejected.status_code == 400
    assert rejected.get_json() == {"error": "invalid_grant"}
    assert accepted.status_code == 200, (
        "A failed refresh attempt must not consume the preconfigured fixture"
    )
    assert oauth_store.find_refresh_token(fixture) is not None


def test_fixture_access_token_is_rejected_by_resource(
    resource_http,
    oauth_store,
    client_module,
):
    response = resource_http.post(
        "/resource",
        headers={
            "Authorization": f"Bearer {client_module.INITIAL_ACCESS_TOKEN}"
        },
    )
    assert response.status_code == 401
    assert response.get_json() == {"error": "invalid_token"}
    assert oauth_store.find_access_token(client_module.INITIAL_ACCESS_TOKEN) is None


def test_non_expiring_issued_access_is_accepted(
    authorization_http,
    authorization_server,
    resource_http,
    oauth_store,
):
    payload = issue_tokens(authorization_http, authorization_server).get_json()
    access_token = payload["access_token"]
    assert oauth_store.find_access_token(access_token) is not None

    response = resource_http.post(
        "/resource",
        headers={"Authorization": f"Bearer {access_token}"},
    )
    assert response.status_code == 200
    assert oauth_store.find_access_token(access_token) is not None


def test_authorization_trust_boundaries_and_invalid_scope(authorization_http):
    unknown = authorization_http.get(
        "/authorize",
        query_string={"client_id": "unknown", "redirect_uri": REDIRECT_URI},
    )
    bad_redirect = authorization_http.get(
        "/authorize",
        query_string={
            "client_id": CLIENT_ID,
            "redirect_uri": "https://attacker.invalid/callback",
        },
    )
    invalid_scope = authorization_http.get(
        "/authorize",
        query_string={
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": "admin",
            "state": "scope-state",
        },
    )
    assert unknown.status_code == 400 and "Location" not in unknown.headers
    assert bad_redirect.status_code == 400 and "Location" not in bad_redirect.headers
    parsed, params = redirect_query(invalid_scope)
    assert parsed.geturl().startswith(REDIRECT_URI + "?"), (
        "Redirect protocol errors only after validating the registered redirect URI"
    )
    assert params == {"error": "invalid_scope", "state": "scope-state"}


def test_token_endpoint_rejects_bad_and_mixed_client_authentication(
    authorization_http,
):
    valid_headers = oauth_form_headers(CLIENT_ID, CLIENT_SECRET)
    malformed_headers = dict(valid_headers, Authorization="Basic !!!")
    attempts = (
        (malformed_headers, {}),
        (oauth_form_headers(CLIENT_ID, "wrong-secret"), {}),
        (
            valid_headers,
            {"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET},
        ),
    )
    for headers, extra in attempts:
        data = {"grant_type": "refresh_token", "refresh_token": "unknown"}
        data.update(extra)
        response = authorization_http.post("/token", data=data, headers=headers)
        assert response.status_code == 401
        assert response.get_json() == {"error": "invalid_client"}
        assert response.headers["WWW-Authenticate"] == 'Basic realm="token"'


def test_wrong_redirect_preserves_code_then_success_consumes_it(
    authorization_http,
    authorization_server,
):
    code, _, _ = issue_authorization_code(authorization_http, authorization_server)
    wrong = token_request(
        authorization_http,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": "https://wrong.invalid/callback",
        },
    )
    accepted = token_request(
        authorization_http,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
        },
    )
    replay = token_request(
        authorization_http,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
        },
    )
    assert wrong.status_code == 400
    assert accepted.status_code == 200, (
        "Validate redirect_uri before consuming the authorization code"
    )
    assert replay.status_code == 400
    assert replay.get_json() == {"error": "invalid_grant"}, (
        "Consume an authorization code after one successful exchange"
    )


def test_resource_transports_and_malformed_header_precedence(
    resource_http,
    oauth_store,
):
    oauth_store.insert_access_token("transport-token", CLIENT_ID, "foo")
    accepted = (
        resource_http.post(
            "/resource",
            headers={"Authorization": "Bearer transport-token"},
        ),
        resource_http.post("/resource", data={"access_token": "transport-token"}),
        resource_http.post(
            "/resource",
            query_string={"access_token": "transport-token"},
        ),
    )
    assert all(response.status_code == 200 for response in accepted)
    rejected = resource_http.post(
        "/resource",
        data={"access_token": "transport-token"},
        query_string={"access_token": "transport-token"},
        headers={"Authorization": "Bearer"},
    )
    assert rejected.status_code == 401, (
        "Do not fall back after a malformed Authorization header is supplied"
    )
    assert rejected.headers["WWW-Authenticate"] == (
        'Bearer realm="protected-resource"'
    )


def failing_store_call(error_type):
    def fail(*_args):
        raise error_type("database unavailable")

    return fail


def assert_temporarily_unavailable(response):
    assert response.status_code == 503
    assert response.get_json() == {"error": "temporarily_unavailable"}
    assert response.headers["Retry-After"] == "1"


def test_code_exchange_database_failure_returns_503(
    authorization_http,
    authorization_server,
    oauth_store,
    monkeypatch,
):
    code, _, _ = issue_authorization_code(
        authorization_http,
        authorization_server,
    )
    monkeypatch.setattr(
        authorization_server,
        "insert_access_token",
        failing_store_call(oauth_store.DatabaseError),
    )
    response = token_request(
        authorization_http,
        {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": REDIRECT_URI,
        },
    )

    assert_temporarily_unavailable(response)


def test_refresh_lookup_database_failure_returns_503(
    authorization_http,
    authorization_server,
    oauth_store,
    monkeypatch,
):
    monkeypatch.setattr(
        authorization_server,
        "find_refresh_token",
        failing_store_call(oauth_store.DatabaseError),
    )
    response = token_request(
        authorization_http,
        {
            "grant_type": "refresh_token",
            "refresh_token": authorization_server.PRECONFIGURED_REFRESH_TOKEN,
        },
    )

    assert_temporarily_unavailable(response)


def test_refresh_access_insertion_failure_returns_503(
    authorization_http,
    authorization_server,
    oauth_store,
    monkeypatch,
):
    monkeypatch.setattr(
        authorization_server,
        "insert_access_token",
        failing_store_call(oauth_store.DatabaseError),
    )
    response = token_request(
        authorization_http,
        {
            "grant_type": "refresh_token",
            "refresh_token": authorization_server.PRECONFIGURED_REFRESH_TOKEN,
        },
    )

    assert_temporarily_unavailable(response)


def test_resource_database_failure_returns_503(
    resource_http,
    protected_resource,
    oauth_store,
    monkeypatch,
):
    monkeypatch.setattr(
        protected_resource,
        "find_access_token",
        failing_store_call(oauth_store.DatabaseError),
    )
    response = resource_http.post(
        "/resource",
        headers={"Authorization": "Bearer database-token"},
    )

    assert_temporarily_unavailable(response)


def test_information_pages_expose_expected_copy_controls(
    authorization_http,
    resource_http,
):
    authorization_page = authorization_http.get("/")
    authorization_values = (
        b"oauth-client-1",
        b"oauth-client-secret-1",
        b"foo bar",
        b"http://localhost:9000/callback",
        b"http://localhost:9001/authorize",
        b"http://localhost:9001/token",
    )

    assert authorization_page.status_code == 200
    for value in authorization_values:
        assert value in authorization_page.data
    assert authorization_page.data.count(b"data-copy-value") == 6
    assert authorization_page.data.count(b"data-copy-button") == 6

    resource_page = resource_http.get("/")
    for value in (
        b"http://localhost:9002/resource",
        b"POST",
        b"Authorization: Bearer",
    ):
        assert value in resource_page.data
    assert resource_page.data.count(b"data-copy-value") == 3
    assert resource_page.data.count(b"data-copy-button") == 3
