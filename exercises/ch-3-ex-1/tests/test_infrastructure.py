from helpers import (
    issue_authorization_code,
    oauth_form_headers,
    redirect_query,
)


CLIENT_ID = "oauth-client-1"
CLIENT_SECRET = "oauth-client-secret-1"
REDIRECT_URI = "http://localhost:9000/callback"


def redeem_code(authorization_http, code, redirect_uri=REDIRECT_URI):
    return authorization_http.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": redirect_uri,
        },
        headers=oauth_form_headers(CLIENT_ID, CLIENT_SECRET),
    )


def test_code_grant_persists_token_and_resource_accepts_it(
    authorization_http,
    authorization_server,
    resource_http,
    oauth_store,
):
    code, _, _ = issue_authorization_code(
        authorization_http,
        authorization_server,
        scope="foo",
    )
    token_response = redeem_code(authorization_http, code)
    payload = token_response.get_json()
    assert token_response.status_code == 200 and payload["access_token"], (
        "Exchange an approved authorization code for a non-empty access token"
    )
    stored = oauth_store.find_access_token(payload["access_token"])
    assert stored == {
        "access_token": payload["access_token"],
        "client_id": CLIENT_ID,
        "scope": "foo",
    }, "Persist the access token so the protected resource can validate it"

    resource_response = resource_http.post(
        "/resource",
        headers={"Authorization": f"Bearer {payload['access_token']}"},
    )
    assert resource_response.status_code == 200
    assert resource_response.get_json()["name"] == "Protected Resource"


def test_unknown_client_and_bad_redirect_are_local_400_errors(authorization_http):
    cases = (
        ({"client_id": "unknown", "redirect_uri": REDIRECT_URI}, b"Unknown client"),
        (
            {"client_id": CLIENT_ID, "redirect_uri": "https://attacker.invalid/callback"},
            b"Invalid redirect URI",
        ),
    )
    for query, expected_text in cases:
        response = authorization_http.get("/authorize", query_string=query)
        assert response.status_code == 400, (
            "Reject unknown clients and unregistered redirects locally before redirecting"
        )
        assert expected_text in response.data
        assert "Location" not in response.headers


def test_invalid_scope_uses_only_the_trusted_redirect_and_preserves_state(
    authorization_http,
):
    response = authorization_http.get(
        "/authorize",
        query_string={
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": "admin",
            "state": "scope-state",
        },
    )
    parsed, params = redirect_query(response)
    assert response.status_code == 302 and parsed.geturl().startswith(REDIRECT_URI + "?"), (
        "Return invalid_scope only to a previously validated redirect URI"
    )
    assert params == {"error": "invalid_scope", "state": "scope-state"}


def test_approval_request_is_one_use(authorization_http, authorization_server):
    authorization_http.get(
        "/authorize",
        query_string={
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "state": "approval-state",
        },
    )
    request_id = next(iter(authorization_server.approval_requests))
    first = authorization_http.post(
        "/approve",
        data={"reqid": request_id, "approve": "Approve"},
    )
    second = authorization_http.post(
        "/approve",
        data={"reqid": request_id, "approve": "Approve"},
    )
    assert first.status_code == 302
    assert second.status_code == 400 and b"No matching authorization request" in second.data, (
        "Consume an approval request after its first decision"
    )


def test_bad_client_authentication_returns_json_challenge(authorization_http):
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
    for headers, extra_data in attempts:
        data = {"grant_type": "authorization_code", "code": "unknown"}
        data.update(extra_data)
        response = authorization_http.post("/token", data=data, headers=headers)
        assert response.status_code == 401
        assert response.get_json() == {"error": "invalid_client"}, (
            "Reject malformed, wrong, or mixed client authentication as invalid_client"
        )
        assert response.headers["WWW-Authenticate"] == 'Basic realm="token"'


def test_wrong_redirect_does_not_consume_authorization_code(
    authorization_http,
    authorization_server,
):
    code, _, _ = issue_authorization_code(authorization_http, authorization_server)
    rejected = redeem_code(authorization_http, code, "https://wrong.invalid/callback")
    accepted = redeem_code(authorization_http, code)
    assert rejected.status_code == 400
    assert rejected.get_json() == {"error": "invalid_grant"}
    assert accepted.status_code == 200, (
        "Validate redirect_uri before consuming the authorization code"
    )


def test_authorization_code_is_one_use(authorization_http, authorization_server):
    code, _, _ = issue_authorization_code(authorization_http, authorization_server)
    first = redeem_code(authorization_http, code)
    second = redeem_code(authorization_http, code)
    assert first.status_code == 200
    assert second.status_code == 400
    assert second.get_json() == {"error": "invalid_grant"}, (
        "Delete an authorization code after one successful token exchange"
    )


def test_resource_accepts_bearer_form_and_query_transports(resource_http, oauth_store):
    oauth_store.insert_access_token("transport-token", CLIENT_ID, "foo")
    responses = (
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
    assert all(response.status_code == 200 for response in responses), (
        "Accept the documented Bearer, form, and query access-token transports"
    )


def test_malformed_authorization_header_takes_precedence(resource_http, oauth_store):
    oauth_store.insert_access_token("valid-fallback", CLIENT_ID, "foo")
    response = resource_http.post(
        "/resource",
        data={"access_token": "valid-fallback"},
        query_string={"access_token": "valid-fallback"},
        headers={"Authorization": "Bearer"},
    )
    assert response.status_code == 401
    assert response.get_json() == {"error": "invalid_token"}, (
        "Do not fall back to weaker token transports after a malformed Authorization header"
    )
    assert response.headers["WWW-Authenticate"] == (
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

    assert_temporarily_unavailable(redeem_code(authorization_http, code))


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
