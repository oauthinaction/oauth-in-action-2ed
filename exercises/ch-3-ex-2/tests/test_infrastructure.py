from helpers import (
    TEST_CODE_CHALLENGE,
    TEST_CODE_VERIFIER,
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


def redeem_code(
    authorization_http,
    code,
    redirect_uri=REDIRECT_URI,
    code_verifier=TEST_CODE_VERIFIER,
):
    form_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
    }
    if code_verifier is not None:
        form_data["code_verifier"] = code_verifier
    return token_request(authorization_http, form_data)


def issue_tokens(authorization_http, authorization_server):
    code, _, _ = issue_authorization_code(
        authorization_http,
        authorization_server,
    )
    return redeem_code(authorization_http, code)


def test_server_pkce_helpers_match_rfc_7636(authorization_server):
    assert (
        authorization_server.generate_code_challenge(TEST_CODE_VERIFIER)
        == TEST_CODE_CHALLENGE
    )
    assert authorization_server.validate_code_challenge(
        TEST_CODE_CHALLENGE,
        "S256",
    )
    assert authorization_server.validate_code_verifier(
        TEST_CODE_VERIFIER,
        TEST_CODE_CHALLENGE,
    )
    for invalid_verifier in (
        None,
        "short",
        "a" * 129,
        "a" * 42 + "!",
        "é" * 43,
    ):
        assert (
            authorization_server.generate_code_challenge(invalid_verifier)
            is None
        )
    assert not authorization_server.validate_code_challenge(
        TEST_CODE_CHALLENGE,
        "plain",
    )
    assert not authorization_server.validate_code_challenge(
        "invalid=challenge",
        "S256",
    )
    assert not authorization_server.validate_code_verifier(
        "x" * 43,
        TEST_CODE_CHALLENGE,
    )


def test_server_rejects_non_canonical_base64url_challenge(
    authorization_server,
):
    assert not authorization_server.validate_code_challenge(
        "A" * 42 + "B",
        "S256",
    )


def test_code_grant_issues_and_persists_access_only(
    authorization_http,
    authorization_server,
    oauth_store,
):
    response = issue_tokens(authorization_http, authorization_server)
    payload = response.get_json()
    assert response.status_code == 200
    assert set(payload) == {"access_token", "token_type"}, (
        "An approved code issues access only; "
        "Exercise 2 refresh uses its fixed fixture"
    )
    assert payload["access_token"]
    assert payload["token_type"] == "Bearer"
    assert oauth_store.find_access_token(payload["access_token"]) == {
        "access_token": payload["access_token"],
        "client_id": CLIENT_ID,
    }


def test_authorization_ignores_extra_scope_and_state_parameters(
    authorization_http,
    authorization_server,
):
    response = authorization_http.get(
        "/authorize",
        query_string={
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "code_challenge": TEST_CODE_CHALLENGE,
            "code_challenge_method": "S256",
            "scope": "foo",
            "state": "xyz",
        },
    )
    assert response.status_code == 200, (
        "Extra scope and state parameters must not block the approval page"
    )
    assert b'name="approve"' in response.data

    request_id = next(iter(authorization_server.approval_requests))
    approval = authorization_http.post(
        "/approve",
        data={"reqid": request_id, "approve": "Approve"},
    )
    parsed, params = redirect_query(approval)

    assert approval.status_code == 302
    assert parsed.geturl().startswith(REDIRECT_URI + "?")
    assert params.keys() == {"code"}, (
        "Redirect with only the authorization code; do not echo state"
    )
    stored_code = authorization_server.authorization_codes[params["code"]]
    assert "scope" not in stored_code


def test_token_store_records_and_schema_have_no_scope(oauth_store):
    oauth_store.insert_access_token("store-access", CLIENT_ID)
    oauth_store.insert_refresh_token("store-refresh", CLIENT_ID)
    assert oauth_store.find_access_token("store-access") == {
        "access_token": "store-access",
        "client_id": CLIENT_ID,
    }
    assert oauth_store.find_refresh_token("store-refresh") == {
        "refresh_token": "store-refresh",
        "client_id": CLIENT_ID,
    }

    rotated = oauth_store.rotate_refresh_token(
        "store-refresh",
        "rotated-access",
        "rotated-refresh",
        CLIENT_ID,
    )
    assert rotated == {
        "refresh_token": "rotated-refresh",
        "client_id": CLIENT_ID,
    }
    assert oauth_store.find_access_token("rotated-access") == {
        "access_token": "rotated-access",
        "client_id": CLIENT_ID,
    }

    with oauth_store._connect() as connection:
        for table in ("access_tokens", "refresh_tokens"):
            columns = {
                row["name"]
                for row in connection.execute(f"PRAGMA table_info({table})")
            }
            assert "scope" not in columns, f"{table} must not store a scope"


def test_preconfigured_refresh_rotates_both_tokens_and_rejects_replay(
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
    assert set(payload) == {
        "access_token",
        "token_type",
        "refresh_token",
    }
    assert payload["access_token"] != client_module.INITIAL_ACCESS_TOKEN
    assert payload["token_type"] == "Bearer"
    assert payload["refresh_token"] != fixture
    assert oauth_store.find_access_token(payload["access_token"]) == {
        "access_token": payload["access_token"],
        "client_id": CLIENT_ID,
    }
    assert oauth_store.find_refresh_token(fixture) is None
    assert oauth_store.find_refresh_token(payload["refresh_token"]) == {
        "refresh_token": payload["refresh_token"],
        "client_id": CLIENT_ID,
    }

    replay = token_request(
        authorization_http,
        {"grant_type": "refresh_token", "refresh_token": fixture},
    )
    assert replay.status_code == 400
    assert replay.get_json() == {"error": "invalid_grant"}

    next_response = token_request(
        authorization_http,
        {
            "grant_type": "refresh_token",
            "refresh_token": payload["refresh_token"],
        },
    )
    next_payload = next_response.get_json()
    assert next_response.status_code == 200
    assert next_payload["refresh_token"] != payload["refresh_token"]
    assert oauth_store.find_refresh_token(payload["refresh_token"]) is None
    assert (
        oauth_store.find_refresh_token(next_payload["refresh_token"])
        is not None
    )


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
    assert rejected.status_code == 400
    assert rejected.get_json() == {"error": "invalid_grant"}
    assert oauth_store.find_refresh_token(fixture) is not None, (
        "A failed refresh attempt must not consume the preconfigured fixture"
    )

    accepted = token_request(
        authorization_http,
        {"grant_type": "refresh_token", "refresh_token": fixture},
    )
    replacement = accepted.get_json()["refresh_token"]
    assert accepted.status_code == 200
    assert oauth_store.find_refresh_token(fixture) is None
    assert oauth_store.find_refresh_token(replacement) is not None


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
    assert (
        oauth_store.find_access_token(client_module.INITIAL_ACCESS_TOKEN)
        is None
    )


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


def test_authorization_trust_boundaries(authorization_http):
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
    assert unknown.status_code == 400 and "Location" not in unknown.headers
    assert (
        bad_redirect.status_code == 400
        and "Location" not in bad_redirect.headers
    )


def test_invalid_pkce_authorization_requests_use_trusted_redirect(
    authorization_http,
    authorization_server,
):
    cases = (
        ({}, "missing challenge and method"),
        ({"code_challenge": TEST_CODE_CHALLENGE}, "missing method"),
        (
            {
                "code_challenge": TEST_CODE_CHALLENGE,
                "code_challenge_method": "plain",
            },
            "plain method",
        ),
        (
            {
                "code_challenge": "malformed=challenge",
                "code_challenge_method": "S256",
            },
            "malformed challenge",
        ),
        (
            {
                "code_challenge": "A" * 42 + "B",
                "code_challenge_method": "S256",
            },
            "non-canonical challenge",
        ),
    )
    for pkce_parameters, description in cases:
        query = {
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
        }
        query.update(pkce_parameters)
        response = authorization_http.get("/authorize", query_string=query)
        parsed, params = redirect_query(response)

        assert response.status_code == 302, (
            f"Reject {description} as invalid_request"
        )
        assert parsed.geturl().startswith(REDIRECT_URI + "?"), (
            "Redirect protocol errors only after validating the "
            "registered redirect URI"
        )
        assert params == {"error": "invalid_request"}
        assert not authorization_server.approval_requests, (
            "Do not save an approval request until PKCE parameters are valid"
        )


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
        response = authorization_http.post(
            "/token",
            data=data,
            headers=headers,
        )
        assert response.status_code == 401
        assert response.get_json() == {"error": "invalid_client"}
        assert response.headers["WWW-Authenticate"] == 'Basic realm="token"'


def test_wrong_redirect_preserves_code_then_success_consumes_it(
    authorization_http,
    authorization_server,
):
    code, _, _ = issue_authorization_code(
        authorization_http,
        authorization_server,
    )
    wrong = redeem_code(
        authorization_http,
        code,
        redirect_uri="https://wrong.invalid/callback",
    )
    accepted = redeem_code(authorization_http, code)
    replay = redeem_code(authorization_http, code)
    assert wrong.status_code == 400
    assert accepted.status_code == 200, (
        "Validate redirect_uri before consuming the authorization code"
    )
    assert replay.status_code == 400
    assert replay.get_json() == {"error": "invalid_grant"}, (
        "Consume an authorization code after one successful exchange"
    )


def test_pkce_failures_do_not_consume_authorization_code(
    authorization_http,
    authorization_server,
):
    code, _, _ = issue_authorization_code(
        authorization_http,
        authorization_server,
    )
    missing = redeem_code(authorization_http, code, code_verifier=None)
    wrong = redeem_code(authorization_http, code, code_verifier="x" * 43)
    accepted = redeem_code(authorization_http, code)
    replay = redeem_code(authorization_http, code)

    for response, description in (
        (missing, "missing verifier"),
        (wrong, "wrong verifier"),
    ):
        assert response.status_code == 400, (
            f"Reject a {description} as invalid_grant"
        )
        assert response.get_json() == {"error": "invalid_grant"}
    assert accepted.status_code == 200, (
        "A wrong verifier must not consume the code before "
        "the correct verifier arrives"
    )
    assert replay.status_code == 400
    assert replay.get_json() == {"error": "invalid_grant"}, (
        "Consume the authorization code after successful PKCE validation"
    )


def test_resource_transports_and_malformed_header_precedence(
    resource_http,
    oauth_store,
):
    oauth_store.insert_access_token("transport-token", CLIENT_ID)
    accepted = (
        resource_http.post(
            "/resource",
            headers={"Authorization": "Bearer transport-token"},
        ),
        resource_http.post(
            "/resource",
            data={"access_token": "transport-token"},
        ),
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
    response = redeem_code(authorization_http, code)

    assert_temporarily_unavailable(response)


def test_refresh_rotation_database_failure_returns_503(
    authorization_http,
    authorization_server,
    oauth_store,
    monkeypatch,
):
    monkeypatch.setattr(
        authorization_server,
        "rotate_refresh_token",
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


def test_refresh_rotation_rolls_back_every_token_on_collision(
    authorization_http,
    authorization_server,
    oauth_store,
    monkeypatch,
):
    fixture = authorization_server.PRECONFIGURED_REFRESH_TOKEN
    colliding_refresh_token = "existing-refresh-token"
    generated_access_token = "generated-access-token"
    oauth_store.insert_refresh_token(
        colliding_refresh_token,
        "another-client",
    )
    generated_values = iter([generated_access_token, colliding_refresh_token])
    monkeypatch.setattr(
        authorization_server.secrets,
        "token_urlsafe",
        lambda _size: next(generated_values),
    )

    response = token_request(
        authorization_http,
        {"grant_type": "refresh_token", "refresh_token": fixture},
    )

    assert_temporarily_unavailable(response)
    assert oauth_store.find_refresh_token(fixture) == {
        "refresh_token": fixture,
        "client_id": CLIENT_ID,
    }
    assert oauth_store.find_access_token(generated_access_token) is None
    assert oauth_store.find_refresh_token(colliding_refresh_token) == {
        "refresh_token": colliding_refresh_token,
        "client_id": "another-client",
    }


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
        b"http://localhost:9000/callback",
        b"http://localhost:9001/authorize",
        b"http://localhost:9001/token",
    )

    assert authorization_page.status_code == 200
    for value in authorization_values:
        assert value in authorization_page.data
    assert b"foo bar" not in authorization_page.data
    assert authorization_page.data.count(b"data-copy-value") == 5
    assert authorization_page.data.count(b"data-copy-button") == 5

    resource_page = resource_http.get("/")
    for value in (
        b"http://localhost:9002/resource",
        b"POST",
        b"Authorization: Bearer",
    ):
        assert value in resource_page.data
    assert resource_page.data.count(b"data-copy-value") == 3
    assert resource_page.data.count(b"data-copy-button") == 3
