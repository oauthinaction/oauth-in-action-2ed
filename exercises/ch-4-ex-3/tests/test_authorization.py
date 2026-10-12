from concurrent.futures import ThreadPoolExecutor
from threading import Event, Lock

import pytest

from helpers import (
    CLIENT_ID,
    CLIENT_SECRET,
    REDIRECT_URI,
    TEST_CODE_CHALLENGE,
    TEST_CODE_VERIFIER,
    authorization_query,
    generate_test_code_challenge,
    issue_authorization_code,
    oauth_form_headers,
    redeem_code,
    redirect_query,
    token_request,
)


def assert_temporarily_unavailable(response):
    assert response.status_code == 503
    assert response.get_json() == {"error": "temporarily_unavailable"}
    assert response.headers["Retry-After"] == "1"


def database_failure(error_type):
    def fail(*_args, **_kwargs):
        raise error_type("database unavailable")

    return fail


def test_pkce_helpers_match_rfc_7636_and_reject_invalid_values(authorization_server):
    assert generate_test_code_challenge(TEST_CODE_VERIFIER) == TEST_CODE_CHALLENGE
    assert authorization_server.generate_code_challenge(TEST_CODE_VERIFIER) == TEST_CODE_CHALLENGE
    assert authorization_server.validate_code_challenge(TEST_CODE_CHALLENGE, "S256")
    assert authorization_server.validate_code_verifier(TEST_CODE_VERIFIER, TEST_CODE_CHALLENGE)

    for verifier in (None, "short", "a" * 129, "a" * 42 + "!", "é" * 43):
        assert authorization_server.generate_code_challenge(verifier) is None
    for challenge, method in (
        (None, "S256"),
        (TEST_CODE_CHALLENGE, None),
        (TEST_CODE_CHALLENGE, "plain"),
        ("invalid=challenge", "S256"),
        ("A" * 42 + "B", "S256"),
    ):
        assert not authorization_server.validate_code_challenge(challenge, method)
    assert not authorization_server.validate_code_verifier("x" * 43, TEST_CODE_CHALLENGE)


def test_authorization_trust_boundary_scope_and_state(authorization_http, authorization_server):
    unknown = authorization_http.get(
        "/authorize", query_string={"client_id": "unknown", "redirect_uri": REDIRECT_URI}
    )
    bad_redirect = authorization_http.get(
        "/authorize",
        query_string={
            "client_id": CLIENT_ID,
            "redirect_uri": "https://attacker.invalid/callback",
        },
    )
    invalid_scope = authorization_http.get(
        "/authorize", query_string=authorization_query("fruit admin", "scope-state")
    )

    assert unknown.status_code == 400 and "Location" not in unknown.headers
    assert bad_redirect.status_code == 400 and "Location" not in bad_redirect.headers
    parsed, params = redirect_query(invalid_scope)
    assert parsed.geturl().startswith(REDIRECT_URI + "?")
    assert params == {"error": "invalid_scope", "state": "scope-state"}
    assert not authorization_server.approval_requests


@pytest.mark.parametrize(
    "updates",
    [
        {"code_challenge": None, "code_challenge_method": None},
        {"code_challenge_method": None},
        {"code_challenge_method": "plain"},
        {"code_challenge": "malformed=challenge"},
        {"code_challenge": "A" * 42 + "B"},
    ],
    ids=["missing", "missing-method", "plain", "malformed", "noncanonical"],
)
def test_invalid_pkce_redirects_only_to_registered_callback(
    authorization_http, authorization_server, updates
):
    query = authorization_query(state="pkce-state")
    for key, value in updates.items():
        if value is None:
            query.pop(key, None)
        else:
            query[key] = value
    response = authorization_http.get("/authorize", query_string=query)
    parsed, params = redirect_query(response)
    assert response.status_code == 302
    assert parsed.geturl().startswith(REDIRECT_URI + "?")
    assert params == {"error": "invalid_request", "state": "pkce-state"}
    assert not authorization_server.approval_requests


@pytest.mark.parametrize(
    ("requested", "granted", "expected"),
    [
        ("fruit veggies meats", "fruit veggies meats", ["fruit", "veggies", "meats"]),
        ("fruit veggies meats", "fruit meats", ["fruit", "meats"]),
        ("fruit veggies meats", "", []),
        ("veggies", "veggies", ["veggies"]),
    ],
)
def test_approval_grants_only_selected_requested_scope(
    authorization_http, authorization_server, requested, granted, expected
):
    code, params = issue_authorization_code(
        authorization_http,
        authorization_server,
        requested_scope=requested,
        granted_scope=granted,
        state="consent-state",
    )
    assert params["state"] == "consent-state"
    assert authorization_server.authorization_codes[code]["scope"] == expected


def test_approval_is_one_use_and_rejects_denial_response_type_and_scope_tampering(
    authorization_http, authorization_server
):
    def pending(query):
        response = authorization_http.get("/authorize", query_string=query)
        assert response.status_code == 200
        return next(iter(authorization_server.approval_requests))

    request_id = pending(authorization_query(state="deny-state"))
    denied = authorization_http.post("/approve", data={"reqid": request_id})
    _, params = redirect_query(denied)
    assert params == {"error": "access_denied", "state": "deny-state"}
    assert authorization_http.post("/approve", data={"reqid": request_id}).status_code == 400

    unsupported_query = authorization_query(state="type-state")
    unsupported_query["response_type"] = "token"
    request_id = pending(unsupported_query)
    unsupported = authorization_http.post(
        "/approve", data={"reqid": request_id, "approve": "Approve"}
    )
    assert redirect_query(unsupported)[1] == {
        "error": "unsupported_response_type",
        "state": "type-state",
    }

    request_id = pending(authorization_query("fruit", "tamper-state"))
    tampered = authorization_http.post(
        "/approve",
        data={"reqid": request_id, "approve": "Approve", "scope_admin": "admin"},
    )
    assert redirect_query(tampered)[1] == {
        "error": "invalid_scope",
        "state": "tamper-state",
    }


def test_token_endpoint_requires_one_valid_client_authentication_method(authorization_http):
    valid_headers = oauth_form_headers()
    attempts = (
        ({"Authorization": "Basic !!!"}, {}),
        (oauth_form_headers(CLIENT_ID, "wrong-secret"), {}),
        (valid_headers, {"client_id": CLIENT_ID, "client_secret": CLIENT_SECRET}),
        ({}, {}),
    )
    for headers, extra in attempts:
        data = {"grant_type": "refresh_token", "refresh_token": "unknown", **extra}
        response = authorization_http.post("/token", data=data, headers=headers)
        assert response.status_code == 401
        assert response.get_json() == {"error": "invalid_client"}
        assert response.headers["WWW-Authenticate"] == 'Basic realm="token"'

    json_request = authorization_http.post(
        "/token",
        json={
            "grant_type": "refresh_token",
            "refresh_token": "unknown",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
    )
    assert json_request.status_code == 400
    assert json_request.get_json() == {"error": "invalid_request"}


def test_code_grant_issues_persisted_access_refresh_pair_and_rejects_replay(
    authorization_http, authorization_server, oauth_store
):
    code, _ = issue_authorization_code(
        authorization_http,
        authorization_server,
        granted_scope="fruit meats",
    )
    response = redeem_code(authorization_http, code)
    payload = response.get_json()

    assert response.status_code == 200
    assert set(payload) == {"access_token", "token_type", "refresh_token", "scope"}
    assert payload["token_type"] == "Bearer"
    assert payload["scope"] == "fruit meats"
    assert oauth_store.find_access_token(payload["access_token"]) == {
        "access_token": payload["access_token"],
        "client_id": CLIENT_ID,
        "scope": "fruit meats",
    }
    assert oauth_store.find_refresh_token(payload["refresh_token"]) == {
        "refresh_token": payload["refresh_token"],
        "client_id": CLIENT_ID,
        "scope": "fruit meats",
    }
    replay = redeem_code(authorization_http, code)
    assert replay.status_code == 400
    assert replay.get_json() == {"error": "invalid_grant"}


def test_concurrent_code_redemption_issues_exactly_one_token_pair(
    authorization_http, authorization_server, oauth_store, monkeypatch
):
    code, _ = issue_authorization_code(authorization_http, authorization_server)
    real_issue_token_pair = authorization_server.issue_token_pair
    first_issue_started = Event()
    release_first_issue = Event()
    issue_calls = []
    issue_calls_lock = Lock()

    def controlled_issue_token_pair(*args):
        with issue_calls_lock:
            issue_calls.append(args)
            call_number = len(issue_calls)
        if call_number == 1:
            first_issue_started.set()
            assert release_first_issue.wait(timeout=5)
        return real_issue_token_pair(*args)

    monkeypatch.setattr(
        authorization_server,
        "issue_token_pair",
        controlled_issue_token_pair,
    )

    def exchange_code():
        with authorization_server.app.test_client() as concurrent_http:
            response = redeem_code(concurrent_http, code)
            return response.status_code, response.get_json()

    second_request_started = Event()

    def exchange_code_second():
        second_request_started.set()
        return exchange_code()

    with ThreadPoolExecutor(max_workers=2) as executor:
        first_result = executor.submit(exchange_code)
        try:
            assert first_issue_started.wait(timeout=5)
            second_result = executor.submit(exchange_code_second)
            assert second_request_started.wait(timeout=5)
        finally:
            release_first_issue.set()
        results = [first_result.result(timeout=5), second_result.result(timeout=5)]

    assert sorted(status for status, _body in results) == [200, 400]
    success_body = next(body for status, body in results if status == 200)
    failure_body = next(body for status, body in results if status == 400)
    assert failure_body == {"error": "invalid_grant"}
    assert len(issue_calls) == 1
    assert oauth_store.find_access_token(success_body["access_token"]) is not None
    assert oauth_store.find_refresh_token(success_body["refresh_token"]) is not None
    with oauth_store._connect() as connection:
        access_count = connection.execute(
            "SELECT COUNT(*) FROM access_tokens"
        ).fetchone()[0]
        refresh_count = connection.execute(
            "SELECT COUNT(*) FROM refresh_tokens"
        ).fetchone()[0]
    assert (access_count, refresh_count) == (1, 1)
    assert code not in authorization_server.authorization_codes


def test_redirect_and_pkce_failures_preserve_code_until_valid_exchange(
    authorization_http, authorization_server
):
    code, _ = issue_authorization_code(authorization_http, authorization_server)
    wrong_redirect = redeem_code(
        authorization_http, code, redirect_uri="https://wrong.invalid/callback"
    )
    missing_verifier = redeem_code(authorization_http, code, code_verifier=None)
    wrong_verifier = redeem_code(authorization_http, code, code_verifier="x" * 43)
    accepted = redeem_code(authorization_http, code)

    for response in (wrong_redirect, missing_verifier, wrong_verifier):
        assert response.status_code == 400
        assert response.get_json() == {"error": "invalid_grant"}
    assert accepted.status_code == 200


def test_refresh_rotation_preserves_scope_and_rejects_replay_and_wrong_binding(
    authorization_http, authorization_server, oauth_store
):
    code, _ = issue_authorization_code(
        authorization_http, authorization_server, granted_scope="veggies meats"
    )
    issued = redeem_code(authorization_http, code).get_json()
    old_access = issued["access_token"]
    old_refresh = issued["refresh_token"]

    first = token_request(
        authorization_http,
        {"grant_type": "refresh_token", "refresh_token": old_refresh},
    )
    first_body = first.get_json()
    assert first.status_code == 200
    assert first_body["scope"] == "veggies meats"
    assert first_body["access_token"] != old_access
    assert first_body["refresh_token"] != old_refresh
    assert oauth_store.find_refresh_token(old_refresh) is None
    assert oauth_store.find_refresh_token(first_body["refresh_token"])["scope"] == "veggies meats"
    assert oauth_store.find_access_token(old_access) is not None

    replay = token_request(
        authorization_http,
        {"grant_type": "refresh_token", "refresh_token": old_refresh},
    )
    assert replay.status_code == 400 and replay.get_json() == {"error": "invalid_grant"}

    oauth_store.insert_refresh_token("other-client-refresh", "other-client", "fruit")
    wrong_binding = token_request(
        authorization_http,
        {"grant_type": "refresh_token", "refresh_token": "other-client-refresh"},
    )
    assert wrong_binding.status_code == 400
    assert oauth_store.find_refresh_token("other-client-refresh") is not None

    second = token_request(
        authorization_http,
        {"grant_type": "refresh_token", "refresh_token": first_body["refresh_token"]},
    )
    assert second.status_code == 200
    assert second.get_json()["scope"] == "veggies meats"


def test_code_and_refresh_database_errors_return_503_without_consuming_grants(
    authorization_http, authorization_server, oauth_store, monkeypatch
):
    code, _ = issue_authorization_code(authorization_http, authorization_server)
    real_issue = authorization_server.issue_token_pair
    monkeypatch.setattr(
        authorization_server,
        "issue_token_pair",
        database_failure(oauth_store.DatabaseError),
    )
    failed_code = redeem_code(authorization_http, code)
    assert_temporarily_unavailable(failed_code)
    assert code in authorization_server.authorization_codes

    monkeypatch.setattr(authorization_server, "issue_token_pair", real_issue)
    retried_code = redeem_code(authorization_http, code)
    assert retried_code.status_code == 200
    issued = retried_code.get_json()
    assert code not in authorization_server.authorization_codes
    refresh = issued["refresh_token"]
    monkeypatch.setattr(
        authorization_server,
        "rotate_refresh_token",
        database_failure(oauth_store.DatabaseError),
    )
    failed_refresh = token_request(
        authorization_http,
        {"grant_type": "refresh_token", "refresh_token": refresh},
    )
    assert_temporarily_unavailable(failed_refresh)
    assert oauth_store.find_refresh_token(refresh) is not None


def test_refresh_rotation_collision_rolls_back_all_changes(
    authorization_http, authorization_server, oauth_store, monkeypatch
):
    oauth_store.insert_refresh_token("original-refresh", CLIENT_ID, "fruit veggies")
    oauth_store.insert_refresh_token("collision-refresh", "other-client", "other")
    values = iter(["candidate-access", "collision-refresh"])
    monkeypatch.setattr(
        authorization_server.secrets, "token_urlsafe", lambda _size: next(values)
    )

    response = token_request(
        authorization_http,
        {"grant_type": "refresh_token", "refresh_token": "original-refresh"},
    )
    assert_temporarily_unavailable(response)
    assert oauth_store.find_refresh_token("original-refresh") == {
        "refresh_token": "original-refresh",
        "client_id": CLIENT_ID,
        "scope": "fruit veggies",
    }
    assert oauth_store.find_access_token("candidate-access") is None
    assert oauth_store.find_refresh_token("collision-refresh")["client_id"] == "other-client"
