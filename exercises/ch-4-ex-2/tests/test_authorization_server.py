from concurrent.futures import ThreadPoolExecutor
from threading import Event
from unittest.mock import Mock

import pytest

from helpers import (
    CLIENT_ID,
    CLIENT_SECRET,
    REDIRECT_URI,
    TEST_CODE_CHALLENGE,
    exchange_code_form,
    issue_authorization_code,
    oauth_form_headers,
    redirect_query,
)


def authorization_query(**overrides):
    query = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": "read write delete",
        "state": "state-1",
        "code_challenge": TEST_CODE_CHALLENGE,
        "code_challenge_method": "S256",
    }
    query.update(overrides)
    return query


def test_authorize_rejects_unknown_client_without_redirect(
    authorization_http,
):
    response = authorization_http.get(
        "/authorize", query_string=authorization_query(client_id="unknown")
    )
    assert response.status_code == 400
    assert "Location" not in response.headers
    assert b"Unknown client" in response.data


def test_authorize_rejects_unregistered_redirect_without_redirect(
    authorization_http,
):
    response = authorization_http.get(
        "/authorize",
        query_string=authorization_query(
            redirect_uri="https://attacker.invalid/cb"
        ),
    )
    assert response.status_code == 400
    assert "Location" not in response.headers
    assert b"Invalid redirect URI" in response.data


def test_authorize_invalid_scope_redirects_only_to_trusted_callback_with_state(
    authorization_http,
):
    response = authorization_http.get(
        "/authorize",
        query_string=authorization_query(scope="read administrator"),
    )
    parsed, params = redirect_query(response)
    assert response.status_code == 302
    assert parsed.geturl().startswith(f"{REDIRECT_URI}?")
    assert params == {"error": "invalid_scope", "state": "state-1"}


@pytest.mark.parametrize(
    ("challenge", "method"),
    [
        (None, "S256"),
        (TEST_CODE_CHALLENGE + "=", "S256"),
        (TEST_CODE_CHALLENGE, "plain"),
        ("x" * 43, "S256"),
    ],
    ids=["missing", "padded", "wrong-method", "non-sha256-shape"],
)
def test_authorize_requires_canonical_s256_pkce(
    challenge, method, authorization_http
):
    response = authorization_http.get(
        "/authorize",
        query_string=authorization_query(
            code_challenge=challenge, code_challenge_method=method
        ),
    )
    _, params = redirect_query(response)
    assert response.status_code == 302
    assert params == {"error": "invalid_request", "state": "state-1"}


def test_approval_page_shows_received_state(authorization_http):
    response = authorization_http.get(
        "/authorize",
        query_string=authorization_query(state="received-state-42"),
    )
    page = response.get_data(as_text=True)

    assert response.status_code == 200
    assert "<strong>State:</strong>" in page
    assert "<code data-copy-value>received-state-42</code>" in page, (
        "Show the state value the client sent on the approval page"
    )


def test_authorize_and_approve_issue_state_bound_code_with_narrowed_scope(
    authorization_server, authorization_http
):
    response = authorization_http.get(
        "/authorize", query_string=authorization_query()
    )
    assert response.status_code == 200
    request_id = next(iter(authorization_server.approval_requests))
    approved = authorization_http.post(
        "/approve",
        data={
            "reqid": request_id,
            "approve": "Approve",
            "scope_read": "read",
            "scope_delete": "delete",
        },
    )
    parsed, params = redirect_query(approved)
    assert approved.status_code == 302
    assert parsed.geturl().startswith(f"{REDIRECT_URI}?")
    assert params["state"] == "state-1"
    code = authorization_server.authorization_codes[params["code"]]
    assert code == {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": ["read", "delete"],
        "code_challenge": TEST_CODE_CHALLENGE,
        "code_challenge_method": "S256",
    }
    assert request_id not in authorization_server.approval_requests


def test_approval_request_is_one_use_even_after_denial(
    authorization_server, authorization_http
):
    authorization_http.get("/authorize", query_string=authorization_query())
    request_id = next(iter(authorization_server.approval_requests))
    denied = authorization_http.post(
        "/approve", data={"reqid": request_id, "deny": "Deny"}
    )
    _, params = redirect_query(denied)
    assert params == {"error": "access_denied", "state": "state-1"}
    replay = authorization_http.post(
        "/approve", data={"reqid": request_id, "approve": "Approve"}
    )
    assert replay.status_code == 400
    assert b"No matching authorization request" in replay.data


def test_approval_cannot_expand_requested_scope(
    authorization_server, authorization_http
):
    authorization_http.get(
        "/authorize", query_string=authorization_query(scope="read")
    )
    request_id = next(iter(authorization_server.approval_requests))
    response = authorization_http.post(
        "/approve",
        data={
            "reqid": request_id,
            "approve": "Approve",
            "scope_read": "read",
            "scope_write": "write",
        },
    )
    _, params = redirect_query(response)
    assert params == {"error": "invalid_scope", "state": "state-1"}
    assert not authorization_server.authorization_codes


def test_authorization_code_exchange_issues_and_persists_exact_token_pair(
    authorization_server, authorization_http, oauth_store, monkeypatch
):
    code, _, _ = issue_authorization_code(
        authorization_http, authorization_server, scope="read write"
    )
    token_values = Mock(side_effect=["issued-access", "issued-refresh"])
    monkeypatch.setattr(
        authorization_server.secrets, "token_urlsafe", token_values
    )

    response = authorization_http.post(
        "/token",
        data=exchange_code_form(code),
        headers=oauth_form_headers(),
    )

    assert response.status_code == 200
    assert response.get_json() == {
        "access_token": "issued-access",
        "token_type": "Bearer",
        "refresh_token": "issued-refresh",
        "scope": "read write",
    }
    assert oauth_store.find_access_token("issued-access") == {
        "access_token": "issued-access",
        "client_id": CLIENT_ID,
        "scope": "read write",
    }
    assert oauth_store.find_refresh_token("issued-refresh") == {
        "refresh_token": "issued-refresh",
        "client_id": CLIENT_ID,
        "scope": "read write",
    }
    assert code not in authorization_server.authorization_codes


def test_concurrent_same_code_redemption_has_one_success_and_one_invalid_grant(
    authorization_server, authorization_http, oauth_store, monkeypatch
):
    code, _, _ = issue_authorization_code(
        authorization_http, authorization_server, scope="read write"
    )
    first_issue_started = Event()
    release_first_issue = Event()
    second_request_started = Event()
    original_issue_token_pair = authorization_server.issue_token_pair

    def delayed_issue_token_pair(*args):
        first_issue_started.set()
        assert release_first_issue.wait(timeout=5)
        return original_issue_token_pair(*args)

    def redeem_code(started=None):
        if started is not None:
            started.set()
        with authorization_server.app.test_client() as http:
            response = http.post(
                "/token",
                data=exchange_code_form(code),
                headers=oauth_form_headers(),
            )
            return response.status_code, response.get_json()

    monkeypatch.setattr(
        authorization_server, "issue_token_pair", delayed_issue_token_pair
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        first_result = executor.submit(redeem_code)
        assert first_issue_started.wait(timeout=5)
        second_result = executor.submit(redeem_code, second_request_started)
        assert second_request_started.wait(timeout=5)
        release_first_issue.set()
        results = [
            first_result.result(timeout=5),
            second_result.result(timeout=5),
        ]

    assert sorted(status for status, _ in results) == [200, 400]
    success_body = next(body for status, body in results if status == 200)
    failure_body = next(body for status, body in results if status == 400)
    assert failure_body == {"error": "invalid_grant"}
    issued_access = oauth_store.find_access_token(success_body["access_token"])
    issued_refresh = oauth_store.find_refresh_token(
        success_body["refresh_token"]
    )
    assert issued_access["scope"] == "read write"
    assert issued_refresh["scope"] == "read write"
    assert code not in authorization_server.authorization_codes


def test_wrong_verifier_or_redirect_does_not_consume_authorization_code(
    authorization_server, authorization_http
):
    code, _, _ = issue_authorization_code(
        authorization_http, authorization_server, scope="read"
    )
    wrong_verifier = authorization_http.post(
        "/token",
        data=exchange_code_form(code, verifier="x" * 43),
        headers=oauth_form_headers(),
    )
    assert wrong_verifier.status_code == 400
    assert wrong_verifier.get_json() == {"error": "invalid_grant"}
    assert code in authorization_server.authorization_codes

    form = exchange_code_form(code)
    form["redirect_uri"] = "https://wrong.invalid/callback"
    wrong_redirect = authorization_http.post(
        "/token", data=form, headers=oauth_form_headers()
    )
    assert wrong_redirect.status_code == 400
    assert wrong_redirect.get_json() == {"error": "invalid_grant"}
    assert code in authorization_server.authorization_codes


def test_token_endpoint_rejects_json_as_invalid_request(
    authorization_server, authorization_http
):
    code, _, _ = issue_authorization_code(
        authorization_http, authorization_server, scope="delete"
    )
    body = {
        **exchange_code_form(code),
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
    }
    response = authorization_http.post("/token", json=body)
    assert response.status_code == 400
    assert response.get_json() == {"error": "invalid_request"}
    assert code in authorization_server.authorization_codes


@pytest.mark.parametrize(
    "headers",
    [
        {},
        {"Authorization": "Bearer not-basic"},
        {"Authorization": "Basic !!!not-base64!!!"},
        {"Authorization": "Basic bm8tY29sb24="},
        oauth_form_headers(CLIENT_ID, "wrong-secret"),
    ],
    ids=[
        "missing",
        "wrong-scheme",
        "bad-base64",
        "missing-colon",
        "wrong-secret",
    ],
)
def test_token_endpoint_rejects_invalid_client_with_exact_challenge(
    headers, authorization_http
):
    response = authorization_http.post(
        "/token",
        data={"grant_type": "refresh_token", "refresh_token": "r"},
        headers=headers,
    )
    assert response.status_code == 401
    assert response.get_json() == {"error": "invalid_client"}
    assert response.headers["WWW-Authenticate"] == 'Basic realm="token"'


def test_token_endpoint_rejects_mixed_basic_and_body_credentials(
    authorization_http,
):
    response = authorization_http.post(
        "/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": "r",
            "client_id": CLIENT_ID,
            "client_secret": CLIENT_SECRET,
        },
        headers=oauth_form_headers(),
    )
    assert response.status_code == 401
    assert response.get_json() == {"error": "invalid_client"}
    assert response.headers["WWW-Authenticate"] == 'Basic realm="token"'


def test_code_database_failure_returns_503_and_keeps_code_retriable(
    authorization_server, authorization_http, monkeypatch
):
    code, _, _ = issue_authorization_code(
        authorization_http, authorization_server, scope="read"
    )
    issue = Mock(
        side_effect=authorization_server.DatabaseError("database down")
    )
    monkeypatch.setattr(authorization_server, "issue_token_pair", issue)
    response = authorization_http.post(
        "/token", data=exchange_code_form(code), headers=oauth_form_headers()
    )
    assert response.status_code == 503
    assert response.get_json() == {"error": "temporarily_unavailable"}
    assert response.headers["Retry-After"] == "1"
    assert code in authorization_server.authorization_codes


def test_refresh_rotates_once_preserves_scope_and_rejects_replay(
    authorization_server, authorization_http, oauth_store, monkeypatch
):
    oauth_store.insert_refresh_token("old-refresh", CLIENT_ID, "read delete")
    values = Mock(
        side_effect=["new-access", "new-refresh", "unused-a", "unused-r"]
    )
    monkeypatch.setattr(authorization_server.secrets, "token_urlsafe", values)
    form = {"grant_type": "refresh_token", "refresh_token": "old-refresh"}

    response = authorization_http.post(
        "/token", data=form, headers=oauth_form_headers()
    )
    assert response.status_code == 200
    assert response.get_json() == {
        "access_token": "new-access",
        "token_type": "Bearer",
        "refresh_token": "new-refresh",
        "scope": "read delete",
    }
    assert oauth_store.find_refresh_token("old-refresh") is None
    new_access = oauth_store.find_access_token("new-access")
    new_refresh = oauth_store.find_refresh_token("new-refresh")
    assert new_access["scope"] == "read delete"
    assert new_refresh["scope"] == "read delete"

    replay = authorization_http.post(
        "/token", data=form, headers=oauth_form_headers()
    )
    assert replay.status_code == 400
    assert replay.get_json() == {"error": "invalid_grant"}


def test_refresh_database_failure_returns_503_without_consuming_token(
    authorization_server, authorization_http, oauth_store, monkeypatch
):
    oauth_store.insert_refresh_token("old-refresh", CLIENT_ID, "write")
    rotate = Mock(
        side_effect=authorization_server.DatabaseError("database down")
    )
    monkeypatch.setattr(authorization_server, "rotate_refresh_token", rotate)
    response = authorization_http.post(
        "/token",
        data={"grant_type": "refresh_token", "refresh_token": "old-refresh"},
        headers=oauth_form_headers(),
    )
    assert response.status_code == 503
    assert response.get_json() == {"error": "temporarily_unavailable"}
    assert response.headers["Retry-After"] == "1"
    assert oauth_store.find_refresh_token("old-refresh")["scope"] == "write"


def test_unsupported_grant_type_is_json_oauth_error(authorization_http):
    response = authorization_http.post(
        "/token",
        data={"grant_type": "client_credentials"},
        headers=oauth_form_headers(),
    )
    assert response.status_code == 400
    assert response.get_json() == {"error": "unsupported_grant_type"}
