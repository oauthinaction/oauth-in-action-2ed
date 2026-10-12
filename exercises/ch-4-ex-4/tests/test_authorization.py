from concurrent.futures import ThreadPoolExecutor
import re
from threading import Event, Lock

import pytest

from helpers import (
    CALLBACK,
    CLIENT_ID,
    TEST_CODE_CHALLENGE,
    TEST_CODE_VERIFIER,
    approve_request,
    authorization_query,
    basic_headers,
    begin_authorization,
    issue_authorization_code,
    redirect_parameters,
    redeem_code,
)


def test_approval_page_exposes_only_fixture_users_and_warning(
    authorization_http, authorization_server
):
    _, response = begin_authorization(authorization_http, authorization_server)
    html = response.get_data(as_text=True)
    assert re.findall(r'<option value="([^"]+)">', html) == ["alice", "bob"]
    assert 'name="resource_owner"' in html
    assert "required" in html
    assert "insecure exercise fixture" in html
    assert "not\n            user authentication" in html
    assert "must not be used as a production pattern" in html


def test_authorize_enforces_client_redirect_scope_pkce_and_preserves_state(
    authorization_http, authorization_server
):
    bad_requests = [
        ({"scope": "movies admin"}, "invalid_scope"),
        ({"code_challenge": None}, "invalid_request"),
        ({"code_challenge_method": "plain"}, "invalid_request"),
        ({"code_challenge": TEST_CODE_CHALLENGE + "="}, "invalid_request"),
    ]
    for updates, expected_error in bad_requests:
        response = authorization_http.get(
            "/authorize", query_string=authorization_query(state="kept-state", **updates)
        )
        parsed, parameters = redirect_parameters(response)
        assert response.status_code == 302
        assert parsed.geturl().startswith(CALLBACK)
        assert parameters == {"error": expected_error, "state": "kept-state"}
    assert authorization_server.approval_requests == {}

    unknown = authorization_http.get(
        "/authorize", query_string=authorization_query(client_id="unknown")
    )
    bad_redirect = authorization_http.get(
        "/authorize",
        query_string=authorization_query(redirect_uri="https://evil.invalid/callback"),
    )
    assert unknown.status_code == 400 and "Location" not in unknown.headers
    assert bad_redirect.status_code == 400 and "Location" not in bad_redirect.headers


@pytest.mark.parametrize("submitted_owner", [None, "", "mallory", "Alice", "BOB"])
def test_missing_or_invalid_owner_uses_trusted_callback_and_preserves_state(
    submitted_owner, authorization_http, authorization_server
):
    request_id, _ = begin_authorization(
        authorization_http, authorization_server, state="owner-state"
    )
    response = approve_request(
        authorization_http, request_id, submitted_owner, ("movies",)
    )
    parsed, parameters = redirect_parameters(response)
    assert response.status_code == 302
    assert (parsed.scheme, parsed.netloc, parsed.path) == (
        "http",
        "localhost:9000",
        "/callback",
    )
    assert parameters == {"error": "invalid_request", "state": "owner-state"}
    assert authorization_server.approval_requests == {}
    assert authorization_server.authorization_codes == {}


def test_approval_binds_exact_owner_and_granted_scope_to_code_and_pair(
    authorization_http, authorization_server, oauth_store
):
    code, _, parameters = issue_authorization_code(
        authorization_http,
        authorization_server,
        owner="bob",
        scope="movies foods music",
        granted_scope=("movies", "music"),
        state="round-trip-state",
    )
    assert parameters["state"] == "round-trip-state"
    code_record = authorization_server.authorization_codes[code]
    assert code_record["resource_owner"] == "bob"
    assert code_record["scope"] == ["movies", "music"]

    response = redeem_code(
        authorization_http,
        code,
        resource_owner="alice",  # Token-request owner injection is untrusted input.
    )
    assert response.status_code == 200
    body = response.get_json()
    assert set(body) == {"access_token", "refresh_token", "token_type", "scope"}
    assert body["token_type"] == "Bearer"
    assert body["scope"] == "movies music"
    assert oauth_store.find_access_token(body["access_token"]) == {
        "access_token": body["access_token"],
        "client_id": CLIENT_ID,
        "scope": "movies music",
        "resource_owner": "bob",
    }
    assert oauth_store.find_refresh_token(body["refresh_token"])["resource_owner"] == "bob"


def test_code_grant_requires_pkce_exact_redirect_and_is_single_use(
    authorization_http, authorization_server, oauth_store
):
    code, _, _ = issue_authorization_code(
        authorization_http, authorization_server, owner="alice"
    )
    wrong_verifier = authorization_http.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": CALLBACK,
            "code_verifier": "A" * 43,
        },
        headers=basic_headers(),
    )
    assert wrong_verifier.status_code == 400
    assert wrong_verifier.get_json() == {"error": "invalid_grant"}
    assert code in authorization_server.authorization_codes

    wrong_redirect = authorization_http.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": CALLBACK + "/wrong",
            "code_verifier": TEST_CODE_VERIFIER,
        },
        headers=basic_headers(),
    )
    assert wrong_redirect.get_json() == {"error": "invalid_grant"}
    assert code in authorization_server.authorization_codes

    success = redeem_code(authorization_http, code)
    replay = redeem_code(authorization_http, code)
    assert success.status_code == 200
    assert replay.status_code == 400
    assert replay.get_json() == {"error": "invalid_grant"}
    assert code not in authorization_server.authorization_codes
    assert oauth_store.find_access_token(success.get_json()["access_token"])


def test_token_endpoint_requires_one_valid_basic_authentication_method(
    authorization_http, authorization_server
):
    code, _, _ = issue_authorization_code(
        authorization_http, authorization_server, owner="alice"
    )
    form = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": CALLBACK,
        "code_verifier": TEST_CODE_VERIFIER,
    }
    cases = [
        ({}, form),
        ({"Authorization": "Basic !!!"}, form),
        (basic_headers(client_secret="wrong"), form),
        (basic_headers(), {**form, "client_id": CLIENT_ID, "client_secret": "x"}),
    ]
    for headers, data in cases:
        response = authorization_http.post("/token", data=data, headers=headers)
        assert response.status_code == 401
        assert response.get_json() == {"error": "invalid_client"}
        assert response.headers["WWW-Authenticate"] == 'Basic realm="token"'
    assert code in authorization_server.authorization_codes


def test_refresh_grant_preserves_scope_and_owner_ignores_injection_and_rejects_replay(
    authorization_http, oauth_store
):
    oauth_store.issue_token_pair(
        "old-access", "old-refresh", CLIENT_ID, "music movies", "alice"
    )
    data = {
        "grant_type": "refresh_token",
        "refresh_token": "old-refresh",
        "resource_owner": "bob",
        "scope": "foods",
    }
    response = authorization_http.post("/token", data=data, headers=basic_headers())
    assert response.status_code == 200
    body = response.get_json()
    assert body["scope"] == "music movies"
    assert oauth_store.find_refresh_token("old-refresh") is None
    assert oauth_store.find_access_token(body["access_token"])["resource_owner"] == "alice"
    assert oauth_store.find_refresh_token(body["refresh_token"])["resource_owner"] == "alice"

    replay = authorization_http.post("/token", data=data, headers=basic_headers())
    assert replay.status_code == 400
    assert replay.get_json() == {"error": "invalid_grant"}


def test_authorization_database_failure_is_a_retryable_503(
    monkeypatch, authorization_http, authorization_server, oauth_store
):
    code, _, _ = issue_authorization_code(
        authorization_http, authorization_server, owner="alice"
    )

    def fail(*args, **kwargs):
        raise oauth_store.DatabaseError("database unavailable")

    monkeypatch.setattr(authorization_server, "issue_token_pair", fail)
    response = redeem_code(authorization_http, code)
    assert response.status_code == 503
    assert response.get_json() == {"error": "temporarily_unavailable"}
    assert response.headers["Retry-After"] == "1"
    assert code in authorization_server.authorization_codes


def test_token_endpoint_rejects_json_without_consuming_code(
    authorization_http, authorization_server
):
    code, _, _ = issue_authorization_code(
        authorization_http, authorization_server, owner="alice"
    )
    headers = {"Authorization": basic_headers()["Authorization"]}
    response = authorization_http.post(
        "/token",
        json={
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": CALLBACK,
            "code_verifier": TEST_CODE_VERIFIER,
        },
        headers=headers,
    )

    assert response.status_code == 400
    assert response.get_json() == {"error": "invalid_request"}
    assert code in authorization_server.authorization_codes


def test_concurrent_code_redemption_issues_exactly_one_owner_bound_pair(
    monkeypatch, authorization_server, oauth_store
):
    with authorization_server.app.test_client() as authorization_http:
        code, _, _ = issue_authorization_code(
            authorization_http, authorization_server, owner="bob"
        )

    class ObservedLock:
        def __init__(self):
            self._lock = Lock()
            self._attempts_lock = Lock()
            self._attempts = 0
            self.second_attempted = Event()

        def __enter__(self):
            with self._attempts_lock:
                self._attempts += 1
                if self._attempts == 2:
                    self.second_attempted.set()
            self._lock.acquire()
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            self._lock.release()

    observed_lock = ObservedLock()
    monkeypatch.setattr(
        authorization_server, "authorization_code_redemption_lock", observed_lock
    )

    original_issue_token_pair = authorization_server.issue_token_pair
    first_pair_persisted = Event()
    release_first_redemption = Event()

    def pause_after_first_pair_is_persisted(*args, **kwargs):
        original_issue_token_pair(*args, **kwargs)
        first_pair_persisted.set()
        assert release_first_redemption.wait(timeout=5)

    monkeypatch.setattr(
        authorization_server, "issue_token_pair", pause_after_first_pair_is_persisted
    )

    def redeem_in_separate_client():
        with authorization_server.app.test_client() as thread_http:
            response = redeem_code(thread_http, code)
            return response.status_code, response.get_json()

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(redeem_in_separate_client)
        assert first_pair_persisted.wait(timeout=5)
        second = executor.submit(redeem_in_separate_client)
        assert observed_lock.second_attempted.wait(timeout=5)
        release_first_redemption.set()
        results = [first.result(timeout=5), second.result(timeout=5)]

    assert sorted(status for status, _ in results) == [200, 400]
    assert [body for status, body in results if status == 400] == [
        {"error": "invalid_grant"}
    ]
    success_body = next(body for status, body in results if status == 200)

    with oauth_store._connect() as connection:
        access_rows = connection.execute(
            "SELECT access_token, client_id, scope, resource_owner FROM access_tokens"
        ).fetchall()
        refresh_rows = connection.execute(
            "SELECT refresh_token, client_id, scope, resource_owner FROM refresh_tokens"
        ).fetchall()

    assert [dict(row) for row in access_rows] == [
        {
            "access_token": success_body["access_token"],
            "client_id": CLIENT_ID,
            "scope": "movies foods music",
            "resource_owner": "bob",
        }
    ]
    assert [dict(row) for row in refresh_rows] == [
        {
            "refresh_token": success_body["refresh_token"],
            "client_id": CLIENT_ID,
            "scope": "movies foods music",
            "resource_owner": "bob",
        }
    ]
