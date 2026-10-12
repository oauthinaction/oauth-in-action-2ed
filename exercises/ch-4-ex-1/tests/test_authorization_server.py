from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event, Lock
from urllib.parse import parse_qs, urlsplit

import pytest

from helpers import basic_header


CLIENT_ID = "oauth-client-1"
CLIENT_SECRET = "oauth-client-secret-1"
REDIRECT_URI = "http://localhost:9000/callback"
VERIFIER = "v" * 43


def token_form(**overrides):
    form = {
        "grant_type": "authorization_code",
        "code": "code-1",
        "redirect_uri": REDIRECT_URI,
        "code_verifier": VERIFIER,
    }
    form.update(overrides)
    return form


def seed_code(authorization_server, code="code-1", verifier=VERIFIER):
    authorization_server.authorization_codes[code] = {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": [],
        "code_challenge": authorization_server.generate_code_challenge(verifier),
        "code_challenge_method": "S256",
    }


def test_authorize_accepts_omitted_empty_scope_and_valid_s256_pkce(
    authorization_http, authorization_server
):
    challenge = authorization_server.generate_code_challenge(VERIFIER)

    response = authorization_http.get(
        "/authorize",
        query_string={
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "state": "state-1",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )

    assert response.status_code == 200
    assert b"Approve" in response.data
    assert len(authorization_server.approval_requests) == 1
    saved = next(iter(authorization_server.approval_requests.values()))
    assert "scope" not in saved
    assert saved["code_challenge"] == challenge


def test_authorization_code_exchange_consumes_code_and_persists_both_tokens_atomically(
    authorization_http, authorization_server, oauth_store
):
    seed_code(authorization_server)

    response = authorization_http.post(
        "/token", data=token_form(), headers=basic_header(CLIENT_ID, CLIENT_SECRET)
    )

    assert response.status_code == 200
    body = response.get_json()
    assert body["token_type"] == "Bearer"
    assert body["scope"] == ""
    assert body["access_token"]
    assert body["refresh_token"]
    assert oauth_store.find_access_token(body["access_token"]) == {
        "access_token": body["access_token"],
        "client_id": CLIENT_ID,
        "scope": "",
    }
    assert oauth_store.find_refresh_token(body["refresh_token"]) == {
        "refresh_token": body["refresh_token"],
        "client_id": CLIENT_ID,
        "scope": "",
    }
    assert "code-1" not in authorization_server.authorization_codes


@pytest.mark.parametrize(
    ("change", "expected_status"),
    [
        ({"redirect_uri": "http://localhost:9000/not-registered"}, 400),
        ({"code_verifier": "x" * 43}, 400),
    ],
)
def test_invalid_redirect_or_pkce_rejects_grant_without_consuming_code(
    change, expected_status, authorization_http, authorization_server, oauth_store
):
    seed_code(authorization_server)

    response = authorization_http.post(
        "/token",
        data=token_form(**change),
        headers=basic_header(CLIENT_ID, CLIENT_SECRET),
    )

    assert response.status_code == expected_status
    assert response.get_json() == {"error": "invalid_grant"}
    assert "code-1" in authorization_server.authorization_codes
    assert oauth_store.find_access_token("code-1") is None


def test_wrong_or_ambiguous_client_authentication_is_a_challenged_401(
    authorization_http, authorization_server
):
    seed_code(authorization_server)
    cases = [
        (basic_header(CLIENT_ID, "wrong-secret"), token_form()),
        (
            basic_header(CLIENT_ID, CLIENT_SECRET),
            token_form(client_id=CLIENT_ID, client_secret=CLIENT_SECRET),
        ),
        ({"Authorization": "Basic not-base64!"}, token_form()),
    ]

    for headers, form in cases:
        response = authorization_http.post("/token", data=form, headers=headers)
        assert response.status_code == 401
        assert response.get_json() == {"error": "invalid_client"}
        assert response.headers["WWW-Authenticate"] == 'Basic realm="token"'
        assert "code-1" in authorization_server.authorization_codes


def test_refresh_rotates_once_rejects_replay_and_preserves_empty_scope(
    authorization_http, oauth_store
):
    oauth_store.issue_token_pair("access-1", "refresh-1", CLIENT_ID, "")
    form = {"grant_type": "refresh_token", "refresh_token": "refresh-1"}
    headers = basic_header(CLIENT_ID, CLIENT_SECRET)

    first = authorization_http.post("/token", data=form, headers=headers)

    assert first.status_code == 200
    body = first.get_json()
    assert body["scope"] == ""
    assert body["access_token"] != "access-1"
    assert body["refresh_token"] != "refresh-1"
    assert oauth_store.find_refresh_token("refresh-1") is None
    assert oauth_store.find_refresh_token(body["refresh_token"])["scope"] == ""
    assert oauth_store.find_access_token(body["access_token"])["scope"] == ""

    replay = authorization_http.post("/token", data=form, headers=headers)
    assert replay.status_code == 400
    assert replay.get_json() == {"error": "invalid_grant"}


def test_token_database_errors_map_to_retryable_503(
    authorization_http, authorization_server, oauth_store, monkeypatch
):
    seed_code(authorization_server)

    def database_failure(*_args, **_kwargs):
        raise oauth_store.DatabaseError("database unavailable")

    original_issue = authorization_server.issue_token_pair
    monkeypatch.setattr(authorization_server, "issue_token_pair", database_failure)
    code_response = authorization_http.post(
        "/token", data=token_form(), headers=basic_header(CLIENT_ID, CLIENT_SECRET)
    )
    assert code_response.status_code == 503
    assert code_response.get_json() == {"error": "temporarily_unavailable"}
    assert code_response.headers["Retry-After"] == "1"
    assert "code-1" in authorization_server.authorization_codes

    monkeypatch.setattr(authorization_server, "issue_token_pair", original_issue)
    oauth_store.insert_refresh_token("refresh-1", CLIENT_ID, "")
    monkeypatch.setattr(authorization_server, "rotate_refresh_token", database_failure)
    refresh_response = authorization_http.post(
        "/token",
        data={"grant_type": "refresh_token", "refresh_token": "refresh-1"},
        headers=basic_header(CLIENT_ID, CLIENT_SECRET),
    )
    assert refresh_response.status_code == 503
    assert refresh_response.get_json() == {"error": "temporarily_unavailable"}
    assert refresh_response.headers["Retry-After"] == "1"


def test_approval_issues_code_bound_to_client_redirect_empty_scope_and_pkce(
    authorization_http, authorization_server
):
    challenge = authorization_server.generate_code_challenge(VERIFIER)
    authorize_response = authorization_http.get(
        "/authorize",
        query_string={
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "state": "state-1",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
        },
    )
    assert authorize_response.status_code == 200
    reqid = next(iter(authorization_server.approval_requests))

    approval_response = authorization_http.post(
        "/approve", data={"reqid": reqid, "approve": "Approve"}
    )

    assert approval_response.status_code == 302
    query = parse_qs(urlsplit(approval_response.headers["Location"]).query)
    assert query["state"] == ["state-1"]
    code = query["code"][0]
    assert authorization_server.authorization_codes[code] == {
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": [],
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }


def test_token_endpoint_rejects_json_with_controlled_oauth_error(
    authorization_http, authorization_server
):
    seed_code(authorization_server)

    response = authorization_http.post(
        "/token",
        json=token_form(),
        headers=basic_header(CLIENT_ID, CLIENT_SECRET),
    )

    assert response.status_code == 400
    assert response.get_json() == {"error": "invalid_request"}
    assert "code-1" in authorization_server.authorization_codes


def test_concurrent_code_redemption_issues_exactly_one_persisted_pair(
    authorization_server, oauth_store, monkeypatch
):
    seed_code(authorization_server)

    class ObservableLock:
        def __init__(self):
            self._lock = Lock()
            self._counter_lock = Lock()
            self._attempts = 0
            self.second_attempted = Event()

        def __enter__(self):
            with self._counter_lock:
                self._attempts += 1
                if self._attempts == 2:
                    self.second_attempted.set()
            self._lock.acquire()
            return self

        def __exit__(self, *_args):
            self._lock.release()

    observable_lock = ObservableLock()
    monkeypatch.setattr(
        authorization_server, "authorization_code_lock", observable_lock
    )

    original_issue = authorization_server.issue_token_pair
    first_issue_started = Event()
    release_first_issue = Event()

    def controlled_issue(*args, **kwargs):
        first_issue_started.set()
        assert release_first_issue.wait(timeout=5)
        return original_issue(*args, **kwargs)

    monkeypatch.setattr(authorization_server, "issue_token_pair", controlled_issue)
    start_barrier = Barrier(3)

    def redeem_code():
        with authorization_server.app.test_client() as http:
            start_barrier.wait(timeout=5)
            response = http.post(
                "/token",
                data=token_form(),
                headers=basic_header(CLIENT_ID, CLIENT_SECRET),
            )
            return response.status_code, response.get_json()

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = [executor.submit(redeem_code) for _ in range(2)]
        start_barrier.wait(timeout=5)
        assert first_issue_started.wait(timeout=5)
        assert observable_lock.second_attempted.wait(timeout=5)
        release_first_issue.set()
        outcomes = [future.result(timeout=5) for future in futures]

    assert sorted(status for status, _body in outcomes) == [200, 400]
    assert all(status != 500 for status, _body in outcomes)
    assert [body for status, body in outcomes if status == 400] == [
        {"error": "invalid_grant"}
    ]

    successful_body = next(body for status, body in outcomes if status == 200)
    assert oauth_store.find_access_token(successful_body["access_token"]) is not None
    assert oauth_store.find_refresh_token(successful_body["refresh_token"]) is not None
    with oauth_store._connect() as connection:
        access_count = connection.execute(
            "SELECT COUNT(*) FROM access_tokens"
        ).fetchone()[0]
        refresh_count = connection.execute(
            "SELECT COUNT(*) FROM refresh_tokens"
        ).fetchone()[0]
    assert (access_count, refresh_count) == (1, 1)
