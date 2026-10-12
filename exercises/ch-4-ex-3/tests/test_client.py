from unittest.mock import Mock

import pytest
import requests

from helpers import (
    FULL_PRODUCE,
    TEST_CODE_CHALLENGE,
    TEST_CODE_VERIFIER,
    generate_test_code_challenge,
    oauth_form_headers,
    oauth_response,
    redirect_query,
)


def test_client_pkce_helpers_and_authorization_request_contract(
    client_module, client_http, monkeypatch
):
    assert client_module.generate_code_challenge(TEST_CODE_VERIFIER) == TEST_CODE_CHALLENGE
    generated = {client_module.generate_code_verifier() for _ in range(32)}
    assert len(generated) == 32
    assert all(43 <= len(value) <= 128 for value in generated)
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
    assert all(set(value) <= allowed for value in generated)

    monkeypatch.setattr(client_module, "generate_code_verifier", lambda: TEST_CODE_VERIFIER)
    client_module.access_token = "old-access"
    client_module.refresh_token = "old-refresh"
    client_module.scope = "old-scope"
    response = client_http.get("/authorize")
    parsed, params = redirect_query(response)

    assert response.status_code == 302
    assert parsed.geturl().startswith("http://localhost:9001/authorize?")
    assert set(params) == {
        "response_type",
        "client_id",
        "redirect_uri",
        "scope",
        "state",
        "code_challenge",
        "code_challenge_method",
    }
    assert params["response_type"] == "code"
    assert params["client_id"] == "oauth-client-1"
    assert params["redirect_uri"] == "http://localhost:9000/callback"
    assert params["scope"] == "fruit veggies meats"
    assert params["state"] == client_module.state and params["state"]
    assert params["code_challenge"] == generate_test_code_challenge(TEST_CODE_VERIFIER)
    assert params["code_challenge_method"] == "S256"
    assert client_module.code_verifier == TEST_CODE_VERIFIER
    assert client_module.access_token is None
    assert client_module.refresh_token is None
    assert client_module.scope is None


def test_callback_state_guard_blocks_requests_and_preserves_pending_exchange(
    client_module, client_http, requests_post
):
    client_module.state = "expected"
    client_module.code_verifier = TEST_CODE_VERIFIER
    for query in ({"code": "code"}, {"state": "wrong", "code": "code"}):
        response = client_http.get("/callback", query_string=query)
        assert response.status_code == 200
        assert b"State value did not match" in response.data
        assert client_module.state == "expected"
        assert client_module.code_verifier == TEST_CODE_VERIFIER
    requests_post.assert_not_called()


def test_callback_posts_exact_contract_and_stores_complete_token_pair(
    client_module, client_http, requests_post
):
    client_module.state = "expected-state"
    client_module.code_verifier = TEST_CODE_VERIFIER
    requests_post.side_effect = None
    requests_post.return_value = oauth_response(
        payload={
            "access_token": "access-123",
            "token_type": "bEaReR",
            "refresh_token": "refresh-123",
            "scope": "fruit meats",
        }
    )
    response = client_http.get(
        "/callback", query_string={"state": "expected-state", "code": "code-123"}
    )

    assert response.status_code == 200
    requests_post.assert_called_once_with(
        "http://localhost:9001/token",
        data={
            "grant_type": "authorization_code",
            "code": "code-123",
            "redirect_uri": "http://localhost:9000/callback",
            "code_verifier": TEST_CODE_VERIFIER,
        },
        headers=oauth_form_headers(),
        timeout=5,
        allow_redirects=False,
    )
    assert client_module.state is None and client_module.code_verifier is None
    assert client_module.access_token == "access-123"
    assert client_module.refresh_token == "refresh-123"
    assert client_module.scope == "fruit meats"


@pytest.mark.parametrize(
    "response",
    [
        oauth_response(
            status=302,
            payload={
                "access_token": "a",
                "token_type": "Bearer",
                "refresh_token": "r",
                "scope": "fruit",
            },
        ),
        oauth_response(status=400, payload={"error": "invalid_grant"}),
        oauth_response(raw_body=b'{"access_token":'),
        oauth_response(payload=["not", "an", "object"]),
        oauth_response(
            payload={"token_type": "Bearer", "refresh_token": "r", "scope": "fruit"}
        ),
        oauth_response(
            payload={
                "access_token": "",
                "token_type": "Bearer",
                "refresh_token": "r",
                "scope": "fruit",
            }
        ),
        oauth_response(
            payload={"access_token": "a", "token_type": "Bearer", "scope": "fruit"}
        ),
        oauth_response(
            payload={
                "access_token": "a",
                "token_type": "Bearer",
                "refresh_token": "",
                "scope": "fruit",
            }
        ),
        oauth_response(
            payload={
                "access_token": "a",
                "token_type": "Bearer",
                "refresh_token": "r",
                "scope": None,
            }
        ),
        oauth_response(
            payload={"access_token": "a", "refresh_token": "r", "scope": "fruit"}
        ),
        oauth_response(
            payload={
                "access_token": "a",
                "token_type": "Basic",
                "refresh_token": "r",
                "scope": "fruit",
            }
        ),
        oauth_response(
            payload={
                "access_token": "a",
                "token_type": 1,
                "refresh_token": "r",
                "scope": "fruit",
            }
        ),
    ],
    ids=[
        "redirect",
        "rejection",
        "malformed-json",
        "array",
        "missing-access",
        "empty-access",
        "missing-refresh",
        "empty-refresh",
        "bad-scope",
        "missing-token-type",
        "wrong-token-type",
        "non-string-token-type",
    ],
)
def test_callback_rejects_non_2xx_or_invalid_json_shape(
    client_module, client_http, requests_post, response
):
    client_module.state = "expected"
    client_module.code_verifier = TEST_CODE_VERIFIER
    requests_post.side_effect = None
    requests_post.return_value = response
    result = client_http.get(
        "/callback", query_string={"state": "expected", "code": "code"}
    )
    assert result.status_code == 200
    assert client_module.access_token is None
    assert client_module.refresh_token is None
    assert client_module.scope is None


def test_callback_connection_error_is_controlled(
    client_module, client_http, requests_post
):
    client_module.state = "expected"
    client_module.code_verifier = TEST_CODE_VERIFIER
    requests_post.side_effect = requests.Timeout("token timeout")
    response = client_http.get(
        "/callback", query_string={"state": "expected", "code": "code"}
    )
    assert response.status_code == 200
    assert b"Unable to fetch token pair" in response.data


def test_produce_get_uses_exact_contract_and_validates_json(
    client_module, client_http, requests_get, requests_post
):
    client_module.access_token = "access-123"
    client_module.scope = "fruit veggies meats"
    requests_get.side_effect = None
    requests_get.return_value = oauth_response(payload=FULL_PRODUCE)
    response = client_http.get("/produce")

    assert response.status_code == 200
    for value in (b"apple", b"lettuce", b"steak"):
        assert value in response.data
    requests_get.assert_called_once_with(
        "http://localhost:9002/produce",
        headers={"Authorization": "Bearer access-123"},
        timeout=5,
        allow_redirects=False,
    )
    requests_post.assert_not_called()


@pytest.mark.parametrize(
    "payload",
    [
        None,
        ["not", "an", "object"],
        {"fruit": [], "veggies": []},
        {"fruit": [], "veggies": [], "meats": [], "extra": []},
        {"fruit": "apple", "veggies": [], "meats": []},
        {"fruit": [1], "veggies": [], "meats": []},
    ],
    ids=["malformed", "array", "missing-key", "extra-key", "non-list", "non-string-item"],
)
def test_produce_rejects_invalid_json_shapes(
    client_module, client_http, requests_get, payload
):
    client_module.access_token = "access"
    requests_get.side_effect = None
    requests_get.return_value = (
        oauth_response(raw_body=b'{"fruit":')
        if payload is None
        else oauth_response(payload=payload)
    )
    response = client_http.get("/produce")
    assert response.status_code == 200
    assert b"invalid JSON object" in response.data


def test_first_401_refreshes_once_then_directly_retries_with_rotated_access(
    client_module, client_http, requests_get, requests_post
):
    client_module.access_token = "expired-access"
    client_module.refresh_token = "refresh-1"
    client_module.scope = "fruit"
    requests_get.side_effect = [
        oauth_response(status=401, payload={"error": "invalid_token"}),
        oauth_response(payload=FULL_PRODUCE),
    ]
    requests_post.side_effect = None
    requests_post.return_value = oauth_response(
        payload={
            "access_token": "replacement-access",
            "token_type": "bearer",
            "refresh_token": "refresh-2",
            "scope": "fruit",
        }
    )

    response = client_http.get("/produce")
    assert response.status_code == 200 and b"apple" in response.data
    assert requests_get.call_count == 2
    assert requests_get.call_args_list[0].kwargs["headers"] == {
        "Authorization": "Bearer expired-access"
    }
    assert requests_get.call_args_list[1].kwargs["headers"] == {
        "Authorization": "Bearer replacement-access"
    }
    requests_post.assert_called_once_with(
        "http://localhost:9001/token",
        data={"grant_type": "refresh_token", "refresh_token": "refresh-1"},
        headers=oauth_form_headers(),
        timeout=5,
        allow_redirects=False,
    )
    assert client_module.access_token == "replacement-access"
    assert client_module.refresh_token == "refresh-2"
    assert client_module.scope == "fruit"


@pytest.mark.parametrize("status", [302, 403, 500])
def test_non_401_produce_status_never_refreshes(
    client_module, client_http, requests_get, requests_post, status
):
    client_module.access_token = "access"
    client_module.refresh_token = "refresh"
    requests_get.side_effect = None
    requests_get.return_value = oauth_response(status=status, payload=FULL_PRODUCE)
    response = client_http.get("/produce")
    assert response.status_code == 200
    assert f"Status {status}".encode() in response.data
    assert client_module.access_token is None
    assert client_module.refresh_token == "refresh"
    requests_post.assert_not_called()


def test_second_401_is_final_with_no_refresh_loop(
    client_module, client_http, requests_get, requests_post
):
    client_module.access_token = "expired"
    client_module.refresh_token = "refresh-1"
    requests_get.side_effect = [
        oauth_response(status=401, payload={"error": "invalid_token"}),
        oauth_response(status=401, payload={"error": "invalid_token"}),
    ]
    requests_post.side_effect = None
    requests_post.return_value = oauth_response(
        payload={
            "access_token": "replacement",
            "token_type": "Bearer",
            "refresh_token": "refresh-2",
            "scope": "veggies",
        }
    )
    response = client_http.get("/produce")
    assert response.status_code == 200 and b"Status 401" in response.data
    assert requests_get.call_count == 2
    assert requests_post.call_count == 1
    assert client_module.access_token is None
    assert client_module.refresh_token == "refresh-2"


@pytest.mark.parametrize(
    "failure",
    [
        oauth_response(
            status=302,
            payload={
                "access_token": "a",
                "token_type": "Bearer",
                "refresh_token": "r",
                "scope": "fruit",
            },
        ),
        oauth_response(status=400, payload={"error": "invalid_grant"}),
        oauth_response(raw_body=b'{"access_token":'),
        oauth_response(
            payload={"access_token": "a", "token_type": "Bearer", "scope": "fruit"}
        ),
        oauth_response(
            payload={"access_token": "a", "refresh_token": "r", "scope": "fruit"}
        ),
        oauth_response(
            payload={
                "access_token": "a",
                "token_type": "Basic",
                "refresh_token": "r",
                "scope": "fruit",
            }
        ),
        oauth_response(
            payload={
                "access_token": "a",
                "token_type": 1,
                "refresh_token": "r",
                "scope": "fruit",
            }
        ),
        oauth_response(
            payload={
                "access_token": "a",
                "token_type": "Bearer",
                "refresh_token": "r",
                "scope": None,
            }
        ),
    ],
    ids=[
        "redirect",
        "rejection",
        "malformed",
        "missing-rotation",
        "missing-token-type",
        "wrong-token-type",
        "non-string-token-type",
        "non-string-scope",
    ],
)
def test_refresh_failure_clears_unusable_tokens(
    client_module, requests_post, failure
):
    client_module.access_token = "old-access"
    client_module.refresh_token = "old-refresh"
    client_module.scope = "old-scope"
    requests_post.side_effect = None
    requests_post.return_value = failure
    assert client_module.refresh_access_token() is False
    assert client_module.access_token is None
    assert client_module.refresh_token is None
    assert client_module.scope is None


def test_refresh_without_token_clears_all_token_state(client_module, requests_post):
    client_module.access_token = "stale-access"
    client_module.refresh_token = None
    client_module.scope = "stale-scope"

    assert client_module.refresh_access_token() is False
    assert client_module.access_token is None
    assert client_module.refresh_token is None
    assert client_module.scope is None
    requests_post.assert_not_called()


def test_get_and_refresh_connection_failures_are_controlled(
    client_module, client_http, requests_get, requests_post
):
    client_module.access_token = "access"
    client_module.refresh_token = "refresh"
    requests_get.side_effect = requests.Timeout("resource timeout")
    response = client_http.get("/produce")
    assert response.status_code == 200
    assert b"Unable to call the Produce API" in response.data
    assert client_module.access_token is None
    requests_post.assert_not_called()

    client_module.access_token = "expired"
    client_module.refresh_token = "refresh"
    client_module.scope = "old-scope"
    requests_get.reset_mock(side_effect=True)
    requests_get.side_effect = [oauth_response(status=401, payload={"error": "invalid_token"})]
    requests_post.side_effect = requests.Timeout("refresh timeout")
    response = client_http.get("/produce")
    assert response.status_code == 200
    assert b"Unable to refresh" in response.data
    assert client_module.access_token is None
    assert client_module.refresh_token is None
    assert client_module.scope is None


def test_empty_produce_arrays_are_valid(client_module, client_http, requests_get):
    client_module.access_token = "access"
    requests_get.side_effect = None
    requests_get.return_value = oauth_response(
        payload={"fruit": [], "veggies": [], "meats": []}
    )
    response = client_http.get("/produce")
    assert response.status_code == 200
    assert b"invalid JSON object" not in response.data
