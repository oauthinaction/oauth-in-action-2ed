from unittest.mock import Mock

import pytest
import requests

from helpers import (
    TEST_CODE_CHALLENGE,
    TEST_CODE_VERIFIER,
    generate_test_code_challenge,
    http_response,
    oauth_form_headers,
    redirect_query,
)


def test_url_basic_and_pkce_helpers_match_protocol_contract(client_module):
    assert client_module.build_url(
        "https://server.example/authorize?keep=yes#chapter",
        {"state": "a value", "keep": "updated"},
    ) == "https://server.example/authorize?keep=updated&state=a+value#chapter"
    assert "Basic " + client_module.encode_client_credentials(
        "client id", "secret:+ value"
    ) == oauth_form_headers("client id", "secret:+ value")["Authorization"]
    assert generate_test_code_challenge(TEST_CODE_VERIFIER) == TEST_CODE_CHALLENGE
    assert client_module.generate_code_challenge(TEST_CODE_VERIFIER) == TEST_CODE_CHALLENGE


def test_generated_pkce_verifiers_are_fresh_and_canonical(client_module):
    allowed = set(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
    )
    verifiers = {client_module.generate_code_verifier() for _ in range(32)}
    assert len(verifiers) == 32
    for verifier in verifiers:
        assert 43 <= len(verifier) <= 128
        assert set(verifier) <= allowed
        challenge = client_module.generate_code_challenge(verifier)
        assert len(challenge) == 43 and "=" not in challenge


def test_authorize_clears_tokens_and_sends_exact_scope_state_pkce(
    client_module, client_http, monkeypatch
):
    monkeypatch.setattr(client_module, "generate_code_verifier", lambda: TEST_CODE_VERIFIER)
    client_module.access_token = "old-access"
    client_module.refresh_token = "old-refresh"
    client_module.scope = "old-scope"

    response = client_http.get("/authorize")
    parsed, params = redirect_query(response)

    assert response.status_code == 302
    assert (parsed.scheme, parsed.netloc, parsed.path) == (
        "http", "localhost:9001", "/authorize"
    )
    assert set(params) == {
        "response_type",
        "client_id",
        "redirect_uri",
        "scope",
        "state",
        "code_challenge",
        "code_challenge_method",
    }
    assert params == {
        "response_type": "code",
        "client_id": "oauth-client-1",
        "redirect_uri": "http://localhost:9000/callback",
        "scope": "read write delete",
        "state": client_module.state,
        "code_challenge": TEST_CODE_CHALLENGE,
        "code_challenge_method": "S256",
    }
    assert client_module.code_verifier == TEST_CODE_VERIFIER
    assert client_module.access_token is None
    assert client_module.refresh_token is None
    assert client_module.scope is None


def test_callback_rejects_state_before_any_token_request(
    client_module, client_http, requests_post
):
    client_module.state = "expected"
    client_module.code_verifier = TEST_CODE_VERIFIER
    response = client_http.get(
        "/callback", query_string={"state": "wrong", "code": "code-1"}
    )
    assert response.status_code == 200
    assert b"State value did not match" in response.data
    requests_post.assert_not_called()
    assert client_module.state == "expected"
    assert client_module.code_verifier == TEST_CODE_VERIFIER


def test_callback_authorization_error_consumes_state_and_verifier(
    client_module, client_http, requests_post
):
    client_module.state = "expected"
    client_module.code_verifier = TEST_CODE_VERIFIER
    response = client_http.get(
        "/callback", query_string={"state": "expected", "error": "access_denied"}
    )
    assert response.status_code == 200
    assert b"access_denied" in response.data
    requests_post.assert_not_called()
    assert client_module.state is None
    assert client_module.code_verifier is None


def test_callback_posts_exact_basic_form_contract_and_accepts_201(
    client_module, client_http, requests_post
):
    client_module.state = "expected"
    client_module.code_verifier = TEST_CODE_VERIFIER
    requests_post.side_effect = None
    requests_post.return_value = http_response(
        201,
        {
            "access_token": "access-1",
            "refresh_token": "refresh-1",
            "token_type": "bEaReR",
            "scope": "read write",
        },
    )

    response = client_http.get(
        "/callback", query_string={"state": "expected", "code": "code-1"}
    )

    assert response.status_code == 200
    requests_post.assert_called_once_with(
        "http://localhost:9001/token",
        data={
            "grant_type": "authorization_code",
            "code": "code-1",
            "redirect_uri": "http://localhost:9000/callback",
            "code_verifier": TEST_CODE_VERIFIER,
        },
        headers=oauth_form_headers(),
        timeout=5,
        allow_redirects=False,
    )
    assert client_module.state is None
    assert client_module.code_verifier is None
    assert client_module.access_token == "access-1"
    assert client_module.refresh_token == "refresh-1"
    assert client_module.scope == "read write"


@pytest.mark.parametrize("status", [199, 300, 302])
def test_callback_accepts_only_exact_2xx(status, client_module, client_http, requests_post):
    client_module.state = "expected"
    client_module.code_verifier = TEST_CODE_VERIFIER
    requests_post.side_effect = None
    requests_post.return_value = http_response(
        status,
        {"access_token": "bad", "refresh_token": "bad", "scope": "read"},
    )
    response = client_http.get(
        "/callback", query_string={"state": "expected", "code": "code-1"}
    )
    assert response.status_code == 200
    assert f"server response: {status}".encode() in response.data
    assert client_module.access_token is None
    assert client_module.refresh_token is None


@pytest.mark.parametrize(
    "response",
    [
        http_response(200, raw_body=b'{"access_token":'),
        http_response(200, ["not", "an", "object"]),
        http_response(
            200,
            {
                "access_token": "only-one-token",
                "token_type": "Bearer",
                "scope": "read",
            },
        ),
        http_response(
            200,
            {
                "access_token": "access",
                "refresh_token": "refresh",
                "scope": "read",
            },
        ),
        http_response(
            200,
            {
                "access_token": "access",
                "refresh_token": "refresh",
                "token_type": "MAC",
                "scope": "read",
            },
        ),
        http_response(
            200,
            {
                "access_token": "access",
                "refresh_token": "refresh",
                "token_type": "Bearer",
                "scope": ["read"],
            },
        ),
    ],
    ids=[
        "malformed-json",
        "non-object-json",
        "incomplete-token-pair",
        "missing-token-type",
        "wrong-token-type",
        "non-string-scope",
    ],
)
def test_callback_rejects_invalid_success_payload(
    response, client_module, client_http, requests_post
):
    client_module.state = "expected"
    client_module.code_verifier = TEST_CODE_VERIFIER
    requests_post.side_effect = None
    requests_post.return_value = response
    result = client_http.get(
        "/callback", query_string={"state": "expected", "code": "code-1"}
    )
    assert result.status_code == 200
    assert b"invalid token response" in result.data
    assert client_module.access_token is None
    assert client_module.refresh_token is None
    assert client_module.scope is None


def test_callback_connection_failure_is_rendered_not_500(
    client_module, client_http, requests_post
):
    client_module.state = "expected"
    client_module.code_verifier = TEST_CODE_VERIFIER
    requests_post.side_effect = requests.ConnectionError("token endpoint unavailable")
    response = client_http.get(
        "/callback", query_string={"state": "expected", "code": "code-1"}
    )
    assert response.status_code == 200
    assert b"Unable to fetch token pair" in response.data
    assert client_module.access_token is None


def test_words_get_uses_exact_url_bearer_timeout_and_redirect_policy(
    client_module, client_http, requests_get
):
    client_module.access_token = "access-1"
    requests_get.side_effect = None
    requests_get.return_value = http_response(
        200, {"words": "alpha beta", "timestamp": 1700000000123}
    )
    response = client_http.get("/get_words")
    assert response.status_code == 200
    assert b"GET succeeded." in response.data
    assert b"alpha beta" in response.data
    requests_get.assert_called_once_with(
        "http://localhost:9002/words",
        headers={"Authorization": "Bearer access-1"},
        timeout=5,
        allow_redirects=False,
    )


def test_words_post_uses_exact_form_contract_and_never_decodes_empty_201(
    client_module, client_http, requests_post
):
    client_module.access_token = "access-1"
    empty_success = Mock(status_code=201)
    empty_success.json.side_effect = AssertionError("empty POST success must not be decoded")
    requests_post.side_effect = None
    requests_post.return_value = empty_success
    response = client_http.get("/add_word", query_string={"word": "gamma"})
    assert response.status_code == 200
    assert b"POST succeeded." in response.data
    assert b"201" in response.data
    requests_post.assert_called_once_with(
        "http://localhost:9002/words",
        data={"word": "gamma"},
        headers={
            "Authorization": "Bearer access-1",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        timeout=5,
        allow_redirects=False,
    )
    empty_success.json.assert_not_called()


def test_words_delete_uses_exact_contract_and_never_decodes_empty_204(
    client_module, client_http, requests_delete
):
    client_module.access_token = "access-1"
    empty_success = Mock(status_code=204)
    empty_success.json.side_effect = AssertionError("empty DELETE success must not be decoded")
    requests_delete.side_effect = None
    requests_delete.return_value = empty_success
    response = client_http.get("/delete_word")
    assert response.status_code == 200
    assert b"DELETE succeeded." in response.data
    assert b"204" in response.data
    requests_delete.assert_called_once_with(
        "http://localhost:9002/words",
        headers={"Authorization": "Bearer access-1"},
        timeout=5,
        allow_redirects=False,
    )
    empty_success.json.assert_not_called()


def test_words_get_accepts_201_and_requires_valid_json(
    client_module, client_http, requests_get
):
    client_module.access_token = "access-1"
    requests_get.side_effect = None
    requests_get.return_value = http_response(
        201, {"words": "created view", "timestamp": 12.5}
    )
    response = client_http.get("/get_words")
    assert b"GET succeeded." in response.data
    assert b"201" in response.data


def test_first_401_refreshes_once_then_retries_get_with_rotated_bearer(
    client_module, client_http, requests_get, requests_post
):
    client_module.access_token = "expired-access"
    client_module.refresh_token = "refresh-1"
    client_module.scope = "read"
    requests_get.side_effect = [
        http_response(401, {"error": "invalid_token"}),
        http_response(200, {"words": "fresh", "timestamp": 1234}),
    ]
    requests_post.side_effect = None
    requests_post.return_value = http_response(
        200,
        {
            "access_token": "replacement-access",
            "refresh_token": "refresh-2",
            "token_type": "Bearer",
            "scope": "read",
        },
    )

    response = client_http.get("/get_words")

    assert response.status_code == 200 and b"fresh" in response.data
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
    assert client_module.refresh_token == "refresh-2"


def test_second_401_is_final_without_second_refresh(
    client_module, client_http, requests_get, requests_post
):
    client_module.access_token = "expired-access"
    client_module.refresh_token = "refresh-1"
    requests_get.side_effect = [
        http_response(401, {"error": "invalid_token"}),
        http_response(401, {"error": "invalid_token"}),
    ]
    requests_post.side_effect = None
    requests_post.return_value = http_response(
        200,
        {
            "access_token": "replacement-access",
            "refresh_token": "refresh-2",
            "token_type": "Bearer",
            "scope": "read",
        },
    )
    response = client_http.get("/get_words")
    assert b"GET failed with status 401." in response.data
    assert requests_get.call_count == 2
    assert requests_post.call_count == 1
    assert client_module.access_token is None
    assert client_module.refresh_token == "refresh-2"


@pytest.mark.parametrize("status", [302, 403, 500])
def test_non_401_resource_response_never_refreshes(
    status, client_module, client_http, requests_get, requests_post
):
    client_module.access_token = "access-1"
    client_module.refresh_token = "refresh-1"
    requests_get.side_effect = None
    requests_get.return_value = http_response(status, {"error": "failure"})
    response = client_http.get("/get_words")
    assert f"GET failed with status {status}.".encode() in response.data
    assert client_module.access_token is None
    assert client_module.refresh_token == "refresh-1"
    requests_post.assert_not_called()


def test_refresh_posts_exact_contract_accepts_2xx_and_rotates_all_state(
    client_module, requests_post
):
    client_module.access_token = "old-access"
    client_module.refresh_token = "old-refresh"
    client_module.scope = "old-scope"
    requests_post.side_effect = None
    requests_post.return_value = http_response(
        202,
        {
            "access_token": "new-access",
            "refresh_token": "new-refresh",
            "token_type": "BEARER",
            "scope": "read delete",
        },
    )
    assert client_module.refresh_access_token() is True
    requests_post.assert_called_once_with(
        "http://localhost:9001/token",
        data={"grant_type": "refresh_token", "refresh_token": "old-refresh"},
        headers=oauth_form_headers(),
        timeout=5,
        allow_redirects=False,
    )
    assert (
        client_module.access_token,
        client_module.refresh_token,
        client_module.scope,
    ) == ("new-access", "new-refresh", "read delete")


@pytest.mark.parametrize(
    "token_response",
    [
        http_response(
            302,
            {
                "access_token": "a",
                "refresh_token": "r",
                "token_type": "Bearer",
                "scope": "read",
            },
        ),
        http_response(400, {"error": "invalid_grant"}),
        http_response(200, raw_body=b"not-json"),
        http_response(
            200,
            {
                "access_token": "missing-rotation",
                "token_type": "Bearer",
                "scope": "read",
            },
        ),
        http_response(
            200,
            {
                "access_token": "",
                "refresh_token": "new-refresh",
                "token_type": "Bearer",
                "scope": "read",
            },
        ),
        http_response(
            200,
            {
                "access_token": "new-access",
                "refresh_token": "new-refresh",
                "scope": "read",
            },
        ),
        http_response(
            200,
            {
                "access_token": "new-access",
                "refresh_token": "new-refresh",
                "token_type": "MAC",
                "scope": "read",
            },
        ),
        http_response(
            200,
            {
                "access_token": "new-access",
                "refresh_token": "new-refresh",
                "token_type": "Bearer",
                "scope": ["read"],
            },
        ),
    ],
    ids=[
        "redirect",
        "oauth-error",
        "malformed-json",
        "missing-refresh",
        "empty-access",
        "missing-token-type",
        "wrong-token-type",
        "non-string-scope",
    ],
)
def test_refresh_failure_clears_unusable_token_state(
    token_response, client_module, requests_post
):
    client_module.access_token = "old-access"
    client_module.refresh_token = "old-refresh"
    client_module.scope = "old-scope"
    requests_post.side_effect = None
    requests_post.return_value = token_response
    assert client_module.refresh_access_token() is False
    assert (
        client_module.access_token,
        client_module.refresh_token,
        client_module.scope,
    ) == (None, None, None)


def test_refresh_without_token_clears_all_state(client_module, requests_post):
    client_module.access_token = "old-access"
    client_module.refresh_token = None
    client_module.scope = "old-scope"

    assert client_module.refresh_access_token() is False
    assert (
        client_module.access_token,
        client_module.refresh_token,
        client_module.scope,
    ) == (None, None, None)
    requests_post.assert_not_called()


def test_refresh_exception_clears_all_state(client_module, requests_post):
    client_module.access_token = "old-access"
    client_module.refresh_token = "old-refresh"
    client_module.scope = "old-scope"
    requests_post.side_effect = requests.ConnectionError("token endpoint unavailable")

    assert client_module.refresh_access_token() is False
    assert (
        client_module.access_token,
        client_module.refresh_token,
        client_module.scope,
    ) == (None, None, None)


def test_resource_connection_failure_is_rendered_and_clears_access(
    client_module, client_http, requests_get
):
    client_module.access_token = "access-1"
    requests_get.side_effect = requests.ConnectionError("resource unavailable")
    response = client_http.get("/get_words")
    assert response.status_code == 200
    assert b"Unable to call the Words API" in response.data
    assert client_module.access_token is None
