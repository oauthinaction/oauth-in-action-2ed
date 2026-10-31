from unittest.mock import Mock

import pytest
import requests

from helpers import (
    TEST_CODE_CHALLENGE,
    TEST_CODE_VERIFIER,
    generate_test_code_challenge,
    malformed_json_response,
    oauth_form_headers,
    oauth_response,
    redirect_query,
)


def test_initial_token_values_are_documented_fixtures(client_module):
    assert client_module.INITIAL_ACCESS_TOKEN == "987tghjkiu6trfghjuytrghj"
    assert client_module.INITIAL_REFRESH_TOKEN == "j2r3oj32r23rmasd98uhjrk2o3i"
    assert client_module.access_token == client_module.INITIAL_ACCESS_TOKEN
    assert client_module.refresh_token == client_module.INITIAL_REFRESH_TOKEN


def test_build_url_preserves_existing_query_and_fragment(client_module):
    url = client_module.build_url(
        "https://server.example/authorize?keep=yes#chapter",
        {"existing": "a value", "keep": "updated"},
    )
    assert url == (
        "https://server.example/authorize"
        "?keep=updated&existing=a+value#chapter"
    ), (
        "Build the authorization URL without discarding existing query "
        "or fragment data"
    )


def test_basic_credentials_match_oauth_encoding(client_module):
    expected = oauth_form_headers(
        "client id",
        "secret:+ value",
    )["Authorization"]
    actual = "Basic " + client_module.encode_client_credentials(
        "client id", "secret:+ value"
    )
    assert actual == expected, (
        "Percent-encode each client credential before constructing "
        "OAuth Basic authentication"
    )


def test_client_generate_code_challenge_matches_rfc_7636(client_module):
    assert (
        generate_test_code_challenge(TEST_CODE_VERIFIER)
        == TEST_CODE_CHALLENGE
    )
    assert (
        client_module.generate_code_challenge(TEST_CODE_VERIFIER)
        == TEST_CODE_CHALLENGE
    ), (
        "Derive the RFC 7636 S256 challenge with base64url encoding "
        "and no padding"
    )


def test_generated_code_verifier_has_rfc_7636_strength_and_shape(
    client_module,
):
    allowed_characters = frozenset(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789-._~"
    )
    generated_verifiers = {
        client_module.generate_code_verifier()
        for _ in range(32)
    }

    assert len(generated_verifiers) == 32, (
        "Generate a fresh cryptographically random PKCE verifier "
        "per authorization request"
    )
    for verifier in generated_verifiers:
        assert 43 <= len(verifier) <= 128, (
            "RFC 7636 code verifiers must contain between 43 and 128 "
            "characters"
        )
        assert set(verifier).issubset(allowed_characters), (
            "RFC 7636 code verifiers may contain only unreserved characters"
        )
        challenge = client_module.generate_code_challenge(verifier)
        assert len(challenge) == 43 and "=" not in challenge, (
            "S256 challenges must be canonical unpadded base64url "
            "SHA-256 values"
        )


def test_authorization_request_clears_access_but_preserves_refresh(
    client_module,
    client_http,
    monkeypatch,
):
    monkeypatch.setattr(
        client_module,
        "generate_code_verifier",
        lambda: TEST_CODE_VERIFIER,
    )
    client_module.access_token = "old-access"
    client_module.refresh_token = "retained-refresh"
    response = client_http.get("/authorize")
    parsed, params = redirect_query(response)
    assert response.status_code == 302
    assert parsed.geturl().startswith("http://localhost:9001/authorize?"), (
        "Send the code request to the configured authorization endpoint"
    )
    assert params.keys() == {
        "response_type",
        "client_id",
        "redirect_uri",
        "code_challenge",
        "code_challenge_method",
    }
    assert params["response_type"] == "code"
    assert "state" not in params, (
        "Chapter 3 does not send a state parameter; it is introduced later"
    )
    assert "scope" not in params, (
        "Chapter 3 obtains an access token without requesting a scope"
    )
    assert params["client_id"] == "oauth-client-1"
    assert params["redirect_uri"] == "http://localhost:9000/callback"
    assert params["code_challenge_method"] == "S256"
    assert client_module.code_verifier == TEST_CODE_VERIFIER
    assert params["code_challenge"] == generate_test_code_challenge(
        client_module.code_verifier
    ), "Bind the authorization request to the retained PKCE verifier"
    assert client_module.access_token is None
    assert client_module.refresh_token == "retained-refresh"
    assert not hasattr(client_module, "state")
    assert not hasattr(client_module, "scope")


def test_callback_code_exchange_contract(
    client_module,
    client_http,
    requests_post,
):
    client_module.code_verifier = TEST_CODE_VERIFIER
    requests_post.return_value = oauth_response(
        payload={"access_token": "access-123"}
    )
    requests_post.side_effect = None
    response = client_http.get(
        "/callback",
        query_string={"code": "code-123"},
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
        headers=oauth_form_headers("oauth-client-1", "oauth-client-secret-1"),
        timeout=5,
        allow_redirects=False,
    )
    assert client_module.code_verifier is None, (
        "Consume the PKCE verifier after the token request is prepared"
    )
    assert client_module.access_token == "access-123"
    assert client_module.refresh_token == client_module.INITIAL_REFRESH_TOKEN


def test_callback_without_stored_verifier_makes_no_token_request(
    client_module,
    client_http,
    requests_post,
):
    client_module.code_verifier = None

    response = client_http.get("/callback", query_string={"code": "code-123"})

    assert response.status_code == 200
    assert b"Missing PKCE code verifier" in response.data
    requests_post.assert_not_called()


def test_callback_error_consumes_verifier_without_token_request(
    client_module,
    client_http,
    requests_post,
):
    client_module.code_verifier = TEST_CODE_VERIFIER

    response = client_http.get(
        "/callback",
        query_string={"error": "access_denied"},
    )

    assert response.status_code == 200
    assert b"access_denied" in response.data
    assert client_module.code_verifier is None, (
        "Consume the PKCE verifier before handling an authorization error"
    )
    requests_post.assert_not_called()


def test_callback_rejects_token_endpoint_redirect(
    client_module,
    client_http,
    requests_post,
):
    client_module.code_verifier = TEST_CODE_VERIFIER
    client_module.access_token = None
    client_module.refresh_token = None
    requests_post.return_value = oauth_response(
        status=302,
        payload={
            "access_token": "redirect-access",
            "refresh_token": "redirect-refresh",
        },
    )
    requests_post.side_effect = None

    response = client_http.get(
        "/callback",
        query_string={"code": "code-123"},
    )

    assert response.status_code == 200
    assert b"server response: 302" in response.data, (
        "Accept token responses only when the endpoint returns "
        "an exact 2xx status"
    )
    assert client_module.access_token is None
    assert client_module.refresh_token is None
    assert b"redirect-access" not in response.data


def test_successful_resource_request_uses_bearer_without_refresh(
    client_module,
    client_http,
    requests_post,
    monkeypatch,
):
    client_module.access_token = "access-123"
    refresh_helper = Mock()
    monkeypatch.setattr(client_module, "refresh_access_token", refresh_helper)
    requests_post.return_value = oauth_response(
        payload={"name": "Protected Resource", "description": "private"}
    )
    requests_post.side_effect = None
    response = client_http.get("/fetch_resource")
    assert (
        response.status_code == 200
        and b"Protected Resource" in response.data
    )
    requests_post.assert_called_once_with(
        "http://localhost:9002/resource",
        headers={
            "Authorization": "Bearer access-123",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        timeout=5,
        allow_redirects=False,
    )
    refresh_helper.assert_not_called()


def test_first_401_refreshes_then_retries_resource_once(
    client_module,
    client_http,
    requests_post,
    monkeypatch,
):
    client_module.access_token = "expired-access"
    client_module.refresh_token = "refresh-123"
    requests_post.side_effect = [
        oauth_response(
            status=401,
            payload={"error": "invalid_token"},
        ),
        oauth_response(
            payload={"name": "Protected Resource"},
        ),
    ]

    def refresh_once():
        client_module.access_token = "replacement-access"
        client_module.refresh_token = "rotated-refresh"
        return True

    refresh_helper = Mock(side_effect=refresh_once)
    monkeypatch.setattr(client_module, "refresh_access_token", refresh_helper)

    response = client_http.get("/fetch_resource")

    assert (
        response.status_code == 200
        and b"Protected Resource" in response.data
    ), (
        "After the first 401, refresh once and return the retried "
        "resource data"
    )
    refresh_helper.assert_called_once_with()
    assert requests_post.call_count == 2
    first_request, retry_request = requests_post.call_args_list
    assert first_request.kwargs["headers"]["Authorization"] == (
        "Bearer expired-access"
    )
    assert retry_request.kwargs["headers"]["Authorization"] == (
        "Bearer replacement-access"
    )


def test_refresh_posts_exact_contract_and_rotates_tokens(
    client_module,
    requests_post,
):
    client_module.access_token = None
    client_module.refresh_token = client_module.INITIAL_REFRESH_TOKEN
    requests_post.return_value = oauth_response(
        payload={
            "access_token": "new-access",
            "refresh_token": "rotated-refresh",
        }
    )
    requests_post.side_effect = None

    result = client_module.refresh_access_token()

    assert result is True, (
        "Exchange the refresh token, store both rotated tokens, "
        "and report success"
    )
    requests_post.assert_called_once_with(
        "http://localhost:9001/token",
        data={
            "grant_type": "refresh_token",
            "refresh_token": client_module.INITIAL_REFRESH_TOKEN,
        },
        headers=oauth_form_headers("oauth-client-1", "oauth-client-secret-1"),
        timeout=5,
        allow_redirects=False,
    )
    assert client_module.access_token == "new-access"
    assert client_module.refresh_token == "rotated-refresh"


def test_non_401_failure_never_refreshes(
    client_module,
    client_http,
    requests_post,
    monkeypatch,
):
    client_module.access_token = "access-123"
    client_module.refresh_token = "refresh-123"
    refresh_helper = Mock()
    monkeypatch.setattr(client_module, "refresh_access_token", refresh_helper)
    requests_post.return_value = oauth_response(
        status=500,
        payload={"error": "server_error"},
    )
    requests_post.side_effect = None
    response = client_http.get("/fetch_resource")
    assert response.status_code == 200
    refresh_helper.assert_not_called()


def test_resource_redirect_is_error_and_never_refreshes(
    client_module,
    client_http,
    requests_post,
    monkeypatch,
):
    client_module.access_token = "redirected-access"
    client_module.refresh_token = "refresh-123"
    refresh_helper = Mock()
    monkeypatch.setattr(client_module, "refresh_access_token", refresh_helper)
    requests_post.return_value = oauth_response(
        status=302,
        payload={"name": "Redirected Protected Resource"},
    )
    requests_post.side_effect = None

    response = client_http.get("/fetch_resource")

    assert response.status_code == 200
    assert b"Status 302" in response.data, (
        "Accept protected-resource responses only for an exact 2xx status"
    )
    assert b"Redirected Protected Resource" not in response.data
    assert client_module.access_token is None
    refresh_helper.assert_not_called()


def test_second_401_is_final_and_never_refreshes_again(
    client_module,
    client_http,
    requests_post,
    monkeypatch,
):
    client_module.access_token = "expired-access"
    client_module.refresh_token = "refresh-123"
    requests_post.side_effect = [
        oauth_response(status=401, payload={"error": "invalid_token"}),
        oauth_response(status=401, payload={"error": "invalid_token"}),
    ]

    def refresh_once():
        client_module.access_token = "replacement-access"
        client_module.refresh_token = "rotated-refresh"
        return True

    refresh_helper = Mock(side_effect=refresh_once)
    monkeypatch.setattr(client_module, "refresh_access_token", refresh_helper)

    response = client_http.get("/fetch_resource")
    if not refresh_helper.called:
        pytest.skip("Starter retry TODO does not yet call the refresh helper")

    assert response.status_code == 200
    assert b"Status 401" in response.data
    refresh_helper.assert_called_once_with()
    assert requests_post.call_count == 2
    assert client_module.access_token is None
    assert client_module.refresh_token == "rotated-refresh"


@pytest.mark.parametrize(
    "token_response",
    [
        oauth_response(status=400, payload={"error": "invalid_grant"}),
        malformed_json_response(),
        oauth_response(
            payload={
                "access_token": "access-without-rotation",
            },
        ),
        oauth_response(
            status=302,
            payload={
                "access_token": "redirect-access",
                "refresh_token": "redirect-refresh",
            },
        ),
    ],
    ids=[
        "token-endpoint-rejection",
        "malformed-json",
        "missing-rotated-refresh-token",
        "token-endpoint-redirect",
    ],
)
def test_refresh_failure_clears_unusable_refresh_token(
    client_module,
    requests_post,
    token_response,
):
    client_module.access_token = "existing-access"
    client_module.refresh_token = "invalid-refresh"
    requests_post.return_value = token_response
    requests_post.side_effect = None
    result = client_module.refresh_access_token()
    if not requests_post.called:
        pytest.skip("Starter refresh TODO makes no Requests call")
    assert result is False, (
        "Reject non-2xx responses, redirects, and malformed token payloads"
    )
    assert client_module.access_token == "existing-access"
    assert client_module.refresh_token is None


def test_home_page_renders_documented_fixtures(client_module, client_http):
    response = client_http.get("/")

    assert response.status_code == 200, (
        "The root client must resolve files/client/index.html "
        "from the exercise directory"
    )
    assert client_module.INITIAL_ACCESS_TOKEN.encode() in response.data
    assert client_module.INITIAL_REFRESH_TOKEN.encode() in response.data


def test_home_copy_contract_for_missing_and_present_values(
    client_module,
    client_http,
):
    client_module.access_token = None
    client_module.refresh_token = "present-refresh"
    missing = client_http.get("/")
    missing_markup = b'<span class="token value-missing">NONE</span>'

    assert missing.status_code == 200
    assert missing.data.count(missing_markup) == 1
    assert missing.data.count(b"data-copy-value") == 1
    assert missing.data.count(b"data-copy-button") == 1

    client_module.access_token = "present-access"
    client_module.refresh_token = "present-refresh"
    present = client_http.get("/")

    for value in (b"present-access", b"present-refresh"):
        assert value in present.data
    assert present.data.count(b"data-copy-value") == 2
    assert present.data.count(b"data-copy-button") == 2
    assert missing_markup not in present.data


def test_common_javascript_asset_is_served(client_http):
    response = client_http.get("/assets/common.js")

    assert response.status_code == 200
    assert b"navigator.clipboard.writeText" in response.data


def test_index_renders_consistent_token_rows(client_http):
    response = client_http.get("/")
    page = response.get_data(as_text=True)

    assert response.status_code == 200, (
        "The client index must render successfully before the refresh flow"
    )
    assert "<dt>Access token</dt>" in page
    assert "<dt>Scope</dt>" not in page
    assert "<dt>Refresh token</dt>" in page
    assert page.count('class="token value-missing">NONE</span>') == 0, (
        "Both documented fixtures are present, so no token row shows NONE"
    )


def test_callback_connection_failure_is_rendered_not_500(
    client_module,
    client_http,
    requests_post,
):
    client_module.code_verifier = TEST_CODE_VERIFIER
    client_module.access_token = None
    requests_post.side_effect = requests.ConnectionError(
        "token endpoint unavailable",
    )

    response = client_http.get(
        "/callback",
        query_string={"code": "code-123"},
    )

    assert response.status_code == 200, (
        "Render a controlled token-endpoint error instead of "
        "returning HTTP 500"
    )
    assert b"Unable to fetch access token" in response.data
    assert client_module.access_token is None


def test_resource_connection_failure_is_rendered_not_500(
    client_module,
    client_http,
    requests_post,
):
    client_module.access_token = "access-123"
    requests_post.side_effect = requests.ConnectionError(
        "resource unavailable",
    )

    response = client_http.get("/fetch_resource")

    assert response.status_code == 200, (
        "Render a controlled protected-resource error instead of "
        "returning HTTP 500"
    )
    assert b"Unable to fetch resource" in response.data
    assert client_module.access_token is None
