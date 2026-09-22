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


def test_build_url_preserves_existing_query_and_fragment(client_module):
    url = client_module.build_url(
        "https://server.example/authorize?keep=yes#chapter",
        {"state": "a value", "keep": "updated"},
    )
    assert url == (
        "https://server.example/authorize?keep=updated&state=a+value#chapter"
    ), "Build the authorization URL without discarding existing query or fragment data"


def test_basic_credentials_match_oauth_encoding(client_module):
    expected = oauth_form_headers("client id", "secret:+ value")["Authorization"]
    actual = "Basic " + client_module.encode_client_credentials(
        "client id", "secret:+ value"
    )
    assert actual == expected, (
        "Percent-encode each client credential before constructing OAuth Basic authentication"
    )


def test_client_generate_code_challenge_matches_rfc_7636(client_module):
    assert generate_test_code_challenge(TEST_CODE_VERIFIER) == TEST_CODE_CHALLENGE
    assert (
        client_module.generate_code_challenge(TEST_CODE_VERIFIER)
        == TEST_CODE_CHALLENGE
    ), "Derive the RFC 7636 S256 challenge with base64url encoding and no padding"


def test_generated_code_verifier_has_rfc_7636_strength_and_shape(client_module):
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
        "Generate a fresh cryptographically random PKCE verifier per authorization request"
    )
    for verifier in generated_verifiers:
        assert 43 <= len(verifier) <= 128, (
            "RFC 7636 code verifiers must contain between 43 and 128 characters"
        )
        assert set(verifier).issubset(allowed_characters), (
            "RFC 7636 code verifiers may contain only unreserved characters"
        )
        challenge = client_module.generate_code_challenge(verifier)
        assert len(challenge) == 43 and "=" not in challenge, (
            "S256 challenges must be canonical unpadded base64url SHA-256 values"
        )


def test_authorize_builds_registered_redirect(
    client_module,
    client_http,
    monkeypatch,
):
    monkeypatch.setattr(
        client_module,
        "generate_code_verifier",
        lambda: TEST_CODE_VERIFIER,
    )
    response = client_http.get("/authorize")
    assert response.status_code == 302, (
        "Configure the client credentials and redirect the browser to the authorization endpoint"
    )
    parsed, params = redirect_query(response)
    assert parsed.geturl().startswith("http://localhost:9001/authorize?"), (
        "Send the authorization request to the configured authorization endpoint"
    )
    assert params.keys() == {
        "response_type",
        "client_id",
        "redirect_uri",
        "state",
        "code_challenge",
        "code_challenge_method",
    }
    assert params["response_type"] == "code"
    assert params["client_id"] == "oauth-client-1"
    assert params["redirect_uri"] == "http://localhost:9000/callback"
    assert params["state"], "Generate and retain a non-empty OAuth state value"
    assert params["code_challenge_method"] == "S256"
    assert client_module.code_verifier == TEST_CODE_VERIFIER
    assert params["code_challenge"] == generate_test_code_challenge(
        client_module.code_verifier
    ), "Bind the authorization request to the retained PKCE verifier"


def test_callback_validates_state_and_posts_code_contract(
    client_module,
    client_http,
    requests_post,
):
    client_module.state = "expected-state"
    client_module.code_verifier = TEST_CODE_VERIFIER
    requests_post.return_value = oauth_response(
        payload={"access_token": "access-123", "scope": "foo"}
    )
    requests_post.side_effect = None

    response = client_http.get(
        "/callback",
        query_string={"state": "expected-state", "code": "code-123"},
    )

    assert response.status_code == 200, (
        "Validate state and exchange the authorization code at the token endpoint"
    )
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
    assert client_module.state is None, (
        "Consume the OAuth state value after validation"
    )
    assert client_module.code_verifier is None, (
        "Consume the PKCE verifier after the token request is prepared"
    )
    assert client_module.access_token == "access-123"
    assert client_module.scope == "foo"


def test_fetch_resource_sends_bearer_contract(
    client_module,
    client_http,
    requests_post,
):
    client_module.access_token = "access-123"
    requests_post.return_value = oauth_response(
        payload={"name": "Protected Resource", "description": "private"}
    )
    requests_post.side_effect = None

    response = client_http.get("/fetch_resource")

    assert response.status_code == 200, (
        "Send the access token as a Bearer credential to the protected resource"
    )
    requests_post.assert_called_once_with(
        "http://localhost:9002/resource",
        headers={"Authorization": "Bearer access-123"},
        timeout=5,
        allow_redirects=False,
    )
    assert b"Protected Resource" in response.data


def test_callback_rejects_state_mismatch(client_module, client_http, requests_post):
    client_module.state = "saved-state"
    client_module.code_verifier = TEST_CODE_VERIFIER
    response = client_http.get(
        "/callback",
        query_string={"state": "different-state", "code": "unused"},
    )
    if response.status_code == 501:
        pytest.skip("Starter callback TODO blocks the state-error behavior")
    assert b"State value did not match" in response.data, (
        "Reject a callback whose state does not match the saved authorization request"
    )
    requests_post.assert_not_called()


def test_callback_reports_malformed_token_json(
    client_module,
    client_http,
    requests_post,
):
    client_module.state = "saved-state"
    client_module.code_verifier = TEST_CODE_VERIFIER
    requests_post.return_value = malformed_json_response()
    requests_post.side_effect = None
    response = client_http.get(
        "/callback",
        query_string={"state": "saved-state", "code": "code-123"},
    )
    if response.status_code == 501:
        pytest.skip("Starter callback TODO blocks token-response error handling")
    assert b"Authorization server returned invalid JSON" in response.data, (
        "Validate that the token endpoint returns an object with an access_token string"
    )


def test_callback_rejects_token_endpoint_redirect(
    client_module,
    client_http,
    requests_post,
):
    client_module.state = "saved-state"
    client_module.code_verifier = TEST_CODE_VERIFIER
    client_module.access_token = None
    client_module.scope = None
    requests_post.return_value = oauth_response(
        status=302,
        payload={"access_token": "redirect-access", "scope": "redirect-scope"},
    )
    requests_post.side_effect = None

    response = client_http.get(
        "/callback",
        query_string={"state": "saved-state", "code": "code-123"},
    )

    if response.status_code == 501:
        pytest.skip("Starter callback TODO blocks token redirect handling")
    assert b"server response: 302" in response.data, (
        "Accept token responses only when the endpoint returns an exact 2xx status"
    )
    assert client_module.state is None
    assert client_module.access_token is None
    assert client_module.scope is None
    assert b"redirect-access" not in response.data


def test_resource_reports_upstream_failure(
    client_module,
    client_http,
    requests_post,
):
    client_module.access_token = "rejected-token"
    requests_post.return_value = oauth_response(
        status=401,
        payload={"error": "invalid_token"},
    )
    requests_post.side_effect = None
    response = client_http.get("/fetch_resource")
    if response.status_code == 501:
        pytest.skip("Starter resource TODO blocks protected-resource error handling")
    assert b"401" in response.data, (
        "Surface a protected-resource rejection and discard the rejected access token"
    )
    assert client_module.access_token is None


def test_resource_rejects_upstream_redirect(
    client_module,
    client_http,
    requests_post,
):
    client_module.access_token = "redirected-token"
    requests_post.return_value = oauth_response(
        status=302,
        payload={"name": "Redirected Protected Resource"},
    )
    requests_post.side_effect = None

    response = client_http.get("/fetch_resource")

    if response.status_code == 501:
        pytest.skip("Starter resource TODO blocks resource redirect handling")
    assert b"302" in response.data, (
        "Accept protected-resource responses only for an exact 2xx status"
    )
    assert b"Redirected Protected Resource" not in response.data
    assert client_module.access_token is None


def test_home_page_renders_from_exercise_root(client_http):
    response = client_http.get("/")

    assert response.status_code == 200, (
        "The root client must resolve files/client/index.html from the exercise directory"
    )
    assert b"OAuth Client" in response.data
    assert b"<dt>Access token</dt>" in response.data
    assert b"<dt>Scope</dt>" in response.data
    assert b"Current access token" not in response.data


def test_home_copy_contract_for_missing_and_present_access(
    client_module,
    client_http,
):
    client_module.access_token = None
    missing = client_http.get("/")
    missing_markup = b'<span class="token value-missing">NONE</span>'

    assert missing.status_code == 200
    assert missing.data.count(missing_markup) == 2
    assert b"data-copy-button" not in missing.data

    client_module.access_token = "present-access"
    present = client_http.get("/")

    assert b'<span class="token" data-copy-value>present-access</span>' in present.data
    assert present.data.count(b"data-copy-value") == 1
    assert present.data.count(b"data-copy-button") == 1
    assert present.data.count(missing_markup) == 1


def test_common_javascript_asset_is_served(client_http):
    response = client_http.get("/assets/common.js")

    assert response.status_code == 200
    assert b"navigator.clipboard.writeText" in response.data


def test_index_renders_aligned_access_and_scope_rows(client_http):
    response = client_http.get("/")
    page = response.get_data(as_text=True)

    assert response.status_code == 200, (
        "The client index must render successfully before starting the OAuth flow"
    )
    assert "<dt>Access token</dt>" in page
    assert "<dt>Scope</dt>" in page
    assert page.count('class="token value-missing">NONE</span>') == 2, (
        "Display aligned NONE values for both the access token and scope"
    )


def test_callback_connection_failure_is_rendered_not_500(
    client_module,
    client_http,
    requests_post,
):
    client_module.state = "saved-state"
    client_module.code_verifier = TEST_CODE_VERIFIER
    requests_post.side_effect = requests.ConnectionError("token endpoint unavailable")

    response = client_http.get(
        "/callback",
        query_string={"state": "saved-state", "code": "code-123"},
    )

    if response.status_code == 501:
        pytest.skip("Starter callback TODO blocks connection-failure handling")
    assert response.status_code == 200, (
        "Render a controlled token-endpoint error instead of returning HTTP 500"
    )
    assert b"Unable to fetch access token" in response.data


def test_resource_connection_failure_is_rendered_not_500(
    client_module,
    client_http,
    requests_post,
):
    client_module.access_token = "access-123"
    requests_post.side_effect = requests.ConnectionError("resource unavailable")

    response = client_http.get("/fetch_resource")

    if response.status_code == 501:
        pytest.skip("Starter resource TODO blocks connection-failure handling")
    assert response.status_code == 200, (
        "Render a controlled protected-resource error instead of returning HTTP 500"
    )
    assert b"Unable to fetch resource" in response.data
    assert client_module.access_token is None
