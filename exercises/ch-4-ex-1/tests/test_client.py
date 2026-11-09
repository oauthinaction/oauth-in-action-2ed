from datetime import datetime
from unittest.mock import Mock

import pytest
import requests

from helpers import (
    TEST_CODE_CHALLENGE,
    TEST_CODE_VERIFIER,
    generate_test_code_challenge,
    oauth_form_headers,
    oauth_response,
    redirect_query,
)


UNAUTHORIZED_NOTICE = (
    b"The protected resource returned 401 Unauthorized. "
    b"Refresh the token, then fetch the protected resource again."
)
FRESHNESS_NOTICE = (
    b"We just refreshed this access token, and the protected resource "
    b"still returned 401 Unauthorized. This is not a freshness problem."
)
MISSING_MARKUP = b'<span class="token value-missing">NONE</span>'


def expected_local_time(epoch):
    local_time = datetime.fromtimestamp(epoch).astimezone()
    return local_time.strftime("%Y-%m-%d %H:%M:%S %Z")


def refresh_button_markup(page):
    start = page.index('<form class="inline-form" action="/refresh"')
    end = page.index("</form>", start)
    return page[start:end]


def test_client_starts_without_tokens(client_module):
    assert client_module.access_token is None
    assert client_module.refresh_token is None
    assert client_module.scope is None
    assert client_module.last_refresh_epoch is None
    assert not hasattr(client_module, "INITIAL_ACCESS_TOKEN"), (
        "Chapter 4 starts without fixture tokens"
    )
    assert not hasattr(client_module, "INITIAL_REFRESH_TOKEN")


def test_client_registration_uses_one_redirect_uri(client_module):
    assert client_module.CLIENT["redirect_uris"] == (
        "http://localhost:9000/callback"
    ), "The client registers a single redirect URI string"


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


def test_authorization_request_omits_scope_and_clears_access_and_scope(
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
    client_module.scope = "old-scope"
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
        "state",
        "code_challenge",
        "code_challenge_method",
    }, "Exercise 1 requests a token without a scope parameter"
    assert params["response_type"] == "code"
    assert params["state"] and params["state"] == client_module.state, (
        "Send a fresh state value and keep it to check the callback"
    )
    assert params["client_id"] == "oauth-client-1"
    assert params["redirect_uri"] == "http://localhost:9000/callback"
    assert params["code_challenge_method"] == "S256"
    assert client_module.code_verifier == TEST_CODE_VERIFIER
    assert params["code_challenge"] == generate_test_code_challenge(
        client_module.code_verifier
    ), "Bind the authorization request to the retained PKCE verifier"
    assert client_module.access_token is None
    assert client_module.scope is None, (
        "A new authorization request clears the previously granted scope"
    )
    assert client_module.refresh_token == "retained-refresh"


def test_each_authorization_request_uses_a_new_state(client_http):
    first = redirect_query(client_http.get("/authorize"))[1]["state"]
    second = redirect_query(client_http.get("/authorize"))[1]["state"]

    assert first != second


def test_callback_code_exchange_contract_stores_tokens_and_scope(
    client_module,
    client_http,
    requests_post,
):
    client_module.state = "state-123"
    client_module.code_verifier = TEST_CODE_VERIFIER
    requests_post.return_value = oauth_response(
        payload={
            "access_token": "access-123",
            "token_type": "Bearer",
            "refresh_token": "refresh-123",
            "scope": "foo bar",
        }
    )
    requests_post.side_effect = None

    response = client_http.get(
        "/callback",
        query_string={"code": "code-123", "state": "state-123"},
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
    assert client_module.refresh_token == "refresh-123"
    assert client_module.scope == "foo bar", (
        "Store the scope returned with the token"
    )
    for shown_value in (b"access-123", b"refresh-123", b"foo bar"):
        assert shown_value in response.data


def test_callback_keeps_refresh_token_when_none_is_issued(
    client_module,
    client_http,
    requests_post,
):
    client_module.state = "state-123"
    client_module.code_verifier = TEST_CODE_VERIFIER
    client_module.refresh_token = "existing-refresh"
    requests_post.return_value = oauth_response(
        payload={"access_token": "access-123", "scope": ""}
    )
    requests_post.side_effect = None

    client_http.get(
        "/callback",
        query_string={"code": "code-123", "state": "state-123"},
    )

    assert client_module.access_token == "access-123"
    assert client_module.refresh_token == "existing-refresh"
    assert client_module.scope == "", (
        "An explicitly empty granted scope is stored as returned"
    )


def test_callback_without_stored_verifier_makes_no_token_request(
    client_module,
    client_http,
    requests_post,
):
    client_module.state = "state-123"
    client_module.code_verifier = None

    response = client_http.get(
        "/callback",
        query_string={"code": "code-123", "state": "state-123"},
    )

    assert response.status_code == 200
    assert b"Missing PKCE code verifier" in response.data
    requests_post.assert_not_called()


def test_callback_error_consumes_verifier_without_token_request(
    client_module,
    client_http,
    requests_post,
):
    client_module.state = "state-123"
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


@pytest.mark.parametrize(
    ("stored_state", "returned_state"),
    [
        ("state-123", "other-state"),
        ("state-123", None),
        (None, "state-123"),
    ],
    ids=["different-state", "missing-state", "no-authorization-request"],
)
def test_callback_rejects_state_mismatch(
    client_module,
    client_http,
    requests_post,
    stored_state,
    returned_state,
):
    client_module.state = stored_state
    client_module.code_verifier = TEST_CODE_VERIFIER
    query = {"code": "code-123"}
    if returned_state is not None:
        query["state"] = returned_state

    response = client_http.get("/callback", query_string=query)

    assert response.status_code == 200
    assert b"State value did not match" in response.data, (
        "Reject a callback whose state is not the one this client sent"
    )
    requests_post.assert_not_called()


@pytest.mark.parametrize("token_status", [302, 201])
def test_callback_rejects_token_endpoint_status_other_than_200(
    client_module,
    client_http,
    requests_post,
    token_status,
):
    client_module.state = "state-123"
    client_module.code_verifier = TEST_CODE_VERIFIER
    requests_post.return_value = oauth_response(
        status=token_status,
        payload={
            "access_token": "redirect-access",
            "refresh_token": "redirect-refresh",
            "scope": "redirect-scope",
        },
    )
    requests_post.side_effect = None

    response = client_http.get(
        "/callback",
        query_string={"code": "code-123", "state": "state-123"},
    )

    assert response.status_code == 200
    assert f"server response: {token_status}".encode() in response.data, (
        "Accept token responses only when the endpoint returns "
        "status 200"
    )
    assert client_module.access_token is None
    assert client_module.refresh_token is None
    assert client_module.scope is None
    assert b"redirect-access" not in response.data


def test_callback_connection_failure_is_rendered_not_500(
    client_module,
    client_http,
    requests_post,
):
    client_module.state = "state-123"
    client_module.code_verifier = TEST_CODE_VERIFIER
    requests_post.side_effect = requests.ConnectionError(
        "token endpoint unavailable",
    )

    response = client_http.get(
        "/callback",
        query_string={"code": "code-123", "state": "state-123"},
    )

    assert response.status_code == 200, (
        "Render a controlled token-endpoint error instead of "
        "returning HTTP 500"
    )
    assert b"Unable to fetch access token" in response.data
    assert b"token endpoint unavailable" in response.data
    assert client_module.access_token is None
    assert client_module.code_verifier is None


def test_fetch_resource_without_access_token_makes_no_request(
    client_http,
    requests_post,
):
    response = client_http.get("/fetch_resource")

    assert response.status_code == 200
    assert b"Missing Access Token" in response.data
    requests_post.assert_not_called()


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
        payload={
            "name": "Protected Resource",
            "description": "This data has been protected by OAuth 2.0",
        }
    )
    requests_post.side_effect = None

    response = client_http.get("/fetch_resource")

    assert response.status_code == 200
    requests_post.assert_called_once_with(
        "http://localhost:9002/resource",
        headers={"Authorization": "Bearer access-123"},
        timeout=5,
        allow_redirects=False,
    )
    for printed_value in (
        b"Protected Resource",
        b"This data has been protected by OAuth 2.0",
    ):
        assert printed_value in response.data, (
            "Show the resource name and description in the JSON block"
        )
    assert b'aria-label="Protected resource JSON"' in response.data
    assert b'aria-label="Copy protected resource JSON"' in response.data
    assert b"<dt>" not in response.data, (
        "The resource page shows only the JSON, without separate field rows"
    )
    assert client_module.access_token == "access-123"
    refresh_helper.assert_not_called()


def test_401_is_reported_and_never_refreshes_automatically(
    client_module,
    client_http,
    requests_post,
    monkeypatch,
):
    client_module.access_token = "expired-access"
    client_module.refresh_token = "refresh-123"
    refresh_helper = Mock()
    monkeypatch.setattr(client_module, "refresh_access_token", refresh_helper)
    requests_post.return_value = oauth_response(
        status=401,
        payload={"error": "invalid_token"},
    )
    requests_post.side_effect = None

    response = client_http.get("/fetch_resource")
    page = response.get_data(as_text=True)

    assert response.status_code == 200
    assert UNAUTHORIZED_NOTICE in response.data, (
        "Tell the user that the protected resource returned a 401"
    )
    assert "<dt>Access token</dt>" in page, (
        "Report the 401 on the client page so the Refresh token button "
        "is available"
    )
    refresh_helper.assert_not_called()
    requests_post.assert_called_once()
    assert client_module.access_token is None
    assert client_module.refresh_token == "refresh-123"
    assert "Refresh token" in refresh_button_markup(page), (
        "Show the Refresh token button with the 401 message"
    )


def test_401_right_after_refresh_is_not_a_freshness_problem(
    client_module,
    client_http,
    requests_post,
    monkeypatch,
):
    client_module.access_token = "just-refreshed-access"
    client_module.last_refresh_epoch = 1_000
    monkeypatch.setattr(client_module.time, "time", lambda: 1_005)
    refresh_helper = Mock()
    monkeypatch.setattr(client_module, "refresh_access_token", refresh_helper)
    requests_post.return_value = oauth_response(
        status=401,
        payload={"error": "invalid_token"},
    )
    requests_post.side_effect = None

    response = client_http.get("/fetch_resource")

    assert response.status_code == 200
    assert FRESHNESS_NOTICE in response.data, (
        "Within 20 seconds of a refresh, explain that a fresh token was "
        "rejected"
    )
    assert UNAUTHORIZED_NOTICE not in response.data
    refresh_helper.assert_not_called()
    assert client_module.access_token is None

    monkeypatch.setattr(client_module.time, "time", lambda: 1_020)
    client_module.access_token = "older-access"
    later = client_http.get("/fetch_resource")

    assert UNAUTHORIZED_NOTICE in later.data, (
        "Once the 20-second wait is over, suggest refreshing the token again"
    )


@pytest.mark.parametrize("resource_status", [201, 302, 500])
def test_resource_status_other_than_200_is_an_error_without_refresh(
    client_module,
    client_http,
    requests_post,
    monkeypatch,
    resource_status,
):
    client_module.access_token = "access-123"
    client_module.refresh_token = "refresh-123"
    refresh_helper = Mock()
    monkeypatch.setattr(client_module, "refresh_access_token", refresh_helper)
    requests_post.return_value = oauth_response(
        status=resource_status,
        payload={"name": "Unexpected Protected Resource"},
    )
    requests_post.side_effect = None

    response = client_http.get("/fetch_resource")

    assert response.status_code == 200
    expected_error = (
        f"Status: {resource_status}, unable to fetch resource."
    ).encode()
    assert expected_error in response.data, (
        "Accept protected-resource responses only for status 200"
    )
    assert b"Unexpected Protected Resource" not in response.data
    assert client_module.access_token is None
    assert client_module.refresh_token == "refresh-123"
    requests_post.assert_called_once()
    refresh_helper.assert_not_called()


def test_resource_connection_failure_is_rendered_not_500(
    client_module,
    client_http,
    requests_post,
):
    client_module.access_token = "access-123"
    client_module.refresh_token = "refresh-123"
    requests_post.side_effect = requests.ConnectionError(
        "resource unavailable",
    )

    response = client_http.get("/fetch_resource")

    assert response.status_code == 200, (
        "Render a controlled protected-resource error instead of "
        "returning HTTP 500"
    )
    assert b"Unable to fetch resource" in response.data
    assert b"resource unavailable" in response.data
    assert client_module.access_token is None
    assert client_module.refresh_token == "refresh-123"


def test_refresh_button_runs_refresh_and_records_epoch(
    client_module,
    client_http,
    requests_post,
    monkeypatch,
):
    refreshed_at = 1_700_000_000
    monkeypatch.setattr(client_module.time, "time", lambda: refreshed_at)
    client_module.refresh_token = "refresh-123"

    def refresh_once():
        client_module.access_token = "replacement-access"
        client_module.refresh_token = "rotated-refresh"
        return True

    refresh_helper = Mock(side_effect=refresh_once)
    monkeypatch.setattr(client_module, "refresh_access_token", refresh_helper)

    response = client_http.post("/refresh")

    assert response.status_code == 303
    assert response.headers["Location"] == "/"
    refresh_helper.assert_called_once_with()
    # Refreshing never fetches the protected resource; the user clicks
    # Fetch protected resource again.
    requests_post.assert_not_called()
    assert client_module.last_refresh_epoch == refreshed_at, (
        "Store the epoch seconds of the last successful refresh"
    )

    home = client_http.get("/")
    assert expected_local_time(refreshed_at).encode() in home.data, (
        "Show the last refresh time in this machine's local timezone"
    )
    assert b"replacement-access" in home.data
    assert b"rotated-refresh" in home.data


def test_refresh_requires_post(client_http):
    response = client_http.get("/refresh")

    assert response.status_code == 405


def test_failed_refresh_reports_error_and_keeps_last_epoch(
    client_module,
    client_http,
    requests_post,
    monkeypatch,
):
    client_module.refresh_token = "refresh-123"
    client_module.last_refresh_epoch = 1_000
    monkeypatch.setattr(client_module.time, "time", lambda: 1_100)
    refresh_helper = Mock(return_value=False)
    monkeypatch.setattr(client_module, "refresh_access_token", refresh_helper)

    response = client_http.post("/refresh")

    assert response.status_code == 200
    assert b"Unable to refresh token." in response.data
    refresh_helper.assert_called_once_with()
    assert client_module.last_refresh_epoch == 1_000
    requests_post.assert_not_called()


def test_refresh_is_blocked_for_20_seconds_after_last_refresh(
    client_module,
    client_http,
    monkeypatch,
):
    client_module.refresh_token = "refresh-123"
    client_module.last_refresh_epoch = 1_000
    refresh_helper = Mock(return_value=True)
    monkeypatch.setattr(client_module, "refresh_access_token", refresh_helper)

    monkeypatch.setattr(client_module.time, "time", lambda: 1_005)
    blocked = client_http.post("/refresh")
    blocked_page = blocked.get_data(as_text=True)

    assert blocked.status_code == 200
    assert (
        "You need to wait 15 seconds before you can refresh again."
        in blocked_page
    ), "Tell the user how long to wait before refreshing again"
    assert "<dt>Access token</dt>" in blocked_page, (
        "Show the wait message on the client page, not an error page"
    )
    refresh_helper.assert_not_called()
    assert client_module.last_refresh_epoch == 1_000

    monkeypatch.setattr(client_module.time, "time", lambda: 1_019)
    last_second = client_http.post("/refresh")

    assert (
        b"You need to wait 1 seconds before you can refresh again."
        in last_second.data
    )
    refresh_helper.assert_not_called()

    monkeypatch.setattr(client_module.time, "time", lambda: 1_020)
    allowed = client_http.post("/refresh")

    assert allowed.status_code == 303
    refresh_helper.assert_called_once_with()
    assert client_module.last_refresh_epoch == 1_020


def test_refresh_without_refresh_token_is_rejected(
    client_module,
    client_http,
    requests_post,
    monkeypatch,
):
    client_module.refresh_token = None
    refresh_helper = Mock()
    monkeypatch.setattr(client_module, "refresh_access_token", refresh_helper)

    response = client_http.post("/refresh")

    assert response.status_code == 200
    assert b"No refresh token available." in response.data
    refresh_helper.assert_not_called()
    requests_post.assert_not_called()


@pytest.mark.parametrize(
    ("refresh_token", "last_refresh_epoch"),
    [
        ("refresh-123", None),
        ("refresh-123", 1_000),
        (None, None),
    ],
    ids=["no-refresh-yet", "during-wait", "no-refresh-token"],
)
def test_refresh_button_is_always_enabled(
    client_module,
    client_http,
    monkeypatch,
    refresh_token,
    last_refresh_epoch,
):
    client_module.refresh_token = refresh_token
    client_module.last_refresh_epoch = last_refresh_epoch
    monkeypatch.setattr(client_module.time, "time", lambda: 1_005)

    page = client_http.get("/").get_data(as_text=True)

    assert "disabled" not in refresh_button_markup(page), (
        "Never disable the Refresh token button; explain any wait "
        "after it is clicked"
    )
    assert "You need to wait" not in page, (
        "Show the wait message only after Refresh token is clicked"
    )


def test_refresh_button_flow_with_real_helper(
    client_module,
    client_http,
    requests_post,
    monkeypatch,
):
    monkeypatch.setattr(client_module.time, "time", lambda: 2_000)
    client_module.refresh_token = "refresh-123"
    requests_post.return_value = oauth_response(
        payload={
            "access_token": "new-access",
            "token_type": "Bearer",
            "refresh_token": "rotated-refresh",
            "scope": "foo",
        }
    )
    requests_post.side_effect = None

    response = client_http.post("/refresh")

    assert response.status_code == 303
    requests_post.assert_called_once()
    assert requests_post.call_args.args[0] == "http://localhost:9001/token"
    assert client_module.access_token == "new-access"
    assert client_module.refresh_token == "rotated-refresh"
    assert client_module.scope == "foo"
    assert client_module.last_refresh_epoch == 2_000


def test_refresh_posts_exact_contract_and_rotates_tokens_and_scope(
    client_module,
    requests_post,
):
    client_module.access_token = None
    client_module.refresh_token = "refresh-123"
    client_module.scope = "old-scope"
    requests_post.return_value = oauth_response(
        payload={
            "access_token": "new-access",
            "token_type": "Bearer",
            "refresh_token": "rotated-refresh",
            "scope": "new-scope",
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
            "refresh_token": "refresh-123",
        },
        headers=oauth_form_headers("oauth-client-1", "oauth-client-secret-1"),
        timeout=5,
        allow_redirects=False,
    )
    assert client_module.access_token == "new-access"
    assert client_module.refresh_token == "rotated-refresh"
    assert client_module.scope == "new-scope", (
        "Store the scope returned with the refreshed token"
    )


@pytest.mark.parametrize(
    "token_response",
    [
        oauth_response(status=400, payload={"error": "invalid_grant"}),
        oauth_response(
            status=201,
            payload={
                "access_token": "created-access",
                "refresh_token": "created-refresh",
                "scope": "created-scope",
            },
        ),
        oauth_response(
            status=302,
            payload={
                "access_token": "redirect-access",
                "refresh_token": "redirect-refresh",
                "scope": "redirect-scope",
            },
        ),
        requests.ConnectionError("token endpoint unavailable"),
    ],
    ids=[
        "token-endpoint-rejection",
        "token-endpoint-201",
        "token-endpoint-redirect",
        "token-endpoint-unreachable",
    ],
)
def test_refresh_failure_clears_unusable_refresh_token(
    client_module,
    requests_post,
    token_response,
):
    client_module.access_token = "existing-access"
    client_module.refresh_token = "invalid-refresh"
    client_module.scope = "existing-scope"
    if isinstance(token_response, Exception):
        requests_post.side_effect = token_response
    else:
        requests_post.return_value = token_response
        requests_post.side_effect = None

    result = client_module.refresh_access_token()

    assert result is False, (
        "Reject any token-endpoint status other than 200"
    )
    requests_post.assert_called_once()
    assert client_module.access_token == "existing-access"
    assert client_module.refresh_token is None
    assert client_module.scope == "existing-scope"


def test_refresh_helper_without_refresh_token_makes_no_request(
    client_module,
    requests_post,
):
    client_module.refresh_token = None

    assert client_module.refresh_access_token() is False
    requests_post.assert_not_called()


def test_index_renders_rows_in_order(client_http):
    response = client_http.get("/")
    page = response.get_data(as_text=True)

    assert response.status_code == 200, (
        "The root client must resolve files/client/index.html "
        "from the exercise directory"
    )
    row_positions = [
        page.index("<dt>Access token</dt>"),
        page.index("<dt>Scope</dt>"),
        page.index("<dt>Refresh token</dt>"),
        page.index("<dt>Last refresh</dt>"),
    ]
    assert row_positions == sorted(row_positions), (
        "Show access token, scope, refresh token, then last refresh time"
    )
    assert "Refresh token\n" in refresh_button_markup(page)
    assert 'href="/authorize"' in page
    assert 'href="/fetch_resource"' in page


def test_home_copy_contract_for_missing_and_present_values(
    client_module,
    client_http,
):
    missing = client_http.get("/")

    assert missing.status_code == 200
    assert missing.data.count(MISSING_MARKUP) == 4, (
        "Show NONE for the access token, scope, refresh token, and last "
        "refresh time before any authorization"
    )
    assert missing.data.count(b"data-copy-value") == 0
    assert missing.data.count(b"data-copy-button") == 0

    client_module.access_token = "present-access"
    client_module.scope = "foo bar"
    client_module.refresh_token = "present-refresh"
    client_module.last_refresh_epoch = 1_000
    present = client_http.get("/")

    for value in (
        b"present-access",
        b"foo bar",
        b"present-refresh",
        expected_local_time(1_000).encode(),
    ):
        assert value in present.data
    assert present.data.count(b"data-copy-value") == 3, (
        "The access token, scope, and refresh token have copy controls"
    )
    assert present.data.count(b"data-copy-button") == 3
    assert b'aria-label="Copy scope"' in present.data
    assert MISSING_MARKUP not in present.data


def test_empty_granted_scope_is_shown_as_none(client_module, client_http):
    client_module.access_token = "present-access"
    client_module.scope = ""

    page = client_http.get("/").get_data(as_text=True)
    scope_row = page[
        page.index("<dt>Scope</dt>"):page.index("<dt>Refresh token</dt>")
    ]

    assert 'class="token value-missing">NONE</span>' in scope_row
    assert "data-copy-value" not in scope_row


def test_common_javascript_asset_is_served(client_http):
    response = client_http.get("/assets/common.js")

    assert response.status_code == 200
    assert b"navigator.clipboard.writeText" in response.data
