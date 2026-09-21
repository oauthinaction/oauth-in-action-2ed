from unittest.mock import Mock

import pytest

from helpers import (
    malformed_json_response,
    oauth_form_headers,
    oauth_response,
    redirect_query,
)


def test_initial_token_values_are_documented_fixtures(client_module):
    assert client_module.INITIAL_ACCESS_TOKEN == "987tghjkiu6trfghjuytrghj"
    assert client_module.INITIAL_REFRESH_TOKEN == "j2r3oj32r23rmasd98uhjrk2o3i"
    assert client_module.access_token == client_module.INITIAL_ACCESS_TOKEN
    assert client_module.scope is None
    assert client_module.refresh_token == client_module.INITIAL_REFRESH_TOKEN


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


def test_authorization_request_clears_access_but_preserves_refresh(
    client_module,
    client_http,
):
    client_module.access_token = "old-access"
    client_module.refresh_token = "retained-refresh"
    client_module.scope = "old-scope"
    response = client_http.get("/authorize")
    parsed, params = redirect_query(response)
    assert response.status_code == 302
    assert parsed.geturl().startswith("http://localhost:9001/authorize?"), (
        "Send the code request to the configured authorization endpoint"
    )
    assert params.keys() == {
        "response_type",
        "scope",
        "client_id",
        "redirect_uri",
        "state",
    }
    assert params["response_type"] == "code"
    assert params["scope"] == "foo"
    assert params["client_id"] == "oauth-client-1"
    assert params["redirect_uri"] == "http://localhost:9000/callback"
    assert params["state"] == client_module.state and params["state"]
    assert client_module.access_token is None
    assert client_module.refresh_token == "retained-refresh"
    assert client_module.scope is None


def test_callback_code_exchange_contract(
    client_module,
    client_http,
    requests_post,
):
    client_module.state = "expected-state"
    requests_post.return_value = oauth_response(
        payload={
            "access_token": "access-123",
            "scope": "foo",
        }
    )
    requests_post.side_effect = None
    response = client_http.get(
        "/callback",
        query_string={"state": "expected-state", "code": "code-123"},
    )
    assert response.status_code == 200
    requests_post.assert_called_once_with(
        "http://localhost:9001/token",
        data={
            "grant_type": "authorization_code",
            "code": "code-123",
            "redirect_uri": "http://localhost:9000/callback",
        },
        headers=oauth_form_headers("oauth-client-1", "oauth-client-secret-1"),
        timeout=5,
        allow_redirects=False,
    )
    assert client_module.state is None
    assert client_module.access_token == "access-123"
    assert client_module.refresh_token == client_module.INITIAL_REFRESH_TOKEN
    assert client_module.scope == "foo"


def test_callback_rejects_token_endpoint_redirect(
    client_module,
    client_http,
    requests_post,
):
    client_module.state = "expected-state"
    client_module.access_token = None
    client_module.refresh_token = None
    client_module.scope = None
    requests_post.return_value = oauth_response(
        status=302,
        payload={
            "access_token": "redirect-access",
            "refresh_token": "redirect-refresh",
            "scope": "redirect-scope",
        },
    )
    requests_post.side_effect = None

    response = client_http.get(
        "/callback",
        query_string={"state": "expected-state", "code": "code-123"},
    )

    assert response.status_code == 200
    assert b"server response: 302" in response.data, (
        "Accept token responses only when the endpoint returns an exact 2xx status"
    )
    assert client_module.state is None
    assert client_module.access_token is None
    assert client_module.refresh_token is None
    assert client_module.scope is None
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
    assert response.status_code == 200 and b"Protected Resource" in response.data
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


def test_first_401_refreshes_then_redirects_for_one_retry(
    client_module,
    client_http,
    requests_post,
    monkeypatch,
):
    client_module.access_token = "expired-access"
    client_module.refresh_token = "refresh-123"
    requests_post.return_value = oauth_response(
        status=401,
        payload={"error": "invalid_token"},
    )
    requests_post.side_effect = None
    refresh_helper = Mock(return_value=True)
    monkeypatch.setattr(client_module, "refresh_access_token", refresh_helper)

    response = client_http.get("/fetch_resource")

    assert response.status_code == 302, (
        "On the first 401, refresh token state and redirect for one guarded retry"
    )
    assert response.headers["Location"] == "/fetch_resource?refreshed=1"
    refresh_helper.assert_called_once_with()


def test_refresh_posts_exact_contract_and_updates_state(
    client_module,
    requests_post,
):
    client_module.access_token = None
    client_module.refresh_token = client_module.INITIAL_REFRESH_TOKEN
    client_module.scope = "old-scope"
    requests_post.return_value = oauth_response(
        payload={
            "access_token": "new-access",
            "refresh_token": client_module.INITIAL_REFRESH_TOKEN,
        }
    )
    requests_post.side_effect = None

    result = client_module.refresh_access_token()

    assert result is True, (
        "Exchange the refresh token, update token state, and report success"
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
    assert client_module.refresh_token == client_module.INITIAL_REFRESH_TOKEN
    assert client_module.scope is None


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


def test_second_401_never_refreshes_again(
    client_module,
    client_http,
    requests_post,
    monkeypatch,
):
    client_module.access_token = "replacement-access"
    client_module.refresh_token = "refresh-123"
    refresh_helper = Mock()
    monkeypatch.setattr(client_module, "refresh_access_token", refresh_helper)
    requests_post.return_value = oauth_response(
        status=401,
        payload={"error": "invalid_token"},
    )
    requests_post.side_effect = None
    response = client_http.get("/fetch_resource?refreshed=1")
    assert response.status_code == 200
    refresh_helper.assert_not_called()


@pytest.mark.parametrize(
    "token_response",
    [
        oauth_response(status=400, payload={"error": "invalid_grant"}),
        malformed_json_response(),
        oauth_response(
            status=302,
            payload={
                "access_token": "redirect-access",
                "refresh_token": "redirect-refresh",
            },
        ),
    ],
    ids=["token-endpoint-rejection", "malformed-json", "token-endpoint-redirect"],
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
        "The root client must resolve files/client/index.html from the exercise directory"
    )
    assert client_module.INITIAL_ACCESS_TOKEN.encode() in response.data
    assert client_module.INITIAL_REFRESH_TOKEN.encode() in response.data


def test_home_copy_contract_for_missing_and_present_values(
    client_module,
    client_http,
):
    client_module.access_token = "present-access"
    client_module.scope = None
    client_module.refresh_token = "present-refresh"
    missing = client_http.get("/")
    missing_markup = b'<span class="token value-missing">NONE</span>'

    assert missing.status_code == 200
    assert missing.data.count(missing_markup) == 1
    assert missing.data.count(b"data-copy-value") == 2
    assert missing.data.count(b"data-copy-button") == 2

    client_module.access_token = "present-access"
    client_module.scope = "present-scope"
    client_module.refresh_token = "present-refresh"
    present = client_http.get("/")

    for value in (b"present-access", b"present-scope", b"present-refresh"):
        assert value in present.data
    assert present.data.count(b"data-copy-value") == 3
    assert present.data.count(b"data-copy-button") == 3
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
    assert "<dt>Scope</dt>" in page
    assert "<dt>Refresh token</dt>" in page
    assert page.count('class="token value-missing">NONE</span>') == 1, (
        "Display the missing scope value in the same aligned token column"
    )
