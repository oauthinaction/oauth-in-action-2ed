from datetime import datetime
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


UNAUTHORIZED_NOTICE = b"The protected resource returned 401 Unauthorized."
FRESHNESS_NOTICE = b"This is not a freshness problem."


def expected_local_time(epoch):
    local_time = datetime.fromtimestamp(epoch).astimezone()
    return local_time.strftime("%Y-%m-%d %H:%M:%S %Z")


def refresh_button_markup(page):
    start = page.index('<form class="inline-form" action="/refresh"')
    end = page.index("</form>", start)
    return page[start:end]


def test_build_url_preserves_existing_query_and_fragment(client_module):
    url = client_module.build_url(
        "https://server.example/authorize?keep=yes#chapter",
        {"existing": "a value", "keep": "updated"},
    )
    assert url == (
        "https://server.example/authorize"
        "?keep=updated&existing=a+value#chapter"
    )


def test_basic_credentials_match_oauth_encoding(client_module):
    expected = oauth_form_headers("client id", "secret:+ value")
    actual = "Basic " + client_module.encode_client_credentials(
        "client id", "secret:+ value"
    )
    assert actual == expected["Authorization"]


def test_client_pkce_helpers_match_rfc_7636(client_module):
    assert (
        client_module.generate_code_challenge(TEST_CODE_VERIFIER)
        == TEST_CODE_CHALLENGE
    )
    allowed = frozenset(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789-._~"
    )
    generated = {client_module.generate_code_verifier() for _ in range(32)}
    assert len(generated) == 32
    for verifier in generated:
        assert 43 <= len(verifier) <= 128
        assert set(verifier) <= allowed
        challenge = client_module.generate_code_challenge(verifier)
        assert len(challenge) == 43 and "=" not in challenge


def test_authorization_request_asks_for_produce_scopes(
    client_module, client_http, monkeypatch
):
    monkeypatch.setattr(
        client_module, "generate_code_verifier", lambda: TEST_CODE_VERIFIER
    )
    client_module.access_token = "old-access"
    client_module.refresh_token = "retained-refresh"
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
    assert params["scope"] == "fruit veggies meats", (
        "Request all three produce scopes"
    )
    assert params["state"] and params["state"] == client_module.state
    assert params["code_challenge"] == generate_test_code_challenge(
        TEST_CODE_VERIFIER
    )
    assert params["code_challenge_method"] == "S256"
    assert client_module.code_verifier == TEST_CODE_VERIFIER
    assert client_module.access_token is None
    assert client_module.scope is None
    assert client_module.refresh_token == "retained-refresh"


def test_each_authorization_request_sends_a_fresh_state(
    client_module, client_http
):
    first = redirect_query(client_http.get("/authorize"))[1]["state"]
    second = redirect_query(client_http.get("/authorize"))[1]["state"]
    assert first != second
    assert client_module.state == second


def test_callback_code_exchange_contract_stores_tokens_and_scope(
    client_module, client_http, requests_post
):
    client_module.state = "state-123"
    client_module.code_verifier = TEST_CODE_VERIFIER
    requests_post.side_effect = None
    requests_post.return_value = oauth_response(
        payload={
            "access_token": "access-123",
            "token_type": "Bearer",
            "refresh_token": "refresh-123",
            "scope": "fruit meats",
        }
    )
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
        headers=oauth_form_headers(),
        timeout=5,
        allow_redirects=False,
    )
    assert client_module.code_verifier is None
    assert client_module.access_token == "access-123"
    assert client_module.refresh_token == "refresh-123"
    assert client_module.scope == "fruit meats"
    assert b"fruit meats" in response.data


def test_callback_keeps_refresh_token_when_none_is_issued(
    client_module, client_http, requests_post
):
    client_module.state = "state-123"
    client_module.code_verifier = TEST_CODE_VERIFIER
    client_module.refresh_token = "existing-refresh"
    requests_post.side_effect = None
    requests_post.return_value = oauth_response(
        payload={"access_token": "access-123", "scope": "veggies"}
    )
    client_http.get(
        "/callback",
        query_string={"code": "code-123", "state": "state-123"},
    )
    assert client_module.access_token == "access-123"
    assert client_module.refresh_token == "existing-refresh"
    assert client_module.scope == "veggies"


def test_callback_without_stored_verifier_makes_no_token_request(
    client_module, client_http, requests_post
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
    client_module, client_http, requests_post
):
    client_module.state = "state-123"
    client_module.code_verifier = TEST_CODE_VERIFIER
    response = client_http.get(
        "/callback", query_string={"error": "access_denied"}
    )
    assert response.status_code == 200
    assert b"access_denied" in response.data
    assert client_module.code_verifier is None
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
    client_module, client_http, requests_post, stored_state, returned_state
):
    client_module.state = stored_state
    client_module.code_verifier = TEST_CODE_VERIFIER
    query = {"code": "code-123"}
    if returned_state is not None:
        query["state"] = returned_state
    response = client_http.get("/callback", query_string=query)
    assert response.status_code == 200
    assert b"State value did not match" in response.data
    requests_post.assert_not_called()


@pytest.mark.parametrize("token_status", [302, 201])
def test_callback_rejects_token_endpoint_status_other_than_200(
    client_module, client_http, requests_post, token_status
):
    client_module.state = "state-123"
    client_module.code_verifier = TEST_CODE_VERIFIER
    requests_post.side_effect = None
    requests_post.return_value = oauth_response(
        status=token_status,
        payload={
            "access_token": "redirect-access",
            "refresh_token": "redirect-refresh",
            "scope": "fruit",
        },
    )
    response = client_http.get(
        "/callback",
        query_string={"code": "code-123", "state": "state-123"},
    )
    assert response.status_code == 200
    assert f"server response: {token_status}".encode() in response.data
    assert client_module.access_token is None
    assert client_module.refresh_token is None
    assert client_module.scope is None
    assert b"redirect-access" not in response.data


def test_callback_connection_failure_is_rendered_not_500(
    client_module, client_http, requests_post
):
    client_module.state = "state-123"
    client_module.code_verifier = TEST_CODE_VERIFIER
    requests_post.side_effect = requests.ConnectionError(
        "token endpoint unavailable"
    )
    response = client_http.get(
        "/callback",
        query_string={"code": "code-123", "state": "state-123"},
    )
    assert response.status_code == 200
    assert b"Unable to fetch access token" in response.data
    assert client_module.access_token is None


def test_produce_get_sends_only_bearer_header_and_renders_lists(
    client_module, client_http, requests_get, requests_post, monkeypatch
):
    client_module.access_token = "access-123"
    client_module.scope = "fruit veggies meats"
    refresh_helper = Mock()
    monkeypatch.setattr(client_module, "refresh_access_token", refresh_helper)
    requests_get.side_effect = None
    requests_get.return_value = oauth_response(payload=FULL_PRODUCE)
    response = client_http.get("/produce")

    assert response.status_code == 200
    requests_get.assert_called_once_with(
        "http://localhost:9002/produce",
        headers={"Authorization": "Bearer access-123"},
        timeout=5,
        allow_redirects=False,
    )
    for values in FULL_PRODUCE.values():
        for value in values:
            assert value.encode() in response.data
    assert b"fruit veggies meats" in response.data, (
        "Show the current granted scope on the produce page"
    )
    requests_post.assert_not_called()
    refresh_helper.assert_not_called()
    assert client_module.access_token == "access-123"


def test_produce_page_renders_partial_grant_as_returned(
    client_module, client_http, requests_get
):
    client_module.access_token = "access-123"
    client_module.scope = "veggies"
    requests_get.side_effect = None
    requests_get.return_value = oauth_response(
        payload={
            "fruit": [],
            "veggies": ["lettuce", "onion", "potato"],
            "meats": [],
        }
    )
    response = client_http.get("/produce")

    assert response.status_code == 200
    assert b"lettuce" in response.data
    assert b"apple" not in response.data and b"steak" not in response.data
    assert b"No fruit was returned for this grant." in response.data
    assert b"No meats were returned for this grant." in response.data


def test_produce_without_access_token_makes_no_request(
    client_http, requests_get
):
    response = client_http.get("/produce")
    assert response.status_code == 200
    assert b"Missing Access Token" in response.data
    requests_get.assert_not_called()


def test_401_is_reported_and_never_refreshes_automatically(
    client_module, client_http, requests_get, requests_post, monkeypatch
):
    client_module.access_token = "expired-access"
    client_module.refresh_token = "refresh-123"
    refresh_helper = Mock()
    monkeypatch.setattr(client_module, "refresh_access_token", refresh_helper)
    requests_get.side_effect = None
    requests_get.return_value = oauth_response(
        status=401, payload={"error": "invalid_token"}
    )
    response = client_http.get("/produce")
    page = response.get_data(as_text=True)

    assert response.status_code == 200
    assert UNAUTHORIZED_NOTICE in response.data
    assert "<dt>Access token</dt>" in page, (
        "Report the 401 on the client page so Refresh token is available"
    )
    assert "Refresh token" in refresh_button_markup(page)
    requests_get.assert_called_once()
    requests_post.assert_not_called()
    refresh_helper.assert_not_called()
    assert client_module.access_token is None
    assert client_module.refresh_token == "refresh-123"


def test_401_right_after_refresh_is_not_a_freshness_problem(
    client_module, client_http, requests_get, monkeypatch
):
    client_module.access_token = "just-refreshed-access"
    client_module.last_refresh_epoch = 1_000
    monkeypatch.setattr(client_module.time, "time", lambda: 1_005)
    refresh_helper = Mock()
    monkeypatch.setattr(client_module, "refresh_access_token", refresh_helper)
    requests_get.side_effect = None
    requests_get.return_value = oauth_response(
        status=401, payload={"error": "invalid_token"}
    )
    response = client_http.get("/produce")

    assert response.status_code == 200
    assert FRESHNESS_NOTICE in response.data
    assert UNAUTHORIZED_NOTICE not in response.data
    refresh_helper.assert_not_called()
    assert client_module.access_token is None

    monkeypatch.setattr(client_module.time, "time", lambda: 1_020)
    client_module.access_token = "older-access"
    later = client_http.get("/produce")
    assert UNAUTHORIZED_NOTICE in later.data
    assert FRESHNESS_NOTICE not in later.data


@pytest.mark.parametrize("status", [201, 302, 403, 500])
def test_non_200_produce_status_is_an_error_and_never_refreshes(
    client_module, client_http, requests_get, requests_post, monkeypatch,
    status,
):
    client_module.access_token = "access-123"
    client_module.refresh_token = "refresh-123"
    refresh_helper = Mock()
    monkeypatch.setattr(client_module, "refresh_access_token", refresh_helper)
    requests_get.side_effect = None
    requests_get.return_value = oauth_response(
        status=status, payload=FULL_PRODUCE
    )
    response = client_http.get("/produce")

    assert response.status_code == 200
    expected = f"Status: {status}, unable to fetch produce."
    assert expected.encode() in response.data, (
        "Accept Produce API responses only for status 200"
    )
    assert b"apple" not in response.data
    assert client_module.access_token is None
    assert client_module.refresh_token == "refresh-123"
    refresh_helper.assert_not_called()
    requests_post.assert_not_called()


def test_produce_connection_failure_is_rendered_not_500(
    client_module, client_http, requests_get, requests_post
):
    client_module.access_token = "access-123"
    client_module.refresh_token = "refresh-123"
    requests_get.side_effect = requests.ConnectionError("api unavailable")
    response = client_http.get("/produce")

    assert response.status_code == 200
    assert b"Unable to fetch produce" in response.data
    assert client_module.access_token is None
    assert client_module.refresh_token == "refresh-123"
    requests_post.assert_not_called()


def test_refresh_button_runs_refresh_and_records_epoch(
    client_module, client_http, requests_get, requests_post, monkeypatch
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
    # Refreshing never calls the Produce API; the user clicks again.
    requests_get.assert_not_called()
    requests_post.assert_not_called()
    assert client_module.last_refresh_epoch == refreshed_at

    home = client_http.get("/")
    assert expected_local_time(refreshed_at).encode() in home.data
    assert b"replacement-access" in home.data
    assert b"rotated-refresh" in home.data


def test_refresh_requires_post(client_http):
    response = client_http.get("/refresh")
    assert response.status_code == 405


def test_failed_refresh_reports_error_and_keeps_last_epoch(
    client_module, client_http, requests_post, monkeypatch
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
    client_module, client_http, monkeypatch
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
    )
    assert "<dt>Access token</dt>" in blocked_page
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
    client_module, client_http, monkeypatch
):
    client_module.refresh_token = None
    refresh_helper = Mock()
    monkeypatch.setattr(client_module, "refresh_access_token", refresh_helper)
    response = client_http.post("/refresh")
    assert b"No refresh token available." in response.data
    refresh_helper.assert_not_called()


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
    client_module, client_http, monkeypatch, refresh_token,
    last_refresh_epoch,
):
    client_module.refresh_token = refresh_token
    client_module.last_refresh_epoch = last_refresh_epoch
    monkeypatch.setattr(client_module.time, "time", lambda: 1_005)
    page = client_http.get("/").get_data(as_text=True)
    assert "disabled" not in refresh_button_markup(page)
    assert "You need to wait" not in page


def test_refresh_button_flow_with_real_helper(
    client_module, client_http, requests_post, monkeypatch
):
    monkeypatch.setattr(client_module.time, "time", lambda: 2_000)
    client_module.refresh_token = "refresh-123"
    requests_post.side_effect = None
    requests_post.return_value = oauth_response(
        payload={
            "access_token": "new-access",
            "token_type": "Bearer",
            "refresh_token": "rotated-refresh",
            "scope": "fruit",
        }
    )
    response = client_http.post("/refresh")

    assert response.status_code == 303
    requests_post.assert_called_once()
    assert requests_post.call_args.args[0] == "http://localhost:9001/token"
    assert client_module.access_token == "new-access"
    assert client_module.refresh_token == "rotated-refresh"
    assert client_module.scope == "fruit"
    assert client_module.last_refresh_epoch == 2_000


def test_refresh_posts_exact_contract_and_rotates_tokens(
    client_module, requests_post
):
    client_module.access_token = None
    client_module.refresh_token = "refresh-1"
    client_module.scope = "fruit veggies"
    requests_post.side_effect = None
    requests_post.return_value = oauth_response(
        payload={
            "access_token": "new-access",
            "token_type": "Bearer",
            "refresh_token": "refresh-2",
            "scope": "fruit veggies",
        }
    )
    result = client_module.refresh_access_token()

    assert result is True
    requests_post.assert_called_once_with(
        "http://localhost:9001/token",
        data={"grant_type": "refresh_token", "refresh_token": "refresh-1"},
        headers=oauth_form_headers(),
        timeout=5,
        allow_redirects=False,
    )
    assert client_module.access_token == "new-access"
    assert client_module.refresh_token == "refresh-2"
    assert client_module.scope == "fruit veggies"


@pytest.mark.parametrize(
    "token_response",
    [
        oauth_response(status=400, payload={"error": "invalid_grant"}),
        oauth_response(
            status=201,
            payload={
                "access_token": "created-access",
                "refresh_token": "created-refresh",
                "scope": "fruit",
            },
        ),
        oauth_response(
            status=302,
            payload={
                "access_token": "redirect-access",
                "refresh_token": "redirect-refresh",
                "scope": "fruit",
            },
        ),
    ],
    ids=[
        "token-endpoint-rejection",
        "token-endpoint-201",
        "token-endpoint-redirect",
    ],
)
def test_refresh_failure_clears_unusable_refresh_token(
    client_module, requests_post, token_response
):
    client_module.access_token = "existing-access"
    client_module.refresh_token = "invalid-refresh"
    client_module.scope = "fruit"
    requests_post.side_effect = None
    requests_post.return_value = token_response
    result = client_module.refresh_access_token()

    assert result is False, "Reject any token-endpoint status other than 200"
    assert client_module.access_token == "existing-access"
    assert client_module.refresh_token is None
    assert client_module.scope == "fruit"


def test_refresh_connection_failure_is_controlled(
    client_module, client_http, requests_post
):
    client_module.refresh_token = "refresh-123"
    requests_post.side_effect = requests.ConnectionError("token unavailable")
    response = client_http.post("/refresh")

    assert response.status_code == 200
    assert b"Unable to refresh token." in response.data
    assert client_module.refresh_token is None
    assert client_module.last_refresh_epoch is None


def test_index_renders_token_scope_and_refresh_rows(client_http):
    response = client_http.get("/")
    page = response.get_data(as_text=True)

    assert response.status_code == 200
    rows = [
        "<dt>Access token</dt>",
        "<dt>Scope</dt>",
        "<dt>Refresh token</dt>",
        "<dt>Last refresh</dt>",
    ]
    positions = [page.index(row) for row in rows]
    assert positions == sorted(positions)
    assert page.count('class="token value-missing">NONE</span>') == 4
    assert 'href="/produce"' in page
    assert "Refresh token\n" in refresh_button_markup(page)


def test_home_copy_contract_for_missing_and_present_values(
    client_module, client_http
):
    client_module.access_token = None
    client_module.scope = None
    client_module.refresh_token = "present-refresh"
    client_module.last_refresh_epoch = None
    missing = client_http.get("/")
    missing_markup = b'<span class="token value-missing">NONE</span>'

    assert missing.status_code == 200
    assert missing.data.count(missing_markup) == 3
    assert missing.data.count(b"data-copy-value") == 1
    assert missing.data.count(b"data-copy-button") == 1

    client_module.access_token = "present-access"
    client_module.scope = "fruit meats"
    client_module.last_refresh_epoch = 1_000
    present = client_http.get("/")

    for value in (
        b"present-access",
        b"fruit meats",
        b"present-refresh",
        expected_local_time(1_000).encode(),
    ):
        assert value in present.data
    assert present.data.count(b"data-copy-value") == 3
    assert present.data.count(b"data-copy-button") == 3
    assert missing_markup not in present.data


def test_common_assets_are_served(client_http):
    javascript = client_http.get("/assets/common.js")
    stylesheet = client_http.get("/assets/common.css")

    assert javascript.status_code == 200
    assert b"navigator.clipboard.writeText" in javascript.data
    assert stylesheet.status_code == 200
    for selector in (b".button-refresh", b".inline-form", b".notice"):
        assert selector in stylesheet.data
