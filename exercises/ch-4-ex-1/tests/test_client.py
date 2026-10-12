from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest
import requests

from helpers import json_response


def prepare_callback(client_module, state="expected-state", verifier="v" * 43):
    client_module.state = state
    client_module.code_verifier = verifier
    return state, verifier


def test_authorize_omits_scope_and_sends_fresh_valid_pkce_state(
    client_http, client_module
):
    client_module.access_token = "old-access"
    client_module.refresh_token = "old-refresh"
    client_module.scope = "old-scope"

    response = client_http.get("/authorize")

    assert response.status_code == 302
    query = parse_qs(urlsplit(response.headers["Location"]).query)
    assert set(query) == {
        "response_type",
        "client_id",
        "redirect_uri",
        "state",
        "code_challenge",
        "code_challenge_method",
    }, "Authorization must omit scope and include only the code-flow/PKCE fields"
    assert query["response_type"] == ["code"]
    assert query["client_id"] == [client_module.CLIENT["client_id"]]
    assert query["redirect_uri"] == [client_module.CLIENT["redirect_uris"][0]]
    assert query["code_challenge_method"] == ["S256"]
    assert query["state"] == [client_module.state]
    assert client_module.code_verifier is not None
    assert len(client_module.code_verifier) == 43
    assert query["code_challenge"] == [
        client_module.generate_code_challenge(client_module.code_verifier)
    ]
    assert client_module.access_token is None
    assert client_module.refresh_token is None
    assert client_module.scope is None


def test_callback_posts_exact_form_basic_headers_and_transport_options(
    client_http, client_module, requests_post
):
    state, verifier = prepare_callback(client_module)
    requests_post.side_effect = None
    requests_post.return_value = json_response(
        200,
        {
            "access_token": "access-1",
            "refresh_token": "refresh-1",
            "scope": "",
            "token_type": "bEaReR",
        },
    )

    response = client_http.get(f"/callback?code=code-1&state={state}")

    assert response.status_code == 200
    assert client_module.access_token == "access-1"
    assert client_module.refresh_token == "refresh-1"
    assert client_module.scope == "", "An explicitly empty granted scope is valid"
    assert client_module.state is None
    assert client_module.code_verifier is None
    expected_basic = client_module.encode_client_credentials(
        client_module.CLIENT["client_id"], client_module.CLIENT["client_secret"]
    )
    requests_post.assert_called_once_with(
        client_module.AUTH_SERVER["token_endpoint"],
        data={
            "grant_type": "authorization_code",
            "code": "code-1",
            "redirect_uri": client_module.CLIENT["redirect_uris"][0],
            "code_verifier": verifier,
        },
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {expected_basic}",
        },
        timeout=client_module.REQUEST_TIMEOUT,
        allow_redirects=False,
    )


@pytest.mark.parametrize("status", [300, 302, 307])
def test_callback_rejects_redirect_responses(status, client_http, client_module, requests_post):
    state, _ = prepare_callback(client_module)
    requests_post.side_effect = None
    requests_post.return_value = json_response(
        status,
        {
            "access_token": "must-not-store",
            "refresh_token": "also-no",
            "scope": "",
            "token_type": "Bearer",
        },
    )

    response = client_http.get(f"/callback?code=code-1&state={state}")

    assert response.status_code == 200
    assert f"server response: {status}".encode() in response.data
    assert client_module.access_token is None
    assert client_module.refresh_token is None


def test_callback_handles_connection_failure_without_leaking_state(
    client_http, client_module, requests_post
):
    state, _ = prepare_callback(client_module)
    requests_post.side_effect = requests.ConnectionError("token endpoint offline")

    response = client_http.get(f"/callback?code=code-1&state={state}")

    assert response.status_code == 200
    assert b"token endpoint offline" in response.data
    assert client_module.state is None
    assert client_module.code_verifier is None
    assert client_module.access_token is None


def test_callback_requires_matching_state_before_any_http_call(
    client_http, client_module, requests_post
):
    prepare_callback(client_module)

    response = client_http.get("/callback?code=code-1&state=wrong")

    assert response.status_code == 200
    assert b"State value did not match" in response.data
    requests_post.assert_not_called()


@pytest.mark.parametrize("status", [200, 204, 299])
def test_fetch_resource_accepts_exactly_2xx_without_refresh(
    status, client_http, client_module, requests_post
):
    client_module.access_token = "access-1"
    client_module.refresh_token = "refresh-1"
    requests_post.side_effect = None
    requests_post.return_value = json_response(status, {"name": "Protected Resource"})

    response = client_http.get("/fetch_resource")

    assert response.status_code == 200
    assert b"Protected Resource" in response.data
    requests_post.assert_called_once_with(
        client_module.PROTECTED_RESOURCE,
        headers={
            "Authorization": "Bearer access-1",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        timeout=client_module.REQUEST_TIMEOUT,
        allow_redirects=False,
    )


@pytest.mark.parametrize("status", [300, 302, 503])
def test_fetch_resource_rejects_redirect_and_non_2xx_without_refresh(
    status, client_http, client_module, requests_post
):
    client_module.access_token = "access-1"
    client_module.refresh_token = "refresh-1"
    requests_post.side_effect = None
    requests_post.return_value = json_response(status, {})

    response = client_http.get("/fetch_resource")

    assert response.status_code == 200
    assert f"Status {status}".encode() in response.data
    assert client_module.access_token is None
    assert client_module.refresh_token == "refresh-1"
    assert requests_post.call_count == 1


def test_fetch_resource_handles_connection_failure_and_clears_access_token(
    client_http, client_module, requests_post
):
    client_module.access_token = "access-1"
    client_module.refresh_token = "refresh-1"
    requests_post.side_effect = requests.ConnectionError("resource offline")

    response = client_http.get("/fetch_resource")

    assert response.status_code == 200
    assert b"resource offline" in response.data
    assert client_module.access_token is None
    assert client_module.refresh_token == "refresh-1"


def test_401_refreshes_once_rotates_client_state_and_retries_exactly_once(
    client_http, client_module, requests_post
):
    client_module.access_token = "expired-access"
    client_module.refresh_token = "refresh-1"
    client_module.scope = ""
    requests_post.side_effect = [
        json_response(401, {"error": "invalid_token"}),
        json_response(
            200,
            {
                "access_token": "access-2",
                "refresh_token": "refresh-2",
                "scope": "",
                "token_type": "bearer",
            },
        ),
        json_response(200, {"name": "Protected Resource"}),
    ]

    response = client_http.get("/fetch_resource")

    assert response.status_code == 200
    assert b"Protected Resource" in response.data
    assert client_module.access_token == "access-2"
    assert client_module.refresh_token == "refresh-2"
    assert client_module.scope == ""
    assert requests_post.call_count == 3
    refresh_call = requests_post.call_args_list[1]
    expected_basic = client_module.encode_client_credentials(
        client_module.CLIENT["client_id"], client_module.CLIENT["client_secret"]
    )
    assert refresh_call.args == (client_module.AUTH_SERVER["token_endpoint"],)
    assert refresh_call.kwargs == {
        "data": {"grant_type": "refresh_token", "refresh_token": "refresh-1"},
        "headers": {
            "Content-Type": "application/x-www-form-urlencoded",
            "Authorization": f"Basic {expected_basic}",
        },
        "timeout": client_module.REQUEST_TIMEOUT,
        "allow_redirects": False,
    }
    assert requests_post.call_args_list[2].kwargs["headers"]["Authorization"] == "Bearer access-2"


def test_failed_refresh_clears_both_tokens_and_does_not_retry_resource(
    client_http, client_module, requests_post
):
    client_module.access_token = "expired-access"
    client_module.refresh_token = "refresh-1"
    client_module.scope = "old-scope"
    requests_post.side_effect = [json_response(401, {}), json_response(302, {})]

    response = client_http.get("/fetch_resource")

    assert response.status_code == 200
    assert b"Unable to refresh token" in response.data
    assert client_module.access_token is None
    assert client_module.refresh_token is None
    assert client_module.scope is None
    assert requests_post.call_count == 2


def test_callback_rejects_invalid_token_pair_or_type_without_partial_state(
    client_http, client_module, requests_post
):
    valid_body = {
        "access_token": "access-1",
        "refresh_token": "refresh-1",
        "scope": "",
        "token_type": "Bearer",
    }
    invalid_bodies = []
    for field in ("access_token", "refresh_token", "scope", "token_type"):
        missing = valid_body.copy()
        missing.pop(field)
        invalid_bodies.append(missing)
    invalid_bodies.extend(
        [
            {**valid_body, "access_token": ""},
            {**valid_body, "refresh_token": ""},
            {**valid_body, "scope": []},
            {**valid_body, "token_type": "Basic"},
            {**valid_body, "token_type": 123},
        ]
    )

    for body in invalid_bodies:
        requests_post.reset_mock(side_effect=True, return_value=True)
        state, _ = prepare_callback(client_module)
        client_module.access_token = "old-access"
        client_module.refresh_token = "old-refresh"
        client_module.scope = "old-scope"
        requests_post.side_effect = None
        requests_post.return_value = json_response(200, body)

        response = client_http.get(f"/callback?code=code-1&state={state}")

        assert response.status_code == 200
        assert b"invalid token response" in response.data
        assert client_module.access_token is None
        assert client_module.refresh_token is None
        assert client_module.scope is None


def test_every_refresh_failure_clears_all_token_state(client_module, requests_post):
    valid_body = {
        "access_token": "access-2",
        "refresh_token": "refresh-2",
        "scope": "",
        "token_type": "Bearer",
    }
    invalid_json = requests.Response()
    invalid_json.status_code = 200
    invalid_json.headers["Content-Type"] = "application/json"
    invalid_json._content = b"not-json"
    failures = [
        ("no refresh token", None),
        ("non-2xx", json_response(400, valid_body)),
        ("redirect", json_response(302, valid_body)),
        ("exception", requests.ConnectionError("token endpoint offline")),
        ("invalid JSON", invalid_json),
        (
            "invalid pair",
            json_response(200, {**valid_body, "access_token": ""}),
        ),
        (
            "invalid token type",
            json_response(200, {**valid_body, "token_type": "Basic"}),
        ),
    ]

    for name, failure in failures:
        requests_post.reset_mock(side_effect=True, return_value=True)
        client_module.access_token = "old-access"
        client_module.refresh_token = None if name == "no refresh token" else "refresh-1"
        client_module.scope = "old-scope"
        if isinstance(failure, Exception):
            requests_post.side_effect = failure
        elif failure is not None:
            requests_post.side_effect = None
            requests_post.return_value = failure

        assert client_module.refresh_access_token() is False, name
        assert client_module.access_token is None, name
        assert client_module.refresh_token is None, name
        assert client_module.scope is None, name
        if name == "no refresh token":
            requests_post.assert_not_called()
        else:
            requests_post.assert_called_once()
