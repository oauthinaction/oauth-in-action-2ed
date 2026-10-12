import requests

import pytest

from helpers import oauth_response


VALID_FAVORITES = {
    "user": "Alice",
    "favorites": {
        "movies": ["The Multidimensional Vector"],
        "foods": ["pizza"],
        "music": ["techno"],
    },
}


def test_authorize_uses_state_pkce_and_exact_registered_redirect(client_http, client_module):
    response = client_http.get("/authorize")
    assert response.status_code == 302
    location = response.headers["Location"]
    assert location.startswith(client_module.AUTH_SERVER["authorization_endpoint"] + "?")
    assert "redirect_uri=http%3A%2F%2Flocalhost%3A9000%2Fcallback" in location
    assert "code_challenge_method=S256" in location
    assert client_module.state
    assert 43 <= len(client_module.code_verifier) <= 128
    assert client_module.generate_code_challenge(client_module.code_verifier) in location


def test_callback_requires_matching_state_and_consumes_it(
    client_http, client_module, requests_post
):
    client_module.state = "expected"
    client_module.code_verifier = "A" * 43
    mismatch = client_http.get("/callback?state=wrong&code=code")
    assert mismatch.status_code == 200
    assert b"State value did not match" in mismatch.data
    requests_post.assert_not_called()

    client_module.state = "expected"
    client_module.code_verifier = "A" * 43
    requests_post.return_value = oauth_response(
        payload={
            "access_token": "access",
            "refresh_token": "refresh",
            "scope": "movies",
            "token_type": "bEaReR",
        }
    )
    success = client_http.get("/callback?state=expected&code=code")
    replay = client_http.get("/callback?state=expected&code=code")
    assert success.status_code == 200
    assert b"access" in success.data
    assert b"State value did not match" in replay.data
    assert client_module.state is None and client_module.code_verifier is None
    requests_post.assert_called_once()
    _, kwargs = requests_post.call_args
    assert kwargs["data"]["code_verifier"] == "A" * 43
    assert kwargs["timeout"] == client_module.REQUEST_TIMEOUT
    assert kwargs["allow_redirects"] is False
    assert kwargs["headers"]["Authorization"].startswith("Basic ")


@pytest.mark.parametrize("status", [200, 204, 299])
def test_favorites_uses_exact_bounded_nonredirecting_get_and_accepts_exact_2xx(
    status, client_http, client_module, requests_get
):
    client_module.access_token = "access-token"
    client_module.scope = "movies foods music"
    requests_get.return_value = oauth_response(status=status, payload=VALID_FAVORITES)
    response = client_http.get("/favorites")
    assert response.status_code == 200
    requests_get.assert_called_once_with(
        "http://localhost:9002/favorites",
        headers={"Authorization": "Bearer access-token"},
        timeout=5,
        allow_redirects=False,
    )


@pytest.mark.parametrize("status", [300, 302, 400, 500])
def test_favorites_rejects_redirects_and_every_non_2xx_without_refresh(
    status, client_http, client_module, requests_get, requests_post
):
    client_module.access_token = "access-token"
    client_module.refresh_token = "refresh-token"
    requests_get.return_value = oauth_response(status=status, payload=VALID_FAVORITES)
    response = client_http.get("/favorites")
    assert response.status_code == 200
    assert f"Status {status}".encode() in response.data
    assert client_module.access_token is None
    assert client_module.refresh_token == "refresh-token"
    assert requests_get.call_count == 1
    requests_post.assert_not_called()


@pytest.mark.parametrize(
    "payload,raw_body",
    [
        (None, b'{"user":'),
        (["not", "an", "object"], None),
        ({"user": "Alice"}, None),
        ({**VALID_FAVORITES, "extra": True}, None),
        ({"user": "Alice", "favorites": {"movies": [], "foods": []}}, None),
        ({"user": "Alice", "favorites": {"movies": "x", "foods": [], "music": []}}, None),
        ({"user": "Alice", "favorites": {"movies": [1], "foods": [], "music": []}}, None),
    ],
)
def test_favorites_requires_exact_json_shape(
    payload, raw_body, client_http, client_module, requests_get
):
    client_module.access_token = "access-token"
    requests_get.return_value = oauth_response(payload=payload, raw_body=raw_body)
    response = client_http.get("/favorites")
    assert response.status_code == 200
    assert b"Favorites API returned an invalid JSON object" in response.data


def test_one_401_refreshes_rotated_pair_and_retries_once(
    client_http, client_module, requests_get, requests_post
):
    client_module.access_token = "old-access"
    client_module.refresh_token = "old-refresh"
    client_module.scope = "old-scope"
    requests_get.side_effect = [
        oauth_response(status=401, payload={"error": "invalid_token"}),
        oauth_response(status=200, payload=VALID_FAVORITES),
    ]
    requests_post.return_value = oauth_response(
        payload={
            "access_token": "new-access",
            "refresh_token": "new-refresh",
            "scope": "movies foods music",
            "token_type": "Bearer",
        }
    )

    response = client_http.get("/favorites")
    assert response.status_code == 200
    assert requests_get.call_count == 2
    assert requests_get.call_args_list[0].kwargs["headers"] == {
        "Authorization": "Bearer old-access"
    }
    assert requests_get.call_args_list[1].kwargs["headers"] == {
        "Authorization": "Bearer new-access"
    }
    requests_post.assert_called_once()
    _, kwargs = requests_post.call_args
    assert kwargs["data"] == {
        "grant_type": "refresh_token",
        "refresh_token": "old-refresh",
    }
    assert kwargs["timeout"] == 5 and kwargs["allow_redirects"] is False
    assert client_module.access_token == "new-access"
    assert client_module.refresh_token == "new-refresh"
    assert client_module.scope == "movies foods music"


def test_second_401_is_final_and_never_refreshes_twice(
    client_http, client_module, requests_get, requests_post
):
    client_module.access_token = "old-access"
    client_module.refresh_token = "old-refresh"
    requests_get.side_effect = [
        oauth_response(status=401, payload={"error": "invalid_token"}),
        oauth_response(status=401, payload={"error": "invalid_token"}),
    ]
    requests_post.return_value = oauth_response(
        payload={
            "access_token": "new-access",
            "refresh_token": "new-refresh",
            "scope": "movies",
            "token_type": "bearer",
        }
    )
    response = client_http.get("/favorites")
    assert b"Status 401" in response.data
    assert requests_get.call_count == 2
    assert requests_post.call_count == 1
    assert client_module.access_token is None


def test_favorites_timeout_is_rendered_without_a_live_retry(
    client_http, client_module, requests_get, requests_post
):
    client_module.access_token = "access"
    client_module.refresh_token = "refresh"
    requests_get.side_effect = requests.Timeout("timed out")
    response = client_http.get("/favorites")
    assert response.status_code == 200
    assert b"Unable to call the Favorites API: timed out" in response.data
    assert requests_get.call_count == 1
    requests_post.assert_not_called()
    assert client_module.access_token is None


@pytest.mark.parametrize(
    "token_fields",
    [
        {},
        {"token_type": 123},
        {"token_type": "Basic"},
    ],
    ids=["missing", "non-string", "unsupported"],
)
def test_callback_rejects_invalid_token_type_and_clears_pair(
    token_fields, client_http, client_module, requests_post
):
    client_module.state = "expected"
    client_module.code_verifier = "A" * 43
    client_module.access_token = "stale-access"
    client_module.refresh_token = "stale-refresh"
    client_module.scope = "stale-scope"
    requests_post.return_value = oauth_response(
        payload={
            "access_token": "access",
            "refresh_token": "refresh",
            "scope": "movies",
            **token_fields,
        }
    )

    response = client_http.get("/callback?state=expected&code=code")

    assert b"Authorization server returned an invalid token response" in response.data
    assert client_module.access_token is None
    assert client_module.refresh_token is None
    assert client_module.scope is None


@pytest.mark.parametrize(
    "token_fields",
    [
        {},
        {"token_type": 123},
        {"token_type": "Basic"},
    ],
    ids=["missing", "non-string", "unsupported"],
)
def test_refresh_rejects_invalid_token_type_and_clears_all_state(
    token_fields, client_module, requests_post
):
    client_module.access_token = "old-access"
    client_module.refresh_token = "old-refresh"
    client_module.scope = "old-scope"
    requests_post.return_value = oauth_response(
        payload={
            "access_token": "new-access",
            "refresh_token": "new-refresh",
            "scope": "new-scope",
            **token_fields,
        }
    )

    assert client_module.refresh_access_token() is False
    assert client_module.access_token is None
    assert client_module.refresh_token is None
    assert client_module.scope is None


@pytest.mark.parametrize("failure", ["missing-refresh", "non-2xx", "transport"])
def test_every_early_refresh_failure_clears_all_state(
    failure, client_module, requests_post
):
    client_module.access_token = "old-access"
    client_module.refresh_token = "old-refresh"
    client_module.scope = "old-scope"
    if failure == "missing-refresh":
        client_module.refresh_token = None
    elif failure == "non-2xx":
        requests_post.return_value = oauth_response(
            status=400, payload={"error": "invalid_grant"}
        )
    else:
        requests_post.side_effect = requests.Timeout("timed out")

    assert client_module.refresh_access_token() is False
    assert client_module.access_token is None
    assert client_module.refresh_token is None
    assert client_module.scope is None
