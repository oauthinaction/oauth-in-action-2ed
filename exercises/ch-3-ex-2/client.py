"""Starter client for Chapter 3 Exercise 2."""

import base64
import hmac
from pathlib import Path
import secrets
from typing import Any
from urllib.parse import parse_qsl, quote_plus, urlencode, urlsplit, urlunsplit

from flask import Flask, Response, redirect, render_template, request
import requests


BASE_DIR = Path(__file__).resolve().parent
app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "files" / "client"),
    static_folder=str(BASE_DIR / "files"),
    static_url_path="/assets",
)
AUTH_SERVER = {
    "authorization_endpoint": "http://localhost:9001/authorize",
    "token_endpoint": "http://localhost:9001/token",
}
CLIENT = {
    "client_id": "oauth-client-1",
    "client_secret": "oauth-client-secret-1",
    "redirect_uris": ["http://localhost:9000/callback"],
    "scope": "foo",
}
PROTECTED_RESOURCE = "http://localhost:9002/resource"
REQUEST_TIMEOUT = 5

# Intentional Exercise 2 teaching fixtures: the access token starts invalid while
# the authorization server recognizes the refresh token.
INITIAL_ACCESS_TOKEN = "987tghjkiu6trfghjuytrghj"
INITIAL_REFRESH_TOKEN = "j2r3oj32r23rmasd98uhjrk2o3i"

# Deliberate single-user exercise shortcut: all browser users share this state.
state: str | None = None
access_token: str | None = INITIAL_ACCESS_TOKEN
scope: str | None = None
refresh_token: str | None = INITIAL_REFRESH_TOKEN


def build_url(
    base: str, parameters: dict[str, str], fragment: str | None = None
) -> str:
    """Add options while preserving query parameters already present in a URL."""
    parts = urlsplit(base)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query.update(parameters)
    encoded_query = urlencode(query)
    return urlunsplit(
        (
            parts.scheme,
            parts.netloc,
            parts.path,
            encoded_query,
            fragment or parts.fragment,
        )
    )


def encode_client_credentials(identifier: str, secret: str) -> str:
    """Apply OAuth percent encoding before constructing Basic credentials."""
    encoded_identifier = quote_plus(identifier, safe="")
    encoded_secret = quote_plus(secret, safe="")
    credential_pair = f"{encoded_identifier}:{encoded_secret}"
    credential_bytes = credential_pair.encode("utf-8")
    encoded_credentials = base64.b64encode(credential_bytes)
    return encoded_credentials.decode("ascii")


def states_match(expected: str, received: str) -> bool:
    """Compare state as bytes so arbitrary Unicode input fails safely."""
    expected_state_bytes = expected.encode("utf-8")
    received_state_bytes = received.encode("utf-8")
    return hmac.compare_digest(expected_state_bytes, received_state_bytes)


def client_error(message: str, status: int = 200) -> tuple[str, int]:
    return render_template("error.html", error=message), status


def response_json(response: requests.Response) -> dict[str, Any] | None:
    try:
        body = response.json()
    except requests.exceptions.JSONDecodeError:
        return None
    return body if isinstance(body, dict) else None


@app.get("/")
def index() -> str:
    return render_template(
        "index.html",
        access_token=access_token,
        scope=scope,
        refresh_token=refresh_token,
    )


@app.get("/authorize")
def authorize() -> Response:
    global access_token, scope, state
    access_token = None
    scope = None
    state = secrets.token_urlsafe(24)
    authorization_params = {
        "response_type": "code",
        "scope": CLIENT["scope"],
        "client_id": CLIENT["client_id"],
        "redirect_uri": CLIENT["redirect_uris"][0],
        "state": state,
    }
    authorization_url = build_url(
        AUTH_SERVER["authorization_endpoint"], authorization_params
    )
    return redirect(authorization_url)


@app.get("/callback")
def callback() -> str | tuple[str, int]:
    global access_token, refresh_token, scope, state
    returned_state = request.args.get("state")
    if state is None or returned_state is None or not states_match(state, returned_state):
        return client_error("State value did not match")
    state = None

    authorization_error = request.args.get("error")
    if authorization_error:
        return client_error(authorization_error)

    code = request.args.get("code")
    if not code:
        return client_error("Authorization response did not include a code")

    form_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": CLIENT["redirect_uris"][0],
    }
    basic_credentials = encode_client_credentials(
        CLIENT["client_id"], CLIENT["client_secret"]
    )
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": f"Basic {basic_credentials}",
    }
    try:
        token_response = requests.post(
            AUTH_SERVER["token_endpoint"],
            data=form_data,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
        )
        token_request_succeeded = 200 <= token_response.status_code < 300
        if not token_request_succeeded:
            return client_error(
                "Unable to fetch access token, server response: "
                f"{token_response.status_code}"
            )
        token_response.raise_for_status()
    except requests.RequestException as error:
        return client_error(f"Unable to fetch access token: {error}")

    token_body = response_json(token_response)
    returned_access_token = token_body.get("access_token") if token_body else None
    if not isinstance(returned_access_token, str):
        return client_error("Authorization server returned invalid JSON")
    returned_refresh_token = token_body.get("refresh_token")
    returned_scope = token_body.get("scope")

    access_token = returned_access_token
    if isinstance(returned_refresh_token, str):
        refresh_token = returned_refresh_token
    scope = returned_scope if isinstance(returned_scope, str) else None
    return render_template(
        "index.html",
        access_token=access_token,
        scope=scope,
        refresh_token=refresh_token,
    )


@app.get("/fetch_resource")
def fetch_resource() -> str | tuple[str, int]:
    global access_token
    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    try:
        resource_response = requests.post(
            PROTECTED_RESOURCE,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
        )
        resource_request_succeeded = 200 <= resource_response.status_code < 300
        if not resource_request_succeeded:
            access_token = None
            if resource_response.status_code == 401:
                # Learner TODO, retry orchestration milestone:
                # - When refresh_token exists and refreshed is not already "1",
                #   call refresh_access_token() and save its boolean result.
                # - If it returns True, build /fetch_resource?refreshed=1 and
                #   return that retry redirect from this caller.
                # - If it returns False, render "Unable to refresh token."
                pass
            return client_error(
                f"Unable to fetch resource. Status {resource_response.status_code}"
            )
        resource_response.raise_for_status()
    except requests.RequestException as error:
        access_token = None
        return client_error(f"Unable to fetch resource: {error}")

    resource_body = response_json(resource_response)
    if resource_body is None:
        return client_error("Protected resource returned invalid JSON")
    return render_template("data.html", resource=resource_body)


def refresh_access_token() -> bool:
    """Learner TODO: exchange refresh_token and update token state; return success."""
    return False


if __name__ == "__main__":
    app.run(host="localhost", port=9000, debug=False, use_reloader=False)
