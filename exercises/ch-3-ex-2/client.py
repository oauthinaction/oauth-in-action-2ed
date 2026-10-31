"""Starter client for Chapter 3 Exercise 2."""

import base64
import hashlib
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
}
PROTECTED_RESOURCE = "http://localhost:9002/resource"
REQUEST_TIMEOUT = 5

# Intentional Exercise 2 teaching fixtures: the access token starts invalid
# while the authorization server recognizes the refresh token.
INITIAL_ACCESS_TOKEN = "987tghjkiu6trfghjuytrghj"
INITIAL_REFRESH_TOKEN = "j2r3oj32r23rmasd98uhjrk2o3i"

# Deliberate single-user shortcut: all browser users share these values.
code_verifier: str | None = None
access_token: str | None = INITIAL_ACCESS_TOKEN
refresh_token: str | None = INITIAL_REFRESH_TOKEN


def build_url(
    base: str, parameters: dict[str, str], fragment: str | None = None
) -> str:
    """Add options while preserving query parameters already in a URL."""
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


def client_error(message: str, status: int = 200) -> tuple[str, int]:
    return render_template("error.html", error=message), status


def response_json(response: requests.Response) -> dict[str, Any] | None:
    try:
        body = response.json()
    except requests.exceptions.JSONDecodeError:
        return None
    return body if isinstance(body, dict) else None


def generate_code_verifier() -> str:
    """Create a fresh RFC 7636 code verifier."""
    return secrets.token_urlsafe(32)


def generate_code_challenge(verifier: str) -> str:
    """Derive the unpadded S256 code challenge for a verifier."""
    ascii_verifier = verifier.encode("ascii")
    verifier_digest = hashlib.sha256(ascii_verifier).digest()
    base64url_digest = base64.urlsafe_b64encode(verifier_digest)
    padded_challenge = base64url_digest.decode("ascii")
    return padded_challenge.rstrip("=")


@app.get("/")
def index() -> str:
    return render_template(
        "index.html",
        access_token=access_token,
        refresh_token=refresh_token,
    )


@app.get("/authorize")
def authorize() -> Response:
    global access_token, code_verifier
    access_token = None
    code_verifier = generate_code_verifier()
    code_challenge = generate_code_challenge(code_verifier)
    authorization_params = {
        "response_type": "code",
        "client_id": CLIENT["client_id"],
        "redirect_uri": CLIENT["redirect_uris"][0],
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    authorization_url = build_url(
        AUTH_SERVER["authorization_endpoint"], authorization_params
    )
    return redirect(authorization_url)


@app.get("/callback")
def callback() -> str | tuple[str, int]:
    global access_token, code_verifier, refresh_token
    current_code_verifier = code_verifier
    code_verifier = None

    authorization_error = request.args.get("error")
    if authorization_error:
        return client_error(authorization_error)
    if current_code_verifier is None:
        return client_error("Missing PKCE code verifier")

    code = request.args.get("code")
    if not code:
        return client_error("Authorization response did not include a code")

    form_data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": CLIENT["redirect_uris"][0],
        "code_verifier": current_code_verifier,
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
    returned_access_token = (
        token_body.get("access_token") if token_body else None
    )
    if not isinstance(returned_access_token, str):
        return client_error("Authorization server returned invalid JSON")
    returned_refresh_token = token_body.get("refresh_token")

    access_token = returned_access_token
    if isinstance(returned_refresh_token, str):
        refresh_token = returned_refresh_token
    return render_template(
        "index.html",
        access_token=access_token,
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
                # Learner TODO, bounded retry orchestration milestone:
                # - When refresh_token exists, call refresh_access_token() once
                #   and save its boolean result.
                # - If it returns True, rebuild the Bearer header with the new
                #   access_token and make one final protected-resource POST.
                # - Render that second response as the final result; do not
                #   redirect, recurse, or attempt another refresh.
                # - If refresh returns False, render "Unable to refresh token."
                pass
            return client_error(
                "Unable to fetch resource. "
                f"Status {resource_response.status_code}"
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
    """Learner TODO: exchange and store both rotated tokens; return success."""
    return False


if __name__ == "__main__":
    app.run(host="localhost", port=9000, debug=False, use_reloader=False)
