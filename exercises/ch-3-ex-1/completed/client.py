"""Completed authorization-code client for Chapter 3 Exercise 1."""

import base64
import hashlib
from pathlib import Path
import secrets
from typing import Any
from urllib.parse import parse_qsl, quote_plus, urlencode, urlsplit, urlunsplit

from flask import Flask, Response, redirect, render_template, request
import requests


BASE_DIR = Path(__file__).resolve().parent
EXERCISE_DIR = BASE_DIR.parent if BASE_DIR.name == "completed" else BASE_DIR

app = Flask(
    __name__,
    template_folder=str(EXERCISE_DIR / "files" / "client"),
    static_folder=str(EXERCISE_DIR / "files"),
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

# Deliberate single-user shortcut: all browser users share these values.
code_verifier: str | None = None
access_token: str | None = None


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
    return render_template("index.html", access_token=access_token)


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
    global access_token, code_verifier
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
    access_token = token_body.get("access_token") if token_body else None
    return render_template("index.html", access_token=access_token)


@app.get("/fetch_resource")
def fetch_resource() -> str | tuple[str, int]:
    global access_token
    if not access_token:
        return client_error("Missing Access Token")

    headers = {"Authorization": f"Bearer {access_token}"}
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
            return client_error(str(resource_response.status_code))
        resource_response.raise_for_status()
    except requests.RequestException as error:
        access_token = None
        return client_error(f"Unable to fetch resource: {error}")

    resource_body = response_json(resource_response)
    return render_template("data.html", resource=resource_body)


if __name__ == "__main__":
    app.run(host="localhost", port=9000, debug=False, use_reloader=False)
