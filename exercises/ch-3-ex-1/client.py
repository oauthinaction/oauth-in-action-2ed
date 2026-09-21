"""Starter client for Chapter 3 Exercise 1."""

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

# Learner TODO: register the client credentials before completing the flow.
CLIENT = {
    "client_id": "",
    "client_secret": "",
    "redirect_uris": ["http://localhost:9000/callback"],
}

PROTECTED_RESOURCE = "http://localhost:9002/resource"
REQUEST_TIMEOUT = 5

# Deliberate single-user exercise shortcut: all browser users share this state.
state: str | None = None
access_token: str | None = None
scope: str | None = None


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


def new_state() -> str:
    return secrets.token_urlsafe(24)


def todo(message: str) -> tuple[str, int]:
    return render_template("error.html", error=f"TODO: {message}"), 501


@app.get("/")
def index() -> str:
    return render_template("index.html", access_token=access_token, scope=scope)


@app.get("/authorize")
def authorize() -> tuple[str, int]:
    return todo("set the client credentials and build the authorization redirect.")


@app.get("/callback")
def callback() -> tuple[str, int]:
    return todo("validate state and exchange the authorization code for a token.")


@app.get("/fetch_resource")
def fetch_resource() -> tuple[str, int]:
    return todo("send the access token to the protected resource.")


if __name__ == "__main__":
    app.run(host="localhost", port=9000, debug=False, use_reloader=False)
