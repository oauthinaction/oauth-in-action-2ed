"""Starter client for Chapter 3 Exercise 1."""

import base64
import hashlib
from pathlib import Path
import secrets
from typing import Any
from urllib.parse import parse_qsl, quote_plus, urlencode, urlsplit, urlunsplit

from flask import Flask, render_template
# Imported for the learner's TODO routes; unused until they are implemented.
from flask import Response, redirect, request  # noqa: F401
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
    "redirect_uris": "http://localhost:9000/callback",
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


def todo(message: str) -> tuple[str, int]:
    return render_template("error.html", error=f"TODO: {message}"), 501


@app.get("/")
def index() -> str:
    return render_template("index.html", access_token=access_token)


@app.get("/authorize")
def authorize() -> tuple[str, int]:
    return todo(
        "generate a verifier and build the S256 authorization redirect."
    )


@app.get("/callback")
def callback() -> tuple[str, int]:
    return todo("exchange the code with the PKCE verifier.")


if __name__ == "__main__":
    app.run(host="localhost", port=9000, debug=False, use_reloader=False)
