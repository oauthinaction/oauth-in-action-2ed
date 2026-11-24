"""Small HTTP and OAuth helpers shared by the practitioner tests."""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any
from urllib.parse import parse_qs, quote_plus, urlsplit

import requests


TEST_CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
TEST_CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def json_response(status: int, body: Any) -> requests.Response:
    response = requests.Response()
    response.status_code = status
    response.url = "http://test.invalid/response"
    response.headers["Content-Type"] = "application/json"
    response._content = json.dumps(body).encode("utf-8")
    response.encoding = "utf-8"
    return response


def basic_header(client_id: str, client_secret: str) -> dict[str, str]:
    raw = f"{client_id}:{client_secret}".encode("utf-8")
    encoded = base64.b64encode(raw).decode("ascii")
    return {"Authorization": f"Basic {encoded}"}


def generate_test_code_challenge(code_verifier):
    """Independently derive an unpadded S256 PKCE challenge for tests."""
    ascii_verifier = code_verifier.encode("ascii")
    verifier_digest = hashlib.sha256(ascii_verifier).digest()
    base64url_digest = base64.urlsafe_b64encode(verifier_digest)
    return base64url_digest.decode("ascii").rstrip("=")


def oauth_response(status=200, payload=None):
    response = requests.Response()
    response.status_code = status
    response.url = "https://test.invalid/oauth"
    response.headers["Content-Type"] = "application/json"
    response._content = json.dumps(payload).encode("utf-8")
    return response


def oauth_form_headers(client_id, client_secret):
    encoded_id = quote_plus(client_id)
    encoded_secret = quote_plus(client_secret)
    credentials = f"{encoded_id}:{encoded_secret}".encode("utf-8")
    value = base64.b64encode(credentials).decode("ascii")
    return {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": f"Basic {value}",
    }


def redirect_query(response):
    location = response.headers["Location"]
    parsed = urlsplit(location)
    values = parse_qs(parsed.query, keep_blank_values=True)
    return parsed, {name: items[-1] for name, items in values.items()}
