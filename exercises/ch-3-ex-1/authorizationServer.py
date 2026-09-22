"""Chapter 3 authorization server: authorization-code grant only."""

from __future__ import annotations

import base64
import binascii
import hashlib
import hmac
from pathlib import Path
import secrets
from typing import Any, TypedDict
from urllib.parse import parse_qsl, unquote_plus, urlencode, urlsplit, urlunsplit

from flask import Flask, Response, jsonify, redirect, render_template, request

from oauth_store import DatabaseError, insert_access_token, reset_schema


BASE_DIR = Path(__file__).resolve().parent
app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "files" / "authorizationServer"),
    static_folder=str(BASE_DIR / "files"),
    static_url_path="/assets",
)

AUTH_SERVER = {
    "authorization_endpoint": "http://localhost:9001/authorize",
    "token_endpoint": "http://localhost:9001/token",
}
CLIENTS = [
    {
        "client_id": "oauth-client-1",
        "client_secret": "oauth-client-secret-1",
        "redirect_uris": ["http://localhost:9000/callback"],
        "scope": "foo bar",
    }
]
PKCE_VERIFIER_CHARACTERS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789-._~"
)
PKCE_CHALLENGE_CHARACTERS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789-_"
)


class AuthorizationCode(TypedDict):
    client_id: str
    redirect_uri: str
    scope: list[str]
    code_challenge: str
    code_challenge_method: str


# Deliberately in memory: Chapter 3 focuses on the protocol, not durable grants.
approval_requests: dict[str, dict[str, str]] = {}
authorization_codes: dict[str, AuthorizationCode] = {}


def build_url(base: str, parameters: dict[str, str | None]) -> str:
    """Add query parameters without discarding parameters already in the URL."""
    parts = urlsplit(base)
    query = dict(parse_qsl(parts.query, keep_blank_values=True))
    query.update(
        {key: value for key, value in parameters.items() if value is not None}
    )
    return urlunsplit(
        (parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment)
    )


def get_client(client_id: str | None) -> dict[str, Any] | None:
    return next(
        (client for client in CLIENTS if client["client_id"] == client_id),
        None,
    )


def oauth_error(error: str, status: int = 400) -> tuple[Response, int]:
    response = jsonify(error=error)
    if error == "invalid_client":
        response.headers["WWW-Authenticate"] = 'Basic realm="token"'
    return response, status


def temporarily_unavailable() -> tuple[Response, int]:
    response = jsonify(error="temporarily_unavailable")
    response.headers["Retry-After"] = "1"
    return response, 503


def request_data() -> dict[str, Any]:
    """Read token parameters from either JSON or an HTML form."""
    if request.is_json:
        body = request.get_json(silent=True)
        return body if isinstance(body, dict) else {}
    return request.form.to_dict()


def basic_credentials(header: str | None) -> tuple[tuple[str, str] | None, bool]:
    """Decode OAuth Basic credentials, including OAuth percent decoding."""
    if header is None:
        return None, False
    scheme, separator, value = header.partition(" ")
    if not separator or scheme.lower() != "basic" or not value or " " in value:
        return None, True
    try:
        decoded = base64.b64decode(value, validate=True).decode("utf-8")
        encoded_id, colon, encoded_secret = decoded.partition(":")
        if not colon:
            return None, True
        return (unquote_plus(encoded_id), unquote_plus(encoded_secret)), True
    except (binascii.Error, UnicodeDecodeError):
        return None, True


def generate_code_challenge(code_verifier: str) -> str | None:
    """Derive an unpadded S256 challenge from a valid PKCE verifier."""
    if not isinstance(code_verifier, str):
        return None
    if not 43 <= len(code_verifier) <= 128:
        return None
    if any(character not in PKCE_VERIFIER_CHARACTERS for character in code_verifier):
        return None
    try:
        ascii_verifier = code_verifier.encode("ascii")
    except UnicodeEncodeError:
        return None
    verifier_digest = hashlib.sha256(ascii_verifier).digest()
    base64url_digest = base64.urlsafe_b64encode(verifier_digest)
    padded_challenge = base64url_digest.decode("ascii")
    return padded_challenge.rstrip("=")


def validate_code_challenge(
    code_challenge: str | None,
    method: str | None,
) -> bool:
    """Accept only a canonical 43-character S256 challenge."""
    if method != "S256":
        return False
    if not isinstance(code_challenge, str):
        return False
    if len(code_challenge) != 43:
        return False
    if any(
        character not in PKCE_CHALLENGE_CHARACTERS
        for character in code_challenge
    ):
        return False

    restored_padding = "=" * (-len(code_challenge) % 4)
    padded_challenge = code_challenge + restored_padding
    try:
        decoded_challenge = base64.urlsafe_b64decode(padded_challenge)
    except (binascii.Error, ValueError):
        return False
    if len(decoded_challenge) != 32:
        return False

    canonical_bytes = base64.urlsafe_b64encode(decoded_challenge)
    canonical_challenge = canonical_bytes.decode("ascii").rstrip("=")
    return canonical_challenge == code_challenge


def validate_code_verifier(
    code_verifier: str | None,
    expected_challenge: str,
) -> bool:
    """Compare a valid verifier's challenge with the stored challenge."""
    generated_challenge = generate_code_challenge(code_verifier)
    if generated_challenge is None:
        return False
    try:
        generated_bytes = generated_challenge.encode("ascii")
        expected_bytes = expected_challenge.encode("ascii")
    except (AttributeError, UnicodeEncodeError):
        return False
    return hmac.compare_digest(generated_bytes, expected_bytes)


def redirect_error(callback: str, error: str, state: str | None) -> Response:
    return redirect(build_url(callback, {"error": error, "state": state}))


@app.get("/")
def index() -> str:
    return render_template("index.html", clients=CLIENTS, auth_server=AUTH_SERVER)


@app.get("/authorize")
def authorize() -> Response | str:
    client = get_client(request.args.get("client_id"))
    if client is None:
        return render_template("error.html", error="Unknown client"), 400

    redirect_uri = request.args.get("redirect_uri")
    if redirect_uri not in client["redirect_uris"]:
        return render_template("error.html", error="Invalid redirect URI"), 400

    requested_scope = request.args.get("scope", "").split()
    allowed_scope = set(client["scope"].split())
    if not set(requested_scope).issubset(allowed_scope):
        return redirect_error(
            redirect_uri,
            "invalid_scope",
            request.args.get("state"),
        )

    code_challenge = request.args.get("code_challenge")
    challenge_method = request.args.get("code_challenge_method")
    if not validate_code_challenge(code_challenge, challenge_method):
        return redirect_error(
            redirect_uri,
            "invalid_request",
            request.args.get("state"),
        )

    request_id = secrets.token_urlsafe(18)
    approval_requests[request_id] = request.args.to_dict()
    return render_template(
        "approve.html", client=client, reqid=request_id, scope=requested_scope
    )


@app.post("/approve")
def approve() -> Response | str:
    saved_request = approval_requests.pop(request.form.get("reqid", ""), None)
    if saved_request is None:
        return render_template(
            "error.html", error="No matching authorization request"
        ), 400

    callback = saved_request["redirect_uri"]
    state = saved_request.get("state")
    if "approve" not in request.form:
        return redirect_error(callback, "access_denied", state)
    if saved_request.get("response_type") != "code":
        return redirect_error(callback, "unsupported_response_type", state)

    granted_scope = [
        key.removeprefix("scope_")
        for key in request.form
        if key.startswith("scope_")
    ]
    client = get_client(saved_request.get("client_id"))
    requested_scope = set(saved_request.get("scope", "").split())
    allowed_scope = set(client["scope"].split()) if client else set()
    if not set(granted_scope).issubset(requested_scope & allowed_scope):
        return redirect_error(callback, "invalid_scope", state)

    code = secrets.token_urlsafe(24)
    authorization_codes[code] = {
        "client_id": saved_request["client_id"],
        "redirect_uri": callback,
        "scope": granted_scope,
        "code_challenge": saved_request["code_challenge"],
        "code_challenge_method": saved_request["code_challenge_method"],
    }
    return redirect(build_url(callback, {"code": code, "state": state}))


@app.post("/token")
def token() -> tuple[Response, int] | Response:
    body = request_data()
    header_credentials, header_supplied = basic_credentials(
        request.headers.get("Authorization")
    )
    body_supplied = "client_id" in body or "client_secret" in body
    invalid_header = header_supplied and header_credentials is None
    if (header_supplied and body_supplied) or invalid_header:
        return oauth_error("invalid_client", 401)

    credentials = header_credentials
    if not header_supplied and body_supplied:
        client_id = body.get("client_id")
        client_secret = body.get("client_secret")
        if isinstance(client_id, str) and isinstance(client_secret, str):
            credentials = (client_id, client_secret)

    client = get_client(credentials[0] if credentials else None)
    if (
        client is None
        or credentials is None
        or not hmac.compare_digest(
            client["client_secret"].encode("utf-8"),
            credentials[1].encode("utf-8"),
        )
    ):
        return oauth_error("invalid_client", 401)

    if body.get("grant_type") != "authorization_code":
        return oauth_error("unsupported_grant_type")

    code_value = body.get("code")
    code = authorization_codes.get(code_value) if isinstance(code_value, str) else None
    if (
        code is None
        or code["client_id"] != client["client_id"]
        or body.get("redirect_uri") != code["redirect_uri"]
    ):
        return oauth_error("invalid_grant")

    if not validate_code_verifier(
        body.get("code_verifier"),
        code["code_challenge"],
    ):
        return oauth_error("invalid_grant")

    del authorization_codes[code_value]
    access_token = secrets.token_urlsafe(32)
    scope = " ".join(code["scope"])
    try:
        insert_access_token(access_token, client["client_id"], scope)
    except DatabaseError:
        return temporarily_unavailable()
    return jsonify(access_token=access_token, token_type="Bearer", scope=scope)


# Match the original authorization-server startup lifecycle: loading the app clears
# its exercise-local token store before requests are accepted.
reset_schema()


if __name__ == "__main__":
    app.run(host="localhost", port=9001, debug=False, use_reloader=False)
