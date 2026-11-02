"""Protected resource starter for Chapter 4 Exercise 3."""

import re
from pathlib import Path

from flask import Flask, Response, jsonify, render_template, request

from oauth_store import (
    AccessToken,
    DatabaseError,
    find_access_token,
    initialize_schema,
)


BASE_DIR = Path(__file__).resolve().parent
app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "files" / "protectedResource"),
    static_folder=str(BASE_DIR / "files"),
    static_url_path="/assets",
)
BEARER_PATTERN = re.compile(
    r"^Bearer ([A-Za-z0-9\-._~+/]+={0,2})$",
    re.IGNORECASE,
)
OAuthError = tuple[Response, int]


def incoming_access_token() -> str | None:
    """Read a strict Bearer token, or a form token if the header is absent."""
    # HTTP field names are case-insensitive. Werkzeug's header mapping handles
    # that lookup while preserving the case-sensitive credential value.
    authorization = request.headers.get("Authorization")
    if authorization is not None:
        match = BEARER_PATTERN.fullmatch(authorization)
        return match.group(1) if match else None
    form_access_token = request.form.get("access_token")
    if form_access_token:
        return form_access_token
    return None


@app.get("/")
def index() -> str:
    return render_template("index.html")


def temporarily_unavailable() -> OAuthError:
    response = jsonify(error="temporarily_unavailable")
    response.headers["Retry-After"] = "1"
    return response, 503


def invalid_token() -> OAuthError:
    response = jsonify(error="invalid_token")
    response.headers["WWW-Authenticate"] = 'Bearer realm="protected-resource"'
    return response, 401


def validated_access_record() -> tuple[AccessToken | None, OAuthError | None]:
    """Return the exact stored token record or a structured OAuth error."""
    token = incoming_access_token()
    if not token:
        return None, invalid_token()
    try:
        access_record = find_access_token(token)
    except DatabaseError:
        return None, temporarily_unavailable()
    if access_record is None:
        return None, invalid_token()
    return access_record, None


@app.get("/produce")
def produce() -> Response | OAuthError:
    access_record, authentication_error = validated_access_record()
    if authentication_error is not None:
        return authentication_error
    if access_record is None:
        return invalid_token()

    produce_result = {
        "fruit": ["apple", "banana", "kiwi"],
        "veggies": ["lettuce", "onion", "potato"],
        "meats": ["bacon", "steak", "chicken breast"],
    }

    # TODO: Initialize all three produce lists as empty lists.
    # TODO: Populate each list only when its exact scope name is present in
    #       access_record["scope"].split(): fruit, veggies, or meats.
    return jsonify(produce_result)


if __name__ == "__main__":
    initialize_schema()
    app.run(host="localhost", port=9002, debug=False, use_reloader=False)
