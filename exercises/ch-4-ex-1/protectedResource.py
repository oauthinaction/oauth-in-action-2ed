"""Learner protected-resource starter for Chapter 4 Exercise 1."""

import re
from pathlib import Path

from flask import Flask, Response, jsonify, render_template

from oauth_store import AccessToken, initialize_schema

# These imports are for the learner's TODOs below; they are unused until then.
from flask import request  # noqa: F401
from oauth_store import DatabaseError, find_access_token  # noqa: F401


BASE_DIR = Path(__file__).resolve().parent
EXERCISE_DIR = BASE_DIR
app = Flask(
    __name__,
    template_folder=str(EXERCISE_DIR / "files" / "protectedResource"),
    static_folder=str(EXERCISE_DIR / "files"),
    static_url_path="/assets",
)
RESOURCE = {
    "name": "Protected Resource",
    "description": "This data has been protected by OAuth 2.0",
}
BEARER_PATTERN = re.compile(
    r"^bearer ([A-Za-z0-9\-._~+/]+={0,2})$",
    re.IGNORECASE,
)
OAuthError = tuple[Response, int]


def incoming_access_token() -> str | None:
    """Extract an access token once this exercise step is complete."""
    # TODO: Treat a present Authorization header as authoritative. Flask and
    # Werkzeug resolve that HTTP field name case-insensitively; accept only a
    # complete, case-insensitive Bearer scheme while preserving the token's
    # case-sensitive value. When the header is absent, return the
    # access_token form field (None when it is missing). Never accept access
    # tokens from the query string because URLs can leak through logs,
    # browser history, referrer headers, screenshots, and copied links.
    return None


@app.get("/")
def index() -> str:
    return render_template("index.html")


def temporarily_unavailable() -> tuple[Response, int]:
    response = jsonify(error="temporarily_unavailable")
    response.headers["Retry-After"] = "1"
    return response, 503


def invalid_token() -> OAuthError:
    response = jsonify(error="invalid_token")
    response.headers["WWW-Authenticate"] = 'Bearer realm="protected-resource"'
    return response, 401


def validated_access_record() -> tuple[AccessToken | None, OAuthError | None]:
    """Learner TODO: return a stored token record or an OAuth error."""
    # TODO: Read the incoming token, reject a missing token with
    # invalid_token(), look up the exact access-token record, translate
    # DatabaseError with temporarily_unavailable(), and reject an unknown
    # token with invalid_token(). Return (access_record, None) only when
    # validation succeeds.
    return None, invalid_token()


@app.post("/resource")
def resource() -> tuple[Response, int]:
    # TODO: Call validated_access_record() and return authentication_error when
    # present. If no error is returned but access_record is still None, fail
    # closed with invalid_token() instead of using assert. Return RESOURCE only
    # for a non-None validated record.
    response = jsonify(
        error="not_implemented",
        error_description=(
            "Complete the access-token extraction, validation, and resource "
            "route TODOs in protectedResource.py"
        ),
    )
    return response, 501


if __name__ == "__main__":
    initialize_schema()
    app.run(host="localhost", port=9002, debug=False, use_reloader=False)
