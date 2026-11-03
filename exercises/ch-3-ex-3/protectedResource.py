"""Chapter 3 protected resource backed by the shared SQLite token store."""

from pathlib import Path
import re
import time

from flask import Flask, Response, jsonify, render_template, request

from oauth_store import DatabaseError, find_access_token, initialize_schema


BASE_DIR = Path(__file__).resolve().parent
app = Flask(
    __name__,
    template_folder=str(BASE_DIR / "files" / "protectedResource"),
    static_folder=str(BASE_DIR / "files"),
    static_url_path="/assets",
)
RESOURCE = {
    "name": "Protected Resource",
    "description": "This data has been protected by OAuth 2.0",
}
BEARER_PATTERN = re.compile(
    r"^Bearer ([A-Za-z0-9\-._~+/]+={0,2})$",
    re.IGNORECASE,
)


def incoming_access_token() -> str | None:
    """Read a token from a strict Bearer header, then form, then query."""
    authorization = request.headers.get("Authorization")
    if authorization is not None:
        match = BEARER_PATTERN.fullmatch(authorization)
        return match.group(1) if match else None
    return request.form.get("access_token") or request.args.get("access_token")


@app.get("/")
def index() -> str:
    return render_template("index.html")


def temporarily_unavailable() -> tuple[Response, int]:
    response = jsonify(error="temporarily_unavailable")
    response.headers["Retry-After"] = "1"
    return response, 503


@app.post("/resource")
def resource() -> Response | tuple[Response, int]:
    token = incoming_access_token()
    if token:
        try:
            access_record = find_access_token(token)
        except DatabaseError:
            return temporarily_unavailable()
        if access_record:
            resource_body = {
                "name": RESOURCE["name"],
                "description": RESOURCE["description"],
                "timestamp": int(time.time()),
            }
            return jsonify(resource_body)
    response = jsonify(error="invalid_token")
    response.headers["WWW-Authenticate"] = 'Bearer realm="protected-resource"'
    return response, 401


if __name__ == "__main__":
    initialize_schema()
    app.run(host="localhost", port=9002, debug=False, use_reloader=False)
