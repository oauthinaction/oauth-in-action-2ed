import base64
import hashlib
import json
from urllib.parse import parse_qs, quote_plus, urlsplit

import requests


TEST_CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
TEST_CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
CLIENT_ID = "oauth-client-1"
CLIENT_SECRET = "oauth-client-secret-1"
REDIRECT_URI = "http://localhost:9000/callback"


def generate_test_code_challenge(code_verifier):
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def http_response(
    status=200,
    payload=None,
    raw_body=None,
    content_type="application/json",
):
    response = requests.Response()
    response.status_code = status
    response.url = "https://test.invalid/endpoint"
    if content_type:
        response.headers["Content-Type"] = content_type
    if raw_body is not None:
        response._content = raw_body
    elif payload is None:
        response._content = b""
    else:
        response._content = json.dumps(payload).encode("utf-8")
    return response


def oauth_form_headers(client_id=CLIENT_ID, client_secret=CLIENT_SECRET):
    encoded_id = quote_plus(client_id, safe="")
    encoded_secret = quote_plus(client_secret, safe="")
    credentials = base64.b64encode(
        f"{encoded_id}:{encoded_secret}".encode("utf-8")
    ).decode("ascii")
    return {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": f"Basic {credentials}",
    }


def redirect_query(response):
    parsed = urlsplit(response.headers["Location"])
    values = parse_qs(parsed.query, keep_blank_values=True)
    return parsed, {name: items[-1] for name, items in values.items()}


def issue_authorization_code(
    authorization_http,
    authorization_server,
    scope="read write delete",
    state="test-state",
):
    response = authorization_http.get(
        "/authorize",
        query_string={
            "response_type": "code",
            "client_id": CLIENT_ID,
            "redirect_uri": REDIRECT_URI,
            "scope": scope,
            "state": state,
            "code_challenge": TEST_CODE_CHALLENGE,
            "code_challenge_method": "S256",
        },
    )
    assert response.status_code == 200
    request_id = next(iter(authorization_server.approval_requests))
    approval = {"reqid": request_id, "approve": "Approve"}
    for item in scope.split():
        approval[f"scope_{item}"] = item
    approved = authorization_http.post("/approve", data=approval)
    parsed, params = redirect_query(approved)
    assert approved.status_code == 302 and "code" in params
    return params["code"], parsed, params


def exchange_code_form(code, verifier=TEST_CODE_VERIFIER):
    return {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": REDIRECT_URI,
        "code_verifier": verifier,
    }
