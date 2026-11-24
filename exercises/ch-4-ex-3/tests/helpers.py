import base64
import hashlib
import json
from urllib.parse import parse_qs, quote_plus, urlsplit

import requests


CLIENT_ID = "oauth-client-1"
CLIENT_SECRET = "oauth-client-secret-1"
REDIRECT_URI = "http://localhost:9000/callback"
TEST_CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
TEST_CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
FULL_PRODUCE = {
    "fruit": ["apple", "banana", "kiwi"],
    "veggies": ["lettuce", "onion", "potato"],
    "meats": ["bacon", "steak", "chicken breast"],
}


def generate_test_code_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def oauth_response(status=200, payload=None, raw_body=None):
    response = requests.Response()
    response.status_code = status
    response.url = "https://test.invalid/oauth"
    response.headers["Content-Type"] = "application/json"
    if raw_body is not None:
        response._content = raw_body
    else:
        response._content = json.dumps(payload).encode("utf-8")
    return response


def oauth_form_headers(client_id=CLIENT_ID, client_secret=CLIENT_SECRET):
    encoded_id = quote_plus(client_id)
    encoded_secret = quote_plus(client_secret)
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
    return parsed, {key: items[-1] for key, items in values.items()}


def authorization_query(scope="fruit veggies meats", state="test-state"):
    return {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": REDIRECT_URI,
        "scope": scope,
        "state": state,
        "code_challenge": TEST_CODE_CHALLENGE,
        "code_challenge_method": "S256",
    }


def issue_authorization_code(
    authorization_http,
    authorization_server,
    requested_scope="fruit veggies meats",
    granted_scope=None,
    state="test-state",
):
    response = authorization_http.get(
        "/authorize",
        query_string=authorization_query(requested_scope, state),
    )
    assert response.status_code == 200
    assert len(authorization_server.approval_requests) == 1
    request_id = next(iter(authorization_server.approval_requests))
    granted = requested_scope if granted_scope is None else granted_scope
    approval = {"reqid": request_id, "approve": "Approve"}
    for item in granted.split():
        approval[f"scope_{item}"] = item
    approved = authorization_http.post("/approve", data=approval)
    parsed, params = redirect_query(approved)
    assert approved.status_code == 302 and "code" in params
    assert parsed.scheme == "http" and parsed.netloc == "localhost:9000"
    return params["code"], params


def token_request(authorization_http, data, client_secret=CLIENT_SECRET):
    return authorization_http.post(
        "/token",
        data=data,
        headers=oauth_form_headers(CLIENT_ID, client_secret),
    )


def redeem_code(
    authorization_http,
    code,
    redirect_uri=REDIRECT_URI,
    code_verifier=TEST_CODE_VERIFIER,
):
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
    }
    if code_verifier is not None:
        data["code_verifier"] = code_verifier
    return token_request(authorization_http, data)
