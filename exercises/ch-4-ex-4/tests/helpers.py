import base64
import hashlib
import json
from urllib.parse import parse_qs, quote_plus, urlsplit

import requests


TEST_CODE_VERIFIER = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
TEST_CODE_CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
CALLBACK = "http://localhost:9000/callback"
CLIENT_ID = "oauth-client-1"
CLIENT_SECRET = "oauth-client-secret-1"


def generate_test_code_challenge(verifier):
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def oauth_response(status=200, payload=None, raw_body=None):
    response = requests.Response()
    response.status_code = status
    response.url = "https://test.invalid/response"
    response.headers["Content-Type"] = "application/json"
    response._content = raw_body if raw_body is not None else json.dumps(payload).encode()
    return response


def basic_headers(client_id=CLIENT_ID, client_secret=CLIENT_SECRET):
    encoded_id = quote_plus(client_id)
    encoded_secret = quote_plus(client_secret)
    value = base64.b64encode(f"{encoded_id}:{encoded_secret}".encode()).decode()
    return {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": f"Basic {value}",
    }


def redirect_parameters(response):
    parsed = urlsplit(response.headers["Location"])
    values = parse_qs(parsed.query, keep_blank_values=True)
    return parsed, {key: items[-1] for key, items in values.items()}


def authorization_query(scope="movies foods music", state="test-state", **updates):
    query = {
        "response_type": "code",
        "client_id": CLIENT_ID,
        "redirect_uri": CALLBACK,
        "scope": scope,
        "state": state,
        "code_challenge": TEST_CODE_CHALLENGE,
        "code_challenge_method": "S256",
    }
    query.update(updates)
    return query


def begin_authorization(authorization_http, authorization_server, **query_updates):
    query = authorization_query(**query_updates)
    response = authorization_http.get("/authorize", query_string=query)
    assert response.status_code == 200
    request_ids = list(authorization_server.approval_requests)
    assert len(request_ids) == 1
    return request_ids[0], response


def approve_request(
    authorization_http,
    request_id,
    owner="alice",
    granted_scope=("movies", "foods", "music"),
):
    data = {"reqid": request_id, "approve": "Approve"}
    if owner is not None:
        data["resource_owner"] = owner
    for item in granted_scope:
        data[f"scope_{item}"] = item
    return authorization_http.post("/approve", data=data)


def issue_authorization_code(
    authorization_http,
    authorization_server,
    owner="alice",
    scope="movies foods music",
    granted_scope=None,
    state="test-state",
):
    request_id, _ = begin_authorization(
        authorization_http, authorization_server, scope=scope, state=state
    )
    selected = tuple(scope.split()) if granted_scope is None else tuple(granted_scope)
    response = approve_request(authorization_http, request_id, owner, selected)
    parsed, parameters = redirect_parameters(response)
    assert response.status_code == 302 and "code" in parameters
    return parameters["code"], parsed, parameters


def redeem_code(authorization_http, code, **extra_data):
    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": CALLBACK,
        "code_verifier": TEST_CODE_VERIFIER,
    }
    data.update(extra_data)
    return authorization_http.post("/token", data=data, headers=basic_headers())
