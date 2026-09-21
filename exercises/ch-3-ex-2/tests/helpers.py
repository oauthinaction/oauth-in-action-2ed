import base64
import json
from urllib.parse import parse_qs, quote_plus, urlsplit

import requests


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


def malformed_json_response(status=200):
    return oauth_response(status=status, raw_body=b'{"access_token":')


def non_object_json_response(status=200):
    return oauth_response(status=status, payload=["not", "an", "object"])


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


def issue_authorization_code(
    authorization_http,
    authorization_server,
    scope="foo",
    state="test-state",
):
    response = authorization_http.get(
        "/authorize",
        query_string={
            "response_type": "code",
            "client_id": "oauth-client-1",
            "redirect_uri": "http://localhost:9000/callback",
            "scope": scope,
            "state": state,
        },
    )
    assert response.status_code == 200, (
        "Authorization setup failed before the code milestone could be exercised"
    )
    request_id = next(iter(authorization_server.approval_requests))
    approval = {"reqid": request_id, "approve": "Approve"}
    for item in scope.split():
        approval[f"scope_{item}"] = item
    response = authorization_http.post("/approve", data=approval)
    parsed, params = redirect_query(response)
    assert response.status_code == 302 and "code" in params, (
        "The authorization server must issue a code after approved consent"
    )
    return params["code"], parsed, params
