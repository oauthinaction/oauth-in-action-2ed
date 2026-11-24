from __future__ import annotations

from unittest.mock import Mock

import pytest


def test_milestone_strict_token_extraction_precedence(protected_resource):
    """Aggregate the extraction matrix into one actionable milestone."""
    cases = [
        (
            "case-insensitive Bearer header",
            {"headers": {"authorization": "bEaReR header-token"}},
            "header-token",
        ),
        (
            "valid header wins over form and query",
            {
                "query_string": {"access_token": "query-token"},
                "data": {"access_token": "form-token"},
                "headers": {"Authorization": "Bearer header-token"},
            },
            "header-token",
        ),
        (
            "form wins over query when header is absent",
            {
                "query_string": {"access_token": "query-token"},
                "data": {"access_token": "form-token"},
            },
            "form-token",
        ),
        (
            "query-string tokens are never accepted",
            {"query_string": {"access_token": "query-token"}},
            None,
        ),
        (
            "malformed present header is authoritative",
            {
                "query_string": {"access_token": "query-token"},
                "data": {"access_token": "form-token"},
                "headers": {"Authorization": "Bearer valid trailing-junk!"},
            },
            None,
        ),
        (
            "non-Bearer present header is authoritative",
            {
                "query_string": {"access_token": "query-token"},
                "data": {"access_token": "form-token"},
                "headers": {"Authorization": "Basic abc"},
            },
            None,
        ),
    ]
    mismatches = []
    for label, request_options, expected in cases:
        with protected_resource.app.test_request_context(
            "/resource", method="POST", **request_options
        ):
            actual = protected_resource.incoming_access_token()
        if actual != expected:
            mismatches.append(
                f"{label}: expected {expected!r}, got {actual!r}"
            )

    assert not mismatches, (
        "Implement incoming_access_token() with strict header > form "
        "precedence. "
        "Query-string tokens must be ignored, and a present malformed "
        "Authorization header must block form fallback:\n- "
        + "\n- ".join(mismatches)
    )


def test_milestone_exact_stored_token_validation_and_oauth_errors(
    resource_http, protected_resource, oauth_store, monkeypatch
):
    """Aggregate valid/invalid/database outcomes into one milestone."""
    oauth_store.insert_access_token(
        "stored-exact-token", "oauth-client-1", ""
    )
    lookup = Mock(side_effect=oauth_store.find_access_token)
    monkeypatch.setattr(protected_resource, "find_access_token", lookup)
    token_box = {"value": "stored-exact-token"}
    monkeypatch.setattr(
        protected_resource, "incoming_access_token", lambda: token_box["value"]
    )
    mismatches = []

    with protected_resource.app.test_request_context(
        "/resource", method="POST"
    ):
        helper_record, helper_error = (
            protected_resource.validated_access_record()
        )
    if helper_record != {
        "access_token": "stored-exact-token",
        "client_id": "oauth-client-1",
        "scope": "",
    } or helper_error is not None:
        mismatches.append(
            "validated_access_record() should return the exact stored record "
            f"and no error; got record={helper_record!r}, "
            f"error={helper_error!r}"
        )
    lookup.reset_mock()

    valid = resource_http.post("/resource")
    if (
        valid.status_code != 200
        or valid.get_json() != protected_resource.RESOURCE
    ):
        mismatches.append(
            "exact stored token should return 200 and the RESOURCE object; "
            f"got {valid.status_code} {valid.get_json()}"
        )
    if lookup.call_args_list != [(("stored-exact-token",), {})]:
        mismatches.append(
            "valid token must be passed unchanged to find_access_token(); "
            f"calls were {lookup.call_args_list!r}"
        )

    real_validation_helper = protected_resource.validated_access_record
    monkeypatch.setattr(
        protected_resource,
        "validated_access_record",
        lambda: (None, None),
    )
    inconsistent = resource_http.post("/resource")
    expected_challenge = 'Bearer realm="protected-resource"'
    if (
        inconsistent.status_code != 401
        or inconsistent.get_json() != {"error": "invalid_token"}
        or inconsistent.headers.get("WWW-Authenticate") != expected_challenge
    ):
        mismatches.append(
            "a validator result of (None, None) must fail closed with a "
            f"challenged 401; got {inconsistent.status_code} "
            f"{inconsistent.get_json()}"
        )
    monkeypatch.setattr(
        protected_resource,
        "validated_access_record",
        real_validation_helper,
    )

    token_box["value"] = "stored-exact-token-extra"
    unknown = resource_http.post("/resource")
    expected_challenge = 'Bearer realm="protected-resource"'
    if (
        unknown.status_code != 401
        or unknown.get_json() != {"error": "invalid_token"}
        or unknown.headers.get("WWW-Authenticate") != expected_challenge
    ):
        mismatches.append(
            "unknown/non-exact token should return structured 401 "
            f"invalid_token with {expected_challenge!r}; got "
            f"{unknown.status_code} {unknown.get_json()} "
            f"challenge={unknown.headers.get('WWW-Authenticate')!r}"
        )

    token_box["value"] = None
    missing = resource_http.post("/resource")
    if (
        missing.status_code != 401
        or missing.get_json() != {"error": "invalid_token"}
        or missing.headers.get("WWW-Authenticate") != expected_challenge
    ):
        mismatches.append(
            "missing token should return the same structured 401 challenge; "
            f"got {missing.status_code} {missing.get_json()}"
        )

    def database_failure(_token):
        raise oauth_store.DatabaseError("database unavailable")

    token_box["value"] = "database-error-token"
    monkeypatch.setattr(
        protected_resource, "find_access_token", database_failure
    )
    unavailable = resource_http.post("/resource")
    if (
        unavailable.status_code != 503
        or unavailable.get_json() != {"error": "temporarily_unavailable"}
        or unavailable.headers.get("Retry-After") != "1"
    ):
        mismatches.append(
            "DatabaseError should return structured 503 "
            "temporarily_unavailable with Retry-After: 1; "
            f"got {unavailable.status_code} {unavailable.get_json()} "
            f"retry={unavailable.headers.get('Retry-After')!r}"
        )

    assert not mismatches, (
        "Implement validated_access_record() and wire /resource to use the "
        "exact token record plus invalid_token() and "
        "temporarily_unavailable():\n- "
        + "\n- ".join(mismatches)
    )


def test_issued_token_reaches_resource_when_milestones_are_complete(
    authorization_http, authorization_server, resource_http
):
    verifier = "v" * 43
    authorization_server.authorization_codes["integration-code"] = {
        "client_id": "oauth-client-1",
        "redirect_uri": "http://localhost:9000/callback",
        "scope": [],
        "code_challenge": authorization_server.generate_code_challenge(
            verifier
        ),
        "code_challenge_method": "S256",
    }
    import base64

    credentials = base64.b64encode(
        b"oauth-client-1:oauth-client-secret-1"
    ).decode("ascii")
    token_response = authorization_http.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": "integration-code",
            "redirect_uri": "http://localhost:9000/callback",
            "code_verifier": verifier,
        },
        headers={"Authorization": f"Basic {credentials}"},
    )
    assert token_response.status_code == 200

    issued_access_token = token_response.get_json()["access_token"]
    resource_response = resource_http.post(
        "/resource",
        headers={"Authorization": f"Bearer {issued_access_token}"},
    )
    if resource_response.status_code == 501:
        pytest.skip(
            "Blocked by the intentional protectedResource.py "
            "extraction/validation milestones"
        )
    assert resource_response.status_code == 200
    assert resource_response.get_json() == {
        "name": "Protected Resource",
        "description": "This data has been protected by OAuth 2.0",
    }
