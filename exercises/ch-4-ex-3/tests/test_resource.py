from unittest.mock import Mock

from helpers import CLIENT_ID, FULL_PRODUCE


def assert_invalid_token(response):
    assert response.status_code == 401
    assert response.get_json() == {"error": "invalid_token"}
    assert response.headers["WWW-Authenticate"] == (
        'Bearer realm="protected-resource"'
    )


def expected_produce(scope):
    granted = set(scope.split())
    return {
        key: values if key in granted else []
        for key, values in FULL_PRODUCE.items()
    }


def test_strict_bearer_transport_and_exact_lookup(
    resource_http, protected_resource, monkeypatch
):
    lookup = Mock(
        return_value={
            "access_token": "exact-token+/=",
            "client_id": CLIENT_ID,
            "scope": "fruit veggies meats",
        }
    )
    monkeypatch.setattr(protected_resource, "find_access_token", lookup)
    response = resource_http.get(
        "/produce",
        headers={"authorization": "bEaReR exact-token+/="},
    )
    assert response.status_code == 200
    assert lookup.call_args_list == [(('exact-token+/=',), {})]

    for authorization in (
        "bearer   exact-token+/=",
        "Bearer exact-token+/===",
    ):
        rejected = resource_http.get(
            "/produce",
            headers={"Authorization": authorization},
        )
        assert_invalid_token(rejected)
    assert lookup.call_count == 1


def test_missing_unknown_malformed_and_prefix_tokens_are_401(
    resource_http, oauth_store
):
    oauth_store.insert_access_token("stored-token", CLIENT_ID, "fruit")
    attempts = (
        {},
        {"headers": {"Authorization": "Bearer unknown"}},
        {"headers": {"Authorization": "Bearer"}},
        {"headers": {"Authorization": "Basic stored-token"}},
        {"headers": {"Authorization": "Bearer stored"}},
        {
            "headers": {"Authorization": "Bearer"},
            "query_string": {"access_token": "stored-token"},
        },
    )
    for kwargs in attempts:
        assert_invalid_token(resource_http.get("/produce", **kwargs))


def test_query_string_token_is_rejected(resource_http, oauth_store):
    oauth_store.insert_access_token(
        "query-token", CLIENT_ID, "fruit veggies meats"
    )
    response = resource_http.get(
        "/produce", query_string={"access_token": "query-token"}
    )
    assert_invalid_token(response)


def test_resource_database_error_returns_503(
    resource_http, protected_resource, oauth_store, monkeypatch
):
    def fail(_token):
        raise oauth_store.DatabaseError("database unavailable")

    monkeypatch.setattr(protected_resource, "find_access_token", fail)
    response = resource_http.get(
        "/produce", headers={"Authorization": "Bearer database-token"}
    )
    assert response.status_code == 503
    assert response.get_json() == {"error": "temporarily_unavailable"}
    assert response.headers["Retry-After"] == "1"


def test_produce_fails_closed_when_validator_returns_no_record_or_error(
    resource_http,
    protected_resource,
    monkeypatch,
):
    monkeypatch.setattr(
        protected_resource,
        "validated_access_record",
        lambda: (None, None),
    )
    response = resource_http.get("/produce")
    assert_invalid_token(response)


def test_full_scope_returns_complete_three_category_document(
    resource_http, oauth_store
):
    oauth_store.insert_access_token(
        "full-scope-token", CLIENT_ID, "fruit veggies meats"
    )
    response = resource_http.get(
        "/produce", headers={"Authorization": "Bearer full-scope-token"}
    )
    assert response.status_code == 200
    assert response.status_code != 403
    assert response.get_json() == FULL_PRODUCE
    assert set(response.get_json()) == {"fruit", "veggies", "meats"}


def test_scope_filtering_milestone_exactly_matches_each_valid_token_grant(
    resource_http, oauth_store
):
    cases = {
        "no-scope": "",
        "fruit-only": "fruit",
        "veggies-only": "veggies",
        "meats-only": "meats",
        "fruit-veggies": "fruit veggies",
        "fruit-meats": "fruit meats",
        "veggies-meats": "veggies meats",
        "whitespace-and-duplicates": "  fruit   fruit\tmeats  ",
        "substring-decoys": "fruitful veggies2 meats-read",
    }
    mismatches = []
    for case_name, scope in cases.items():
        token = f"filter-{case_name}"
        oauth_store.insert_access_token(token, CLIENT_ID, scope)
        response = resource_http.get(
            "/produce", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code != 403, (
            "A valid token is authorized even with no scopes"
        )
        assert response.status_code == 200
        body = response.get_json()
        assert set(body) == {"fruit", "veggies", "meats"}
        expected = expected_produce(scope)
        if body != expected:
            mismatches.append(f"{case_name}: expected {expected}, got {body}")

    assert not mismatches, (
        "Filtering milestone: populate only categories whose exact scope "
        "name is granted; valid tokens always return all three keys with "
        "ungranted lists empty.\n"
        + "\n".join(mismatches)
    )
