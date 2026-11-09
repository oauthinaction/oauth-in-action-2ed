# Chapter 4 Exercise 1 practitioner tests

These tests exercise only the four Python modules in this exercise root: `client.py`, `authorizationServer.py`, `protectedResource.py`, and `oauth_store.py`. The fixture loader resolves each file by its explicit root path, verifies its provenance, and never imports from `completed/`. Do not run this suite against an answer-key tree or copy `completed/` onto `PYTHONPATH`.

## Python 3.14 setup and run

Run these commands from `exercises/ch-4-ex-1`; each command is intentionally shown on one line:

```text
python3.14 -m venv .venv
.venv/bin/python -m pip install --upgrade pip
.venv/bin/python -m pip install -r requirements.txt -r tests/requirements.txt
.venv/bin/python -m pytest tests -q
```

The suite creates a new temporary SQLite database for every test, resets all in-memory client and authorization-server globals (including `last_refresh_epoch`), and replaces `requests.post` with a fail-fast mock. It never needs the three Flask services to be live.

Python normally supplies `_sqlite3`. If that extension is missing, `oauth_store.py` falls back to `pysqlite3`; the root `requirements.txt` pins the Linux/Python 3.14 fallback package. If installation of that fallback fails, use a Python 3.14 build with SQLite support rather than pointing tests at a persistent database.

## Client behavior under test

The root `client.py` is the completed Chapter 3 Exercise 3 client without fixture tokens: the access token, refresh token, and scope all start as `None`. It sends a fresh `state` and an S256 PKCE challenge on every authorization request, and does not request a scope. The callback checks `error` first, then rejects any `state` that does not match the stored one, then requires the PKCE verifier and the code. The client stores the `access_token`, `refresh_token`, and `scope` from the token response and shows them in the Access token, Scope, and Refresh token rows; a new authorization request clears the access token and scope.

Only HTTP status 200 counts as success, for the token endpoint and for the protected resource. A 401 from the protected resource is reported on the client page and never triggers an automatic refresh. The user clicks **Refresh token** (a `POST /refresh` form button that is always enabled), then clicks **Fetch protected resource** again. A successful refresh stores the rotated tokens and scope and records `last_refresh_epoch`, shown as the Last refresh time in the machine's local timezone. Within 20 seconds of a refresh, another refresh is blocked with "You need to wait X seconds before you can refresh again.", and a 401 shows "This is not a freshness problem." instead of the refresh suggestion. Connection errors are rendered as client error pages, never as HTTP 500.

The authorization server registers a single `redirect_uris` string and shows the received `state` on the approval page, with a copy control, or a red NONE when the client sent no state.

During a refresh, the authorization server's console prints "We found a matching refresh token: …" and "Issuing access token … and refresh token … for refresh token …", or "No matching token was found." when the refresh token is unknown or already used. Printing token values is a teaching shortcut; a real server must never log them.

## Expected learning-state result

The untouched root starter is intentionally incomplete only in `protectedResource.py`. Expect exactly two grouped failures, `2 failed, 64 passed, 1 skipped`:

1. `test_milestone_strict_token_extraction_precedence`: strict access-token extraction (`Authorization` header first, then an optional form-body token; query-string tokens are always ignored).
2. `test_milestone_exact_stored_token_validation_and_oauth_errors`: implement `validated_access_record()` for exact SQLite lookup and structured challenged 401 or retryable 503 errors, then wire `/resource` to return data only when that helper returns a valid record. A `(None, None)` helper result must fail closed with `401 invalid_token`, never an assertion-driven 500.

The end-to-end issued-token/resource check (`test_issued_token_reaches_resource_when_milestones_are_complete`) is skipped while the starter returns its explicit 501 milestone response. All client, authorization-server, store, and infrastructure tests pass. Each grouped failure reports all mismatched cases so one early assertion does not hide the rest. With `completed/protectedResource.py` copied over the root file, the suite reports `67 passed` with no failures and no skip.

## Manual same-tree troubleshooting

Automated tests are preferred because they are isolated. If manually troubleshooting, stay in this same `exercises/ch-4-ex-1` tree and use the same `.venv` in every terminal; mixing another exercise tree or interpreter can silently load different code or database drivers.

```text
.venv/bin/python authorizationServer.py
.venv/bin/python protectedResource.py
.venv/bin/python client.py
```

Run each service command from this exercise root in a separate terminal, then open `http://localhost:9000/`. Stop all three services before rerunning pytest so manual processes cannot be mistaken for test dependencies. If imports or SQLite differ between manual and automated runs, confirm `.venv/bin/python -c "import sys, sqlite3; print(sys.executable, sqlite3.sqlite_version)"` and `.venv/bin/python -m pytest tests -q` both use this exact tree and virtual environment.
