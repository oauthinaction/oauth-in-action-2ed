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

The suite creates a new temporary SQLite database for every test, resets all in-memory client/authorization globals, and replaces `requests.post` with a fail-fast mock. It never needs the three Flask services to be live.

Python normally supplies `_sqlite3`. If that extension is missing, `oauth_store.py` falls back to `pysqlite3`; the root `requirements.txt` pins the Linux/Python 3.14 fallback package. If installation of that fallback fails, use a Python 3.14 build with SQLite support rather than pointing tests at a persistent database.

## Expected learning-state result

The untouched root starter is intentionally incomplete only in `protectedResource.py`. Expect exactly two grouped failures:

1. strict access-token extraction (`Authorization` header first, then an
   optional form-body token; query-string tokens are always ignored), and
2. implement `validated_access_record()` for exact SQLite lookup and structured
   challenged 401/retryable 503 errors, then wire `/resource` to return data only
   when that helper returns a valid record. A `(None, None)` helper result must
   fail closed with `401 invalid_token`, never an assertion-driven 500.

The end-to-end issued-token/resource check is skipped while the starter returns its explicit 501 milestone response. All client, authorization-code, refresh rotation/replay, database atomicity, transport, and isolation tests should pass. Each grouped failure reports all mismatched cases so one early assertion does not hide the rest. The goal after implementing both root TODO milestones is an all-green run with no failures and no milestone skip.

## Manual same-tree troubleshooting

Automated tests are preferred because they are isolated. If manually troubleshooting, stay in this same `exercises/ch-4-ex-1` tree and use the same `.venv` in every terminal; mixing another exercise tree or interpreter can silently load different code or database drivers.

```text
.venv/bin/python authorizationServer.py
.venv/bin/python protectedResource.py
.venv/bin/python client.py
```

Run each service command from this exercise root in a separate terminal, then open `http://localhost:9000/`. Stop all three services before rerunning pytest so manual processes cannot be mistaken for test dependencies. If imports or SQLite differ between manual and automated runs, confirm `.venv/bin/python -c "import sys, sqlite3; print(sys.executable, sqlite3.sqlite_version)"` and `.venv/bin/python -m pytest tests -q` both use this exact tree and virtual environment.
