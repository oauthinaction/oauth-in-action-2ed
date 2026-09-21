# Exercise 2 practitioner tests

The fixed initial token values are intentional, documented teaching fixtures. The access token is
invalid, while the refresh token is recognized by the authorization server. Running the tests or
the root client demonstrates an immediate protected-resource 401 followed by the two learner
refresh tasks; the refresh lesson requires neither waiting nor prior authorization.

From the exercise directory, create and activate a Python 3.14 virtual environment, install the
exercise and suite dependencies, then run the tests:

```console
python3.14 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt -r tests/requirements.txt
python -m pytest -q tests
```

Python normally uses its standard-library `sqlite3` module. On Linux with Python 3.14, the runtime
requirements also install the pinned `pysqlite3-binary` fallback. `oauth_store.py` selects that
fallback only when the interpreter is missing its `_sqlite3` extension; unrelated import failures
are not hidden.

The suite always loads the root `client.py`. It is intended to validate the practitioner's
completed work in place and never loads `completed/client.py`; that directory is only an answer
key.

An initial exercise implementation is expected to report two milestone failures: making
`refresh_access_token()` exchange the refresh token, update token state, and return a success
boolean; and making `fetch_resource()` own error rendering plus one guarded retry redirect after a
successful refresh. Secondary refresh error cases blocked while the root refresh stub makes no
Requests call are skipped. As each milestone is implemented in the root `client.py`, the goal is
for every test to pass.

No live services are required. Flask test clients call all three applications in process, outbound
Requests calls are replaced with `unittest.mock.Mock`, and every test receives a fresh temporary
SQLite database with the preconfigured refresh fixture seeded synchronously. These boundaries
isolate the suite from the network and persistent local data while checking the request contracts
used by the exercise.
