# Exercise 2 practitioner tests

The fixed initial token values are intentional, documented teaching fixtures. The access token is
invalid, while the refresh token is recognized by the authorization server. Running the tests or
the root client demonstrates an immediate protected-resource 401; the refresh lesson requires
neither waiting nor prior authorization.

The client never refreshes on its own. A 401 from the protected resource is reported on the
client page. The user then clicks **Refresh token**, and afterwards clicks **Fetch protected
resource** again. The client page shows the time of the last successful refresh in the machine's
local timezone, stored as epoch seconds in `last_refresh_epoch`. The **Refresh token** button is
always enabled. Clicking it within 20 seconds of a successful refresh does not refresh; the client
page shows "You need to wait X seconds before you can refresh again." instead.

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

An initial exercise implementation is expected to report one milestone failure: making
`refresh_access_token()` exchange the refresh token, require and store both rotated token values,
and return a success boolean (`test_refresh_posts_exact_contract_and_rotates_tokens`). The 401
report, the `/refresh` route, the 20-second limit, and the last-refresh time are provided. The old
refresh token is single-use: the authorization server atomically replaces it, and only the rotated
refresh token can be used again. Refresh cases blocked while the root refresh stub makes no
Requests call are skipped. With the starter `client.py` the suite reports
`1 failed, 48 passed, 5 skipped`. Once the milestone is implemented in the root `client.py`, the
goal is for every test to pass.

No live services are required. Flask test clients call all three applications in process, outbound
Requests calls are replaced with `unittest.mock.Mock`, and every test receives a fresh temporary
SQLite database with the preconfigured refresh fixture seeded synchronously. These boundaries
isolate the suite from the network and persistent local data while checking the request contracts
used by the exercise.
## Manual service troubleshooting

The automated suite does not need live services. For a manual browser flow, activate the same
exercise `.venv` in every terminal and launch all three scripts from this exercise directory.
Before starting, check that ports 9000, 9001, and 9002 are not owned by a sandbox, legacy copy, or
another exercise; mixing source trees means the processes use different configuration and token
stores.