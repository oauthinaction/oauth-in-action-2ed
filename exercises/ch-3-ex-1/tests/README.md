# Exercise 1 practitioner tests

From the exercise directory, create and activate a virtual environment, install the exercise and suite dependencies, then run the tests:

```console
python3.14 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt -r tests/requirements.txt
python -m pytest -q tests
```

Python normally uses its standard-library `sqlite3` module. On Linux with Python 3.14, the runtime requirements also install the pinned `pysqlite3-binary` fallback. `oauth_store.py` selects that fallback only when the interpreter is missing its `_sqlite3` extension; unrelated import failures are not hidden.

The suite always loads the root `client.py`. It is intended to validate the practitioner's completed work in place and never loads `completed/client.py`; that directory is only an answer key.

An initial exercise implementation is expected to report two milestone failures: constructing the authorization redirect, and exchanging the authorization code with the PKCE verifier. Fetching the protected resource is the Exercise 2 activity, so this client has no Fetch protected resource button. Secondary error-path cases blocked by an unimplemented HTTP 501 response are skipped. A token response counts as successful only with status 200. As each milestone is implemented in the root `client.py`, the goal is for every test to pass.

No live services are required. Flask test clients call all three applications in process, outbound Requests calls are replaced with `unittest.mock.Mock`, and every test receives a fresh temporary SQLite database. These boundaries keep the suite isolated from the network and persistent local data while checking the request contracts used by the exercise.

## Manual service troubleshooting

The automated suite does not need live services. For a manual browser flow, activate the same exercise `.venv` in every terminal and launch all three scripts from this exercise directory. Before starting, check that ports 9000, 9001, and 9002 are not owned by a sandbox, legacy copy, or another exercise; mixing source trees means the processes use different configuration and token stores.
