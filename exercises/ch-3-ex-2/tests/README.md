# Exercise 2 practitioner tests

The starter `client.py` is the completed Exercise 1 client. The authorization-code flow with PKCE already works. The activity has two parts. First, finish `/fetch_resource`: the request to the protected resource, the status check, and the page that shows the response are provided; return "Missing Access Token" when there is no access token, and send the token as a Bearer credential with `headers = {"Authorization": f"Bearer {access_token}"}`. Second, add the OAuth `state` parameter: in `/authorize`, create a fresh value with `state = secrets.token_urlsafe(24)`, keep it in the global `state`, and send it as the `state` authorization parameter; in `/callback`, return "State value did not match" when the returned `state` is not the stored one. The authorization server already shows the received `state` on its approval page and returns it unchanged with the code or error.

From the exercise directory, create and activate a virtual environment, install the exercise and suite dependencies, then run the tests:

```console
python3.14 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt -r tests/requirements.txt
python -m pytest -q tests
```

Python normally uses its standard-library `sqlite3` module. On Linux with Python 3.14, the runtime requirements also install the pinned `pysqlite3-binary` fallback. `oauth_store.py` selects that fallback only when the interpreter is missing its `_sqlite3` extension; unrelated import failures are not hidden.

The suite always loads the root `client.py`. It is intended to validate the practitioner's completed work in place and never loads `completed/client.py`; that directory is only an answer key.

The starter `client.py` is expected to report three milestone failures: stopping with "Missing Access Token" when there is no token (`test_fetch_resource_without_access_token_makes_no_request`), sending the access token as a Bearer credential (`test_fetch_resource_sends_bearer_contract`), sending a fresh `state` with the authorization request (`test_authorize_builds_registered_redirect`), and rejecting a callback whose `state` does not match (the three `test_callback_rejects_state_mismatch` cases). With the starter `client.py` the suite reports `6 failed, 37 passed`. Once all milestones are implemented in the root `client.py`, the goal is for every test to pass.

No live services are required. Flask test clients call all three applications in process, outbound Requests calls are replaced with `unittest.mock.Mock`, and every test receives a fresh temporary SQLite database. These boundaries keep the suite isolated from the network and persistent local data while checking the request contracts used by the exercise.

## Manual service troubleshooting

The automated suite does not need live services. For a manual browser flow, activate the same exercise `.venv` in every terminal and launch all three scripts from this exercise directory. Before starting, check that ports 9000, 9001, and 9002 are not owned by a sandbox, legacy copy, or another exercise; mixing source trees means the processes use different configuration and token stores.
