# Exercise 3 practitioner tests

This suite targets **Python 3.14** and validates the complete Chapter 4 Exercise 3 OAuth flow: PKCE and state, registered client/redirect/scope boundaries, consent narrowing, access/refresh token-pair issuance, scope-preserving refresh rotation and replay rejection, client Produce API contracts and bounded retry, strict resource bearer lookup, database failure handling, and exact per-category scope filtering.

## Root-only boundary

The suite explicitly loads only these files from the exercise root by exact path:

- `oauth_store.py`
- `authorizationServer.py`
- `client.py`
- `protectedResource.py`

It never imports or executes `completed/`; that directory is only an answer key. Run the tests against your edits in the root files. Do not copy the suite into `completed/` and do not add `completed/` to `PYTHONPATH`.

No live services are used. Flask test clients invoke all three applications in process, every test receives a fresh temporary SQLite database, all process-global authorization/client state is reset, and both `requests.get` and `requests.post` are guarded so an unexpected network call fails immediately. Ports 9000–9002 do not need to be open.

## Python 3.14 setup and run

From `exercises/ch-4-ex-3`:

```console
python3.14 --version
python3.14 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt -r tests/requirements.txt
python -m pytest -q tests
```

The test dependency is pinned to `pytest==9.1.1`. Runtime dependencies are pinned in the exercise’s root `requirements.txt`. Python normally uses the standard-library `sqlite3`; on Linux/Python 3.14, the pinned `pysqlite3-binary` fallback is installed and is selected only if `_sqlite3` is unavailable.

## Expected starter result

The untouched root intentionally has **one failing test**:

```text
test_scope_filtering_milestone_exactly_matches_each_valid_token_grant
```

That single aggregated milestone explains every missing filtering case without turning one learner task into many failures. All support tests should pass. A valid access token must always receive HTTP 200 and exactly the `fruit`, `veggies`, and `meats` keys. No scope means three empty lists; each singleton or partial grant populates only matching categories; all three scopes return all values; names such as `fruitful` must not match `fruit`; a valid token is never rejected with 403. Once the root filtering TODO is implemented, the complete suite should pass.

## Troubleshooting

- **Wrong Python:** verify both `python3.14 --version` and `python --version` after activation report Python 3.14.
- **`No module named pytest`:** install both manifests with the command above; do not rely on a repository-level environment created for another Python version.
- **`No module named _sqlite3`:** on Linux/Python 3.14, reinstall the root requirements so the pinned fallback is available. On other platforms, use a Python build that includes SQLite support.
- **Unexpected network-call assertion:** a test reached an unconfigured Requests seam. Tests must configure `requests_get`/`requests_post`; they must never require running localhost services.
- **Persistent or order-dependent failures:** run from this exercise directory and avoid importing a different exercise in the same custom pytest invocation. The suite itself uses unique module names, temporary SQLite, and reset globals.
- **Template/static file errors:** confirm the four root scripts and `files/` remain in `exercises/ch-4-ex-3`; module loading is path-based and independent of the shell working directory.
- **Manual browser flow:** the automated tests do not need it. If you separately run the services, use this same exercise environment in each terminal and ensure ports 9000, 9001, and 9002 are not occupied by another exercise or sandbox.
