# Chapter 4 Exercise 4 practitioner tests

This is a **Python 3.14** practitioner suite for the root implementation of Chapter 4 Exercise 4. It checks the inherited OAuth authorization-code flow (state, S256 PKCE, exact redirect URI, OAuth Basic client authentication, granted scope, one-time codes, rotating refresh tokens), then checks this exercise's resource-owner binding from approval through storage and the Favorites API.

## Client behavior under test

The client is the Chapter 4 base client. `/authorize` sends a fresh random `state`, an S256 PKCE challenge, the single registered redirect URI, and the requested scope `movies foods music`. `/callback` checks `error` first, then rejects any `state` that does not match with "State value did not match", then checks the PKCE verifier and the code. The authorization server's approval page shows the received state next to the Alice/Bob selector.

Only HTTP status 200 counts as success, for the token endpoint and for the Favorites API. Each click on "Get the resource owner's favorites" sends exactly one `GET` to `http://localhost:9002/favorites` with only the Bearer header and renders the returned owner and lists with the granted scope. Any other status clears the access token: a 401 returns the client page with a notice, and any other status shows `Status: N, unable to fetch favorites.` Connection errors clear the access token and show a controlled error page instead of HTTP 500. Response bodies from the exercise's own servers are trusted and not shape-checked.

The client never refreshes automatically. The user clicks the "Refresh token" button (`POST /refresh`), which rotates the token pair, records the Last refresh time, and redirects back to the client page with 303. Another refresh is blocked for 20 seconds with a "You need to wait N seconds" notice. A 401 within those 20 seconds explains that the fresh token was rejected and that this is not a freshness problem.

During a refresh, the authorization server's console prints "We found a matching refresh token: …" and "Issuing access token … and refresh token … for refresh token …", or "No matching token was found." when the refresh token is unknown or already used. Printing token values is a teaching shortcut; a real server must never log them.

## Run the suite

From this exact exercise directory, create a Python 3.14 environment and install both runtime and test dependencies:

```console
cd /home/ec2-user/oauth-in-action/oauth-in-action-2ed/exercises/ch-4-ex-4
python3.14 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt -r tests/requirements.txt
python -m pytest -q tests
```

The test dependency is pinned to `pytest==9.1.1`. The exercise runtime requirements are also pinned. Python normally supplies `sqlite3`; on Python 3.14 Linux, `requirements.txt` installs the pinned `pysqlite3-binary` fallback, and `oauth_store.py` uses it only when the interpreter lacks `_sqlite3`.

## Root-only answer-key boundary and expected milestone

The suite explicitly imports only these files from the exercise root: `oauth_store.py`, `authorizationServer.py`, `client.py`, and `protectedResource.py`. It never imports or executes `completed/protectedResource.py`; `completed/` is an answer key, not test input. Run pytest from this exercise tree so similarly named modules from another chapter or checkout cannot mask the learner's work.

On the untouched starter, the expected result is **one clear grouped failure** (`1 failed, 72 passed`):

```text
test_root_learner_owner_selection_returns_exact_alice_and_bob_fixtures
```

That milestone asks the root `protectedResource.py` to inspect the already validated `access_record["resource_owner"]`, return the exact Alice fixture for `alice`, the exact Bob fixture for `bob`, and the explicit empty Unknown fixture otherwise. The corrected Alice movie title is `The Multidimensional Vector`. Once that single TODO is implemented, the full suite should pass. Copying `completed/protectedResource.py` over the root file in a temporary copy of this folder gives `73 passed`.

The authorization page's Alice/Bob selector is intentionally insecure. It is a visible exercise fixture for demonstrating owner propagation, **not authentication** and not a production design. The owner must come only from a validated approval selection, be bound to the authorization code, and then be read from persisted access/refresh records. Request query values, headers, token-request owner fields, display names, and scope must never choose or override an owner.

## Isolation and no-live-service guarantees

No service needs to be running. Flask test clients invoke all three applications in process. Both outbound `requests.get` and `requests.post` are guarded and replaced by explicit mocks in client contract tests. Every test receives a newly reset SQLite file under pytest's temporary directory; import-time storage is also redirected to a temporary owner-aware database. Authorization/client globals are reset before and after every test. The repository `database.sqlite3`, production source, and answer key are not changed.

The resource contract deliberately does not filter Favorites categories by scope: every valid persisted owner response is HTTP 200 and includes `movies`, `foods`, and `music`. Invalid or unknown bearer tokens are 401, database failures are 503, and a valid token with an unknown stored owner receives the explicit empty `NO_DATA` object, which the client page shows as NO DATA.

## Same-tree troubleshooting

If imports, templates, ports, or token data look inconsistent:

1. Confirm `pwd` ends in `oauth-in-action-2ed/exercises/ch-4-ex-4` and `python --version` reports Python 3.14.
2. Run `python -m pytest -q tests`, not a global `pytest`, so the activated interpreter owns the process.
3. Confirm dependencies came from this directory's `requirements.txt` and `tests/requirements.txt`.
4. Do not copy tests into another exercise and do not put `completed/` on `PYTHONPATH`.
5. The automated suite uses no ports. If manually testing instead, stop processes from other exercises/checkouts before launching ports 9000, 9001, and 9002, and launch every service from this same source tree and environment.
6. Persistent manual data is irrelevant to pytest because the suite uses temporary SQLite. If a manual flow has a legacy database, starting the root authorization server resets it; importing modules during pytest does not.
