# Chapter 4 Exercise 2 practitioner tests

These tests exercise **only** the four starter modules in the exercise root: `client.py`, `authorizationServer.py`, `protectedResource.py`, and `oauth_store.py`. They explicitly load those files by path and reject `completed/`; they do not import an installed or same-named exercise module.

## Python 3.14 setup and test commands

Run these exact commands from a shell:

```bash
cd /home/ec2-user/oauth-in-action/oauth-in-action-2ed/exercises/ch-4-ex-2
python3.14 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install -r tests/requirements.txt
python -m pytest tests -q
```

If `python3.14` is not installed, use the repository's available Python 3 interpreter as a local fallback (for example, `python3 -m venv .venv`) and report its version with `python --version`. The authoritative target remains Python 3.14; the Linux Python 3.14 dependency marker installs `pysqlite3-binary` when the standard `_sqlite3` extension is unavailable.

## Isolation and expected milestones

Every test gets a newly reset SQLite database under pytest's temporary directory. Client token/state, authorization approval/code dictionaries, and resource `SAVED_WORDS` are reset before and after every test. `requests.get`, `requests.post`, and `requests.delete` are fail-closed mocks, so the suite never contacts live services on ports 9000, 9001, or 9002.

On the untouched starter, token extraction, exact token-record lookup,
structured `401`/`503` errors, and authentication wiring on every `/words`
method are inherited from completed Exercise 1 and are always-on regression
coverage. Participants modify only operation authorization.

Exactly three tests should fail as practitioner milestones:

1. `test_get_words_requires_exact_read_scope`
2. `test_add_word_requires_exact_write_scope_without_mutation`
3. `test_delete_word_requires_exact_delete_scope_without_mutation`

They turn green when the root protected resource enforces exact
whitespace-delimited `read`, `write`, and `delete` scope membership with the
required 403 challenges and no denied mutation.

The verified progression is:

| Stage | Result |
| --- | --- |
| Untouched Exercise 2 starter | `87 passed, 3 failed` |
| Completed scope checks | `90 passed` |

There are no prerequisite skips because Exercise 2 begins with Exercise 1's
authentication work already complete. The final goal is an all-green suite.

## Troubleshooting

Always run pytest from this exercise directory with `python -m pytest tests -q`. If imports, templates, or counts look unrelated, confirm that the active interpreter and pytest are from the same tree:

```bash
pwd
python -c "import sys; print(sys.executable); print(sys.version)"
python -m pytest --version
python -m pytest tests/test_infrastructure.py -q
```

Do not run a repository-wide pytest command for this practitioner checkpoint: neighboring exercises intentionally contain modules with the same names and different milestones.
