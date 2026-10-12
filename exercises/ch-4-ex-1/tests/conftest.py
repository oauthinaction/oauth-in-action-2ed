"""Root-only, hermetic fixtures for Chapter 4 Exercise 1."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from unittest.mock import Mock

import pytest


EXERCISE_DIR = Path(__file__).resolve().parents[1]
ROOT_MODULE_PATHS = {
    "oauth_store": EXERCISE_DIR / "oauth_store.py",
    "authorization_server": EXERCISE_DIR / "authorizationServer.py",
    "protected_resource": EXERCISE_DIR / "protectedResource.py",
    "client": EXERCISE_DIR / "client.py",
}


def load_root_module(name: str, path: Path):
    """Load one exact exercise-root file without putting completed/ on sys.path."""
    resolved = path.resolve()
    if resolved.parent != EXERCISE_DIR.resolve() or "completed" in resolved.parts:
        raise RuntimeError(f"Refusing to load a non-root exercise module: {resolved}")
    spec = importlib.util.spec_from_file_location(name, resolved)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load root exercise module from {resolved}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


STORE = load_root_module("ch4_ex1_root_oauth_store", ROOT_MODULE_PATHS["oauth_store"])
# The two servers deliberately use ``from oauth_store import ...``. Supply only
# the explicitly loaded root module for that import; completed/ is never used.
sys.modules["oauth_store"] = STORE
AUTHORIZATION_SERVER = load_root_module(
    "ch4_ex1_root_authorization_server",
    ROOT_MODULE_PATHS["authorization_server"],
)
PROTECTED_RESOURCE = load_root_module(
    "ch4_ex1_root_protected_resource",
    ROOT_MODULE_PATHS["protected_resource"],
)
CLIENT = load_root_module("ch4_ex1_root_client", ROOT_MODULE_PATHS["client"])

LOADED_MODULES = {
    "oauth_store": STORE,
    "authorizationServer": AUTHORIZATION_SERVER,
    "protectedResource": PROTECTED_RESOURCE,
    "client": CLIENT,
}
for module_name, module in LOADED_MODULES.items():
    actual = Path(module.__file__).resolve()
    expected = EXERCISE_DIR / f"{module_name}.py"
    assert actual == expected.resolve(), f"Loaded {actual}, expected root file {expected}"
    assert "completed" not in actual.parts

for flask_app in (CLIENT.app, AUTHORIZATION_SERVER.app, PROTECTED_RESOURCE.app):
    flask_app.config.update(TESTING=True)


@pytest.fixture
def client_module():
    return CLIENT


@pytest.fixture
def authorization_server():
    return AUTHORIZATION_SERVER


@pytest.fixture
def protected_resource():
    return PROTECTED_RESOURCE


@pytest.fixture
def oauth_store():
    return STORE


@pytest.fixture
def loaded_modules():
    return LOADED_MODULES


@pytest.fixture
def client_http():
    return CLIENT.app.test_client()


@pytest.fixture
def authorization_http():
    return AUTHORIZATION_SERVER.app.test_client()


@pytest.fixture
def resource_http():
    return PROTECTED_RESOURCE.app.test_client()


@pytest.fixture(autouse=True)
def isolated_runtime(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Reset all process globals, use disposable SQLite, and deny live HTTP."""
    for name in ("state", "code_verifier", "access_token", "refresh_token", "scope"):
        setattr(CLIENT, name, None)
    AUTHORIZATION_SERVER.approval_requests.clear()
    AUTHORIZATION_SERVER.authorization_codes.clear()

    database_path = tmp_path / "oauth.sqlite3"
    monkeypatch.setattr(STORE, "DB_PATH", database_path)
    STORE.reset_schema()

    guarded_request = Mock(
        name="guarded_session_request",
        side_effect=AssertionError(
            "Unexpected Requests transport call: live OAuth services are never allowed"
        ),
    )
    monkeypatch.setattr(CLIENT.requests.sessions.Session, "request", guarded_request)
    guarded_post = Mock(
        name="guarded_requests_post",
        side_effect=AssertionError(
            "Unexpected requests.post: tests must provide an explicit response; "
            "live OAuth services are never allowed"
        ),
    )
    monkeypatch.setattr(CLIENT.requests, "post", guarded_post)
    yield guarded_post

    for name in ("state", "code_verifier", "access_token", "refresh_token", "scope"):
        setattr(CLIENT, name, None)
    AUTHORIZATION_SERVER.approval_requests.clear()
    AUTHORIZATION_SERVER.authorization_codes.clear()


@pytest.fixture
def requests_post(isolated_runtime):
    return isolated_runtime
