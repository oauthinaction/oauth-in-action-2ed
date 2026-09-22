import importlib.util
import sys
import tempfile
from pathlib import Path
from unittest.mock import Mock

import pytest


EXERCISE_DIR = Path(__file__).resolve().parents[1]


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load test module from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


STORE = load_module("ch3_ex1_oauth_store", EXERCISE_DIR / "oauth_store.py")
sys.modules["oauth_store"] = STORE

# authorizationServer initializes its store when imported, just like the original
# Node.js module. Point that startup side effect at a disposable database first.
IMPORT_STORE_DIRECTORY = tempfile.TemporaryDirectory(prefix="ch3-ex1-import-")
STORE.DB_PATH = Path(IMPORT_STORE_DIRECTORY.name) / "oauth.sqlite3"

AUTHORIZATION_SERVER = load_module(
    "ch3_ex1_authorization_server",
    EXERCISE_DIR / "authorizationServer.py",
)
PROTECTED_RESOURCE = load_module(
    "ch3_ex1_protected_resource",
    EXERCISE_DIR / "protectedResource.py",
)
CLIENT = load_module("ch3_ex1_client", EXERCISE_DIR / "client.py")

for flask_app in (CLIENT.app, AUTHORIZATION_SERVER.app, PROTECTED_RESOURCE.app):
    flask_app.config["TESTING"] = True


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
def client_http():
    return CLIENT.app.test_client()


@pytest.fixture
def authorization_http():
    return AUTHORIZATION_SERVER.app.test_client()


@pytest.fixture
def resource_http():
    return PROTECTED_RESOURCE.app.test_client()


@pytest.fixture(autouse=True)
def isolated_runtime(tmp_path, monkeypatch):
    for name in ("state", "code_verifier", "access_token", "scope"):
        setattr(CLIENT, name, None)
    AUTHORIZATION_SERVER.approval_requests.clear()
    AUTHORIZATION_SERVER.authorization_codes.clear()

    monkeypatch.setattr(STORE, "DB_PATH", tmp_path / "oauth.sqlite3")
    STORE.reset_schema()
    guarded_post = Mock(
        side_effect=AssertionError(
            "Unexpected real requests.post attempt; configure the Requests mock seam"
        )
    )
    monkeypatch.setattr(CLIENT.requests, "post", guarded_post)
    yield guarded_post

    for name in ("state", "code_verifier", "access_token", "scope"):
        setattr(CLIENT, name, None)
    AUTHORIZATION_SERVER.approval_requests.clear()
    AUTHORIZATION_SERVER.authorization_codes.clear()


@pytest.fixture
def requests_post(isolated_runtime):
    return isolated_runtime
