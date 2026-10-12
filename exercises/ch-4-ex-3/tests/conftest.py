import importlib.util
import sys
import tempfile
from pathlib import Path
from unittest.mock import Mock

import pytest


EXERCISE_DIR = Path(__file__).resolve().parents[1]


def load_root_module(name: str, filename: str):
    path = (EXERCISE_DIR / filename).resolve()
    assert path.parent == EXERCISE_DIR.resolve()
    assert "completed" not in path.parts
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load root exercise module from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


STORE = load_root_module("ch4_ex3_root_oauth_store", "oauth_store.py")
sys.modules["oauth_store"] = STORE

# Keep any future import-time database work away from the exercise directory.
IMPORT_STORE_DIRECTORY = tempfile.TemporaryDirectory(prefix="ch4-ex3-import-")
STORE.DB_PATH = Path(IMPORT_STORE_DIRECTORY.name) / "oauth.sqlite3"

AUTHORIZATION_SERVER = load_root_module(
    "ch4_ex3_root_authorization_server", "authorizationServer.py"
)
PROTECTED_RESOURCE = load_root_module(
    "ch4_ex3_root_protected_resource", "protectedResource.py"
)
CLIENT = load_root_module("ch4_ex3_root_client", "client.py")

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
    for name in ("state", "code_verifier", "access_token", "refresh_token", "scope"):
        setattr(CLIENT, name, None)
    AUTHORIZATION_SERVER.approval_requests.clear()
    AUTHORIZATION_SERVER.authorization_codes.clear()

    monkeypatch.setattr(STORE, "DB_PATH", tmp_path / "oauth.sqlite3")
    STORE.reset_schema()

    guarded_get = Mock(
        side_effect=AssertionError(
            "Unexpected real requests.get attempt; configure the requests_get fixture"
        )
    )
    guarded_post = Mock(
        side_effect=AssertionError(
            "Unexpected real requests.post attempt; configure the requests_post fixture"
        )
    )
    monkeypatch.setattr(CLIENT.requests, "get", guarded_get)
    monkeypatch.setattr(CLIENT.requests, "post", guarded_post)
    yield

    for name in ("state", "code_verifier", "access_token", "refresh_token", "scope"):
        setattr(CLIENT, name, None)
    AUTHORIZATION_SERVER.approval_requests.clear()
    AUTHORIZATION_SERVER.authorization_codes.clear()


@pytest.fixture
def requests_get():
    return CLIENT.requests.get


@pytest.fixture
def requests_post():
    return CLIENT.requests.post
