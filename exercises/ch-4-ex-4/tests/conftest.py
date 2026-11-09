import importlib.util
import sys
import tempfile
from pathlib import Path
from unittest.mock import Mock

import pytest


EXERCISE_DIR = Path(__file__).resolve().parents[1]
TESTS_DIR = Path(__file__).resolve().parent


def load_root_module(name, filename):
    path = (EXERCISE_DIR / filename).resolve()
    assert path.parent == EXERCISE_DIR.resolve(), (
        f"Tests may load only root exercise modules: {path}"
    )
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load test module from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


_PREVIOUS_OAUTH_STORE = sys.modules.get("oauth_store")
STORE = load_root_module("ch4_ex4_root_oauth_store", "oauth_store.py")
sys.modules["oauth_store"] = STORE

# Any import-time persistence must be disposable, even if a future
# learner edit adds it.
_IMPORT_STORE_DIRECTORY = tempfile.TemporaryDirectory(
    prefix="ch4-ex4-import-"
)
STORE.DB_PATH = Path(_IMPORT_STORE_DIRECTORY.name) / "oauth.sqlite3"

AUTHORIZATION_SERVER = load_root_module(
    "ch4_ex4_root_authorization_server", "authorizationServer.py"
)
PROTECTED_RESOURCE = load_root_module(
    "ch4_ex4_root_protected_resource", "protectedResource.py"
)
CLIENT = load_root_module("ch4_ex4_root_client", "client.py")

for flask_app in (
    CLIENT.app,
    AUTHORIZATION_SERVER.app,
    PROTECTED_RESOURCE.app,
):
    flask_app.config.update(TESTING=True)


def pytest_sessionfinish(session, exitstatus):
    if _PREVIOUS_OAUTH_STORE is None:
        sys.modules.pop("oauth_store", None)
    else:
        sys.modules["oauth_store"] = _PREVIOUS_OAUTH_STORE
    _IMPORT_STORE_DIRECTORY.cleanup()


@pytest.fixture
def exercise_dir():
    return EXERCISE_DIR


@pytest.fixture
def oauth_store():
    return STORE


@pytest.fixture
def authorization_server():
    return AUTHORIZATION_SERVER


@pytest.fixture
def protected_resource():
    return PROTECTED_RESOURCE


@pytest.fixture
def client_module():
    return CLIENT


@pytest.fixture
def authorization_http():
    return AUTHORIZATION_SERVER.app.test_client()


@pytest.fixture
def resource_http():
    return PROTECTED_RESOURCE.app.test_client()


@pytest.fixture
def client_http():
    return CLIENT.app.test_client()


@pytest.fixture(autouse=True)
def isolated_runtime(tmp_path, monkeypatch):
    STORE.DB_PATH = tmp_path / "oauth.sqlite3"
    STORE.reset_schema()

    AUTHORIZATION_SERVER.approval_requests.clear()
    AUTHORIZATION_SERVER.authorization_codes.clear()
    CLIENT.state = None
    CLIENT.code_verifier = None
    CLIENT.access_token = None
    CLIENT.refresh_token = None
    CLIENT.scope = None
    CLIENT.last_refresh_epoch = None

    guarded_get = Mock(
        side_effect=AssertionError(
            "Unexpected live requests.get attempt; "
            "configure the requests_get fixture"
        )
    )
    guarded_post = Mock(
        side_effect=AssertionError(
            "Unexpected live requests.post attempt; "
            "configure the requests_post fixture"
        )
    )
    monkeypatch.setattr(CLIENT.requests, "get", guarded_get)
    monkeypatch.setattr(CLIENT.requests, "post", guarded_post)
    yield

    AUTHORIZATION_SERVER.approval_requests.clear()
    AUTHORIZATION_SERVER.authorization_codes.clear()
    CLIENT.state = None
    CLIENT.code_verifier = None
    CLIENT.access_token = None
    CLIENT.refresh_token = None
    CLIENT.scope = None
    CLIENT.last_refresh_epoch = None


@pytest.fixture
def requests_get(isolated_runtime):
    CLIENT.requests.get.side_effect = None
    return CLIENT.requests.get


@pytest.fixture
def requests_post(isolated_runtime):
    CLIENT.requests.post.side_effect = None
    return CLIENT.requests.post
