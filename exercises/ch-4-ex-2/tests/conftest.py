import importlib.util
import sys
import tempfile
from pathlib import Path
from unittest.mock import Mock

import pytest


EXERCISE_DIR = Path(__file__).resolve().parents[1]
ROOT_MODULE_PATHS = {
    "client": EXERCISE_DIR / "client.py",
    "authorization_server": EXERCISE_DIR / "authorizationServer.py",
    "protected_resource": EXERCISE_DIR / "protectedResource.py",
    "oauth_store": EXERCISE_DIR / "oauth_store.py",
}


def load_root_module(name, path):
    path = path.resolve()
    if path.parent != EXERCISE_DIR or "completed" in path.parts:
        raise RuntimeError(f"Practitioner tests may load only root modules: {path}")
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load root exercise module from {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


STORE = load_root_module("ch4_ex2_root_oauth_store", ROOT_MODULE_PATHS["oauth_store"])
sys.modules["oauth_store"] = STORE

# Point any import-time or accidental setup at a disposable location before loading
# the three applications. Production does not currently initialize on import, but the
# ordering keeps the practitioner boundary safe if startup details change.
IMPORT_STORE_DIRECTORY = tempfile.TemporaryDirectory(prefix="ch4-ex2-root-import-")
STORE.DB_PATH = Path(IMPORT_STORE_DIRECTORY.name) / "oauth.sqlite3"

AUTHORIZATION_SERVER = load_root_module(
    "ch4_ex2_root_authorization_server",
    ROOT_MODULE_PATHS["authorization_server"],
)
PROTECTED_RESOURCE = load_root_module(
    "ch4_ex2_root_protected_resource",
    ROOT_MODULE_PATHS["protected_resource"],
)
CLIENT = load_root_module("ch4_ex2_root_client", ROOT_MODULE_PATHS["client"])

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


def guarded_request_mock(method):
    return Mock(
        name=f"guarded_requests_{method}",
        side_effect=AssertionError(
            f"Unexpected live requests.{method} attempt; configure the test mock first"
        ),
    )


@pytest.fixture(autouse=True)
def isolated_runtime(tmp_path, monkeypatch):
    CLIENT.state = None
    CLIENT.code_verifier = None
    CLIENT.access_token = None
    CLIENT.refresh_token = None
    CLIENT.scope = None
    AUTHORIZATION_SERVER.approval_requests.clear()
    AUTHORIZATION_SERVER.authorization_codes.clear()
    PROTECTED_RESOURCE.SAVED_WORDS.clear()

    monkeypatch.setattr(STORE, "DB_PATH", tmp_path / "oauth.sqlite3")
    STORE.reset_schema()

    guards = {
        "get": guarded_request_mock("get"),
        "post": guarded_request_mock("post"),
        "delete": guarded_request_mock("delete"),
    }
    monkeypatch.setattr(CLIENT.requests, "get", guards["get"])
    monkeypatch.setattr(CLIENT.requests, "post", guards["post"])
    monkeypatch.setattr(CLIENT.requests, "delete", guards["delete"])
    yield guards

    CLIENT.state = None
    CLIENT.code_verifier = None
    CLIENT.access_token = None
    CLIENT.refresh_token = None
    CLIENT.scope = None
    AUTHORIZATION_SERVER.approval_requests.clear()
    AUTHORIZATION_SERVER.authorization_codes.clear()
    PROTECTED_RESOURCE.SAVED_WORDS.clear()


@pytest.fixture
def requests_get(isolated_runtime):
    return isolated_runtime["get"]


@pytest.fixture
def requests_post(isolated_runtime):
    return isolated_runtime["post"]


@pytest.fixture
def requests_delete(isolated_runtime):
    return isolated_runtime["delete"]
