from pathlib import Path


def test_only_exercise_root_modules_are_loaded(loaded_modules):
    expected_names = {
        "oauth_store.py",
        "authorizationServer.py",
        "protectedResource.py",
        "client.py",
    }
    paths = {Path(module.__file__).resolve() for module in loaded_modules.values()}
    assert {path.name for path in paths} == expected_names
    assert all(path.parent.name == "ch-4-ex-1" for path in paths)
    assert all("completed" not in path.parts for path in paths)


def test_client_starts_with_no_oauth_state(client_module):
    assert client_module.state is None
    assert client_module.code_verifier is None
    assert client_module.access_token is None
    assert client_module.refresh_token is None
    assert client_module.scope is None


def test_each_test_uses_a_temporary_initialized_database(oauth_store, tmp_path):
    assert oauth_store.DB_PATH.parent == tmp_path
    assert oauth_store.DB_PATH.name == "oauth.sqlite3"
    assert oauth_store.find_access_token("missing") is None
    assert oauth_store.find_refresh_token("missing") is None
