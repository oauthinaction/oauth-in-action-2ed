from pathlib import Path

import pytest


def test_practitioner_suite_loaded_only_root_modules(
    client_module,
    authorization_server,
    protected_resource,
    oauth_store,
):
    exercise_dir = Path(__file__).resolve().parents[1]
    expected = {
        client_module: exercise_dir / "client.py",
        authorization_server: exercise_dir / "authorizationServer.py",
        protected_resource: exercise_dir / "protectedResource.py",
        oauth_store: exercise_dir / "oauth_store.py",
    }
    for module, path in expected.items():
        loaded_path = Path(module.__file__).resolve()
        assert loaded_path == path.resolve()
        assert "completed" not in loaded_path.parts


def test_every_test_uses_disposable_sqlite(oauth_store, tmp_path):
    assert oauth_store.DB_PATH.parent == tmp_path
    assert oauth_store.DB_PATH.name == "oauth.sqlite3"
    assert oauth_store.DB_PATH.exists()


def test_all_http_apps_render_without_live_services(
    client_http,
    authorization_http,
    resource_http,
):
    assert client_http.get("/").status_code == 200
    assert authorization_http.get("/").status_code == 200
    assert resource_http.get("/").status_code == 200


def test_outbound_get_post_delete_are_fail_closed(
    client_module,
    requests_get,
    requests_post,
    requests_delete,
):
    with pytest.raises(AssertionError, match=r"Unexpected live requests\.get"):
        client_module.requests.get("https://example.invalid")
    with pytest.raises(AssertionError, match=r"Unexpected live requests\.post"):
        client_module.requests.post("https://example.invalid")
    with pytest.raises(AssertionError, match=r"Unexpected live requests\.delete"):
        client_module.requests.delete("https://example.invalid")
    assert requests_get.call_count == requests_post.call_count == requests_delete.call_count == 1


def test_words_actions_use_read_and_write_colors(client_http):
    page = client_http.get("/words")
    stylesheet = client_http.get("/assets/common.css")

    assert page.status_code == 200
    assert b'class="button button-read" href="/get_words"' in page.data
    assert b"GET current words</a>" in page.data
    assert b'class="button button-write" type="submit"' in page.data
    assert b"POST a word</button>" in page.data

    assert stylesheet.status_code == 200
    css = stylesheet.get_data(as_text=True)
    assert ".button-read {" in css
    assert "background: #9fd3f2;" in css
    assert ".button-write {" in css
    assert "background: #8a6200;" in css