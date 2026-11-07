from pathlib import Path

import pytest

from wstg import config

REPO = Path(__file__).resolve().parents[1]


def env_for(tmp_path: Path, **extra) -> dict:
    return {"WSTG_EVIDENCE_ROOT": str(tmp_path / "ev"), "WSTG_DB_PATH": str(tmp_path / "w.sqlite3"), **extra}


def test_load_defaults(tmp_path):
    c = config.load(env_for(tmp_path))
    assert c.app_port == config.DEFAULT_APP_PORT
    assert c.client_allowed("192.168.10.5")
    assert c.client_allowed("127.0.0.1")
    assert not c.client_allowed("10.0.0.1")
    assert not c.client_allowed("203.0.113.9")
    assert not c.client_allowed(None)


def test_required_paths(tmp_path):
    with pytest.raises(config.ConfigError, match="WSTG_DB_PATH"):
        config.load({"WSTG_EVIDENCE_ROOT": str(tmp_path)})
    with pytest.raises(config.ConfigError, match="absolute"):
        config.load(env_for(tmp_path, WSTG_DB_PATH="relative.sqlite3"))


@pytest.mark.parametrize("key", ["WSTG_EVIDENCE_ROOT", "WSTG_DB_PATH"])
def test_refuses_data_inside_repo(tmp_path, key):
    env = env_for(tmp_path, **{key: str(REPO / "data" / "x")})
    with pytest.raises(config.ConfigError, match="inside the repository"):
        config.load(env)


def test_refuses_symlink_into_repo(tmp_path):
    link = tmp_path / "link"
    link.symlink_to(REPO)
    with pytest.raises(config.ConfigError, match="inside the repository"):
        config.load(env_for(tmp_path, WSTG_EVIDENCE_ROOT=str(link / "evidence")))


def test_config_file(tmp_path):
    f = tmp_path / "wstg.env"
    f.write_text(
        "# comment\n"
        f"export WSTG_EVIDENCE_ROOT='{tmp_path / 'ev'}'\n"
        f"WSTG_DB_PATH=\"{tmp_path / 'db.sqlite3'}\"\n"
        "WSTG_ALLOWED_NETWORKS=10.1.0.0/16\n"
        "WSTG_SECRET_KEY=from-file\n")
    c = config.load({"WSTG_CONFIG": str(f), "WSTG_SECRET_KEY": "from-env"})
    assert c.evidence_root == tmp_path / "ev"
    assert c.secret_key == "from-env"  # environment wins
    assert c.client_allowed("10.1.2.3") and not c.client_allowed("192.168.0.1")


def test_config_file_inside_repo_refused(tmp_path):
    with pytest.raises(config.ConfigError, match="inside the repository"):
        config.load({"WSTG_CONFIG": str(REPO / "wstg.env")})


def test_bad_network(tmp_path):
    with pytest.raises(config.ConfigError, match="WSTG_ALLOWED_NETWORKS"):
        config.load(env_for(tmp_path, WSTG_ALLOWED_NETWORKS="not-a-net"))


def test_default_config_file_is_used_when_wstg_config_is_unset(tmp_path, monkeypatch):
    f = tmp_path / ".config" / "wstg2" / "wstg2.env"
    f.parent.mkdir(parents=True)
    f.write_text(f"WSTG_EVIDENCE_ROOT={tmp_path}/e\nWSTG_DB_PATH={tmp_path}/d.db\n")
    monkeypatch.setenv("HOME", str(tmp_path))
    for k in [k for k in __import__("os").environ if k.startswith("WSTG_")]:
        monkeypatch.delenv(k)
    assert config.load().evidence_root == tmp_path / "e"
