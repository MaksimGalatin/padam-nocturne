"""Фаза 2 аудита GLM, API-01: session.json Studio с токеном владельца доступен только владельцу."""
from padam import api, net_guard


def test_session_json_только_владельцу(tmp_path):
    p = api.write_session_file(tmp_path / "PADAM Studio", {"port": 1, "token": "secret-token", "pid": 1, "ppid": 1})
    assert p.exists() and "secret-token" in p.read_text(encoding="utf-8")
    assert net_guard.verify_owner_only_permissions(p)
