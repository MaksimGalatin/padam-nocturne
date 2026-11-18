# Аудит GLM 18.11.2026, MCP-02/03: клиент со скоупом padam:read не получает экспорт и действия владельца.
from padam import oauth


def _need(name):
    return oauth.required_scope_for_rpc({"method": "tools/call", "params": {"name": name}})


def test_чтение_только_явный_список():
    for n in ("padam_search", "padam_timeline", "padam_stats", "padam_profile", "padam_recent"):
        assert _need(n) == "padam:read"


def test_экспорт_и_всё_остальное_только_владелец():
    for n in ("padam_export", "padam_freelance_hub", "padam_family_feed", "padam_partner_find_clients",
              "padam_batch", "some_future_tool"):
        assert _need(n) == oauth.OWNER_SCOPE, n
    assert oauth.OWNER_SCOPE not in oauth.ALL_SCOPES  # через OAuth-регистрацию не выдаётся


def test_запись_и_сон_как_раньше():
    assert _need("padam_write") == "padam:write"
    assert _need("padam_sleep") == "padam:sleep"
