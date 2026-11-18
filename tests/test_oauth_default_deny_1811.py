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


def test_root01_все_инструменты_перебором(monkeypatch):
    """Фаза 2 ROOT-01: actor=None остаётся только у процесса владельца (stdio/консоль). По сети любой инструмент,
    не названный явно в READ/WRITE/SLEEP, требует padam:owner — перебор ВСЕХ зарегистрированных, а не выборки."""
    monkeypatch.setenv("PADAM_MCP_ARK_TOOLS", "1")   # не os.environ: флаг не должен протечь в другие тесты
    from padam import mcp_server
    names = {t["name"] for t in mcp_server._list_tools_payload()} | set(mcp_server._ALL_TOOLS_BY_NAME)
    явные = oauth.READ_TOOLS | oauth.WRITE_TOOLS | oauth.SLEEP_TOOLS
    for n in sorted(names - явные):
        assert _need(n) == oauth.OWNER_SCOPE, n
    # деньги, выгрузка, площадки, магазины и бенчмарк не должны попасть в чтение/запись
    for опасный in ("padam_export", "padam_freelance_hub", "padam_platform_connect", "padam_token_budget",
                    "padam_benchmark", "padam_mesh_sync", "padam_phoenix_family"):
        assert опасный not in oauth.READ_TOOLS | oauth.WRITE_TOOLS, опасный
