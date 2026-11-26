"""25.11.2026: тесты не видят ключей моделей этой машины — роутер в тестах как на GitHub.

Повод: на машине владельца в окружении стоят настоящие ключи Gemini и файл гранта Vertex; три теста роутера
падали дома, а тест без подмены сети мог бы потратить эти ключи. Защита — tests/conftest.py."""
import os

from padam import router


def test_no_machine_router_settings_inside_tests():
    утечки = [k for k in os.environ if k.startswith(("PADAM_LLM_", "PADAM_VERTEX_", "PADAM_GRANT_"))]
    assert утечки == [], f"router settings leaked from the machine into tests: {утечки}"


def test_router_has_no_paid_or_keyed_contours_by_default():
    имена = [c.name for c in router.load_contours()]
    assert not any(n.startswith("gemini_acct_") for n in имена), имена
    assert "vertex_grant_after_local" not in имена or not any(
        c.api_key for c in router.load_contours() if c.name == "vertex_grant_after_local"), имена
