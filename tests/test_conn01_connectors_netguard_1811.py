"""Фаза 2 аудита GLM, CONN-01: коннекторы не уносят Bearer-токен во внутреннюю сеть и на http."""
import pytest

from padam.connectors import base


@pytest.mark.parametrize("url", [
    "http://169.254.169.254/latest/meta-data/iam/",
    "https://169.254.169.254/latest/meta-data/",
    "https://127.0.0.1:8080/v1/pages",
    "https://10.0.0.5/api",
    "http://api.notion.com/v1/search",          # не HTTPS
    "https://metadata.google.internal/computeMetadata/v1/",
])
def test_запрещённые_адреса_не_получают_токен(url, monkeypatch):
    отправлено = []
    import urllib.request
    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: отправлено.append(a) or (_ for _ in ()).throw(AssertionError("ушло в сеть")))
    with pytest.raises(base.ConnectorError):
        base.default_http_call("POST", url, {"Authorization": "Bearer secret-notion-token"}, b"{}")
    assert not отправлено
