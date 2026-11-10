"""0.4.4: форматы ключей сервисов, добавленные после первого круга Red Team. Каждый формат — проверен здесь.

Значения выдуманные и склеены из частей, чтобы хостинг кода не принимал тест за утечку.
"""

import pytest

from padam import safety

H32, H40, H64 = "0123456789abcdef" * 2, ("0123456789abcdef" * 3)[:40], "0123456789abcdef" * 4
A40 = "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx2Yz3A"

КЛЮЧИ = {
    "notion": "secret" + "_" + "9f8e7d6c5b4a3f2e1d0c9b8a7f6e5d4c3b2a1f0e9d8",
    "notion_ntn": "ntn" + "_" + "12345678901" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op8Qr9St0Uv1Wx",
    "linear": "lin" + "_api_" + "8a7b6c5d4e3f2a1b0c9d8e7f6a5b4c3d2e1f0a9b",
    "shopify": "shp" + "at_" + H32,
    "grafana": "glsa" + "_" + "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d" + "_98765432",
    "grafana_cloud": "glc" + "_" + "eyJvIjoiMTIzNDU2NyIsIm4iOiJzdGFjayIsImsiOiJ4eXoifQ==",
    "vault": "hvs" + "." + "CAESIJ_FakeVaultToken0123456789abcdef",
    "sentry": "sntrys" + "_" + H64,
    "bitbucket": "ATBB" + "abcdef0123456789abcdef012345",
    "airtable": "pat" + "9a8b7c6d5e4f3a" + "." + H64,
    "digitalocean": "dop" + "_v1_" + H64,
    "postman": "PMAK" + "-" + H32[:24] + "-" + (H32 + H32)[:34],
    "square": "sq0" + "atp-" + "Ab1Cd2Ef3Gh4Ij5Kl6Mn7Op",
    "figma": "figd" + "_" + A40,
    "perplexity": "pplx" + "-" + A40 + "abcdefgh",
    "groq": "gsk" + "_" + A40 + "abcdefghijkl",
    "slack_app": "xapp" + "-1-" + "A0123ABCD" + "-1234567890-" + H64,
    "supabase": "sbp" + "_" + H40,
    "planetscale": "pscale" + "_tkn_" + A40,
    "doppler": "dp" + ".st." + A40,
    "replicate": "r8" + "_" + A40[:37],
    "sendgrid": "SG" + "." + "9a8b7c6d5e4f3a2b1c0d9e" + "." + "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c",
    "discord": "MTAw" + "MDAwMDAwMDAwMDAwMDAwMA" + ".GzXyZa." + "abcdef1234567890abcdef1234567890abcdef",
}


@pytest.mark.parametrize("сервис", sorted(КЛЮЧИ))
def test_service_token_is_masked(сервис):
    ключ = КЛЮЧИ[сервис]
    итог = safety.redact(f"Ключ {сервис}: {ключ} — в конфиге")[0]
    assert ключ not in итог and "[REDACTED:" in итог


@pytest.mark.parametrize("обычное", [
    "secret_key_rotation_policy описан в README",            # имя переменной, не ключ
    "pattern matching: pat.match(x) returns None",
    "SG.Pk.short не ключ",
    "Version M1.2.3 released",
    "redis://localhost:6379/0 без пароля",
])
def test_ordinary_text_is_left_alone(обычное):
    assert safety.redact(обычное)[0] == обычное


def test_url_password_with_empty_user():
    итог = safety.redact("redis://:" + "Str0ngPass2026!" + "@10.0.0.1:6379/0")[0]
    assert "Str0ngPass2026!" not in итог and итог.startswith("redis://:[REDACTED")
