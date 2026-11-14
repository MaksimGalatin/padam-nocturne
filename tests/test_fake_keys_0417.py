# -*- coding: utf-8 -*-
"""0.4.17: проверка на фейковых ключах перед сменой настоящих (13.11.2026).

Ключи генерируются случайно (с фиксированным зерном) в форматах реальных сервисов и вставляются в 20 форм, в которых
люди пишут ключи в заметках: присваивание, .env, JSON, таблица Markdown, «ИМЯ — значение», и проза без двоеточия —
«my api key is X», «новый ключ X — сохрани», «set K to X», «K теперь X». Значение не должно остаться в тексте.
И обратная сторона: обычные фразы со словами key / token / password / ключ не маскируются.
"""
import random
import string

import pytest

from padam import safety

_A = string.ascii_letters + string.digits
ФОРМЫ = ['{k}={v}', 'export {k}="{v}"', 'мой {k}: {v}', 'Вот ключ от сервиса, запиши: {v}', '| {k} | {v} |', '{k} — {v}',
         'токен: {v}', 'secret for the bot: {v}', 'my api key is {v}', 'пароль от базы: {v}', '"{k}": "{v}"', '{{"{k}":"{v}"}}',
         '# .env\nPORT=3000\n{k}={v}\n', 'Запомни на будущее, {k} теперь {v}', 'новый ключ {v} — сохрани', '{k}:\n{v}',
         'set {k} to {v} please', 'ключ API от сервиса — {v}', 'Here is the token {v}, keep it.', 'пароль {v}']


def _фейки(r: random.Random) -> dict:
    def rnd(n, al=_A):
        return "".join(r.choice(al) for _ in range(n))
    return {
        "TELEGRAM_BOT_TOKEN": f"{r.randint(10**9, 10**10 - 1)}:AA{rnd(33, _A + '_-')}",
        "PAYMENTS_API_KEY": "-".join(rnd(7).upper() for _ in range(4)),
        "IPN_SECRET": rnd(32),
        "MASTER_KEY": "".join(r.choice("0123456789abcdef") for _ in range(64)),
        "ENCRYPTION_SECRET": rnd(43, _A + "_-"),
        "DB_PASSWORD": "npg_" + rnd(12),
        "OPENAI_API_KEY": "sk-proj-" + rnd(48),
        "MAIL_API_KEY": "re_" + rnd(8) + "_" + rnd(24),
        "DEPLOY_TOKEN": rnd(24),
    }


СЛУЧАИ = []
_r = random.Random(17)
for _ in range(12):
    for _k, _v in _фейки(_r).items():
        for _f in ФОРМЫ:
            СЛУЧАИ.append((_f.format(k=_k, v=_v), _v))


def test_ни_одно_фейковое_значение_не_остаётся():
    утечки = [(t, v) for t, v in СЛУЧАИ if v in safety.redact(t)[0]]
    assert not утечки, f"{len(утечки)} из {len(СЛУЧАИ)}: {утечки[:3]}"


@pytest.mark.parametrize("v", ["CVNUVBI-VBOEINQ-NELLAIQ-RRQDYBH", "QwErTyUiOpAsDfGhJkLzXcVb"])
def test_ключ_без_цифр(v):
    # 7×4 из одних букв и случайная строка двух регистров без цифр: strong_secret их не видел.
    for f in ("my api key is {v}", "DEPLOY_TOKEN={v}", "| DEPLOY_TOKEN | {v} |"):
        assert v not in safety.redact(f.format(v=v))[0]


@pytest.mark.parametrize("строка", [
    "commit hash: 0a6925a84c8b9759df49f91b4e4b85ab29ade061",
    "The key insight is that memory decays.",
    "ключ к успеху — постоянство",
    "token count: 128000",
    "password reset link was sent to the user yesterday",
    "API key rotation is planned for Friday.",
    "the cache key is user_profile_settings_v2",
    "the session key is authenticationServiceToken",
    "secret santa list is ready",
    "Токен $GALATIN, эмиссия 10 000 000 000.",
    '{"type":"started","key":"v2:9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f9f"}',
    # Ложные маски черновика 0.4.17 на LongMemEval-S (51 реплика из 189 635), каждая — свой класс:
    "**Key Considerations:**\n\n1. **Space**: Measure your room.",
    "several key agreements, including the 1987 Intermediate-Range Nuclear Forces Treaty.",
    "--key-name MyKeyPair --security-group-ids sg-01234567890abcdef0 --subnet-id subnet-01234567890abcdef0",
    "you will shortly receive a link to reset your password.\"}, status=status.HTTP_200_OK)",
    "headers: { 'API-Key': process.env.MONGO_API_KEY }",
    "low-key, or something a bit more trendy and hipster-friendly",
])
def test_обычные_фразы_не_маскируются(строка):
    assert safety.redact(строка)[1] == {}


def test_настоящий_ключ_в_коде_из_корпуса():
    # Единственная новая маска на всём LongMemEval-S — настоящий ключ API (hex 40) в примере кода.
    t = '# Set your SparkPost API key\nsparkpost_api_key="5d4d97f437cb777fdaa63f6c9af1e62230e7f12b"'
    assert "5d4d97f437cb777f" not in safety.redact(t)[0]
