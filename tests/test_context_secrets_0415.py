# 0.4.15: секрет по подписи рядом с ним — шесть видов из пропусков круга 6 Red Team (12.11.2026).
# Каждый вид проверяется в обе стороны: секрет закрыт И похожая обычная речь осталась как была.
import pytest

from padam import safety


def _закрыт(текст: str, секрет: str) -> str:
    маска, _ = safety.redact(текст)
    assert секрет not in маска, маска
    return маска


@pytest.mark.parametrize("текст, секрет", [
    ("Чтобы не забыть пароль от нашего семейного сейфа, запишу его прямо между строками рецепта: V7$kP9!mQ2#xL4&zR8.",
     "V7$kP9!mQ2#xL4&zR8"),
    ("Артём, пароль от архива я поставил такой: Krapiva-749-Zebra!22 — запиши себе.", "Krapiva-749-Zebra!22"),
    ("El código maestro del servidor de respaldo es: Bruma-Norte-8391#kQ", "Bruma-Norte-8391#kQ"),
    ("Тома VeraCrypt монтируются с использованием мастер-ключ-фразы: Tr0ub4dor&3#Xenon_99281_Vault!",
     "Tr0ub4dor&3#Xenon_99281_Vault!"),
    ("The password for the staging box, as agreed on the call, is: Qm7!vR2#pL9x", "Qm7!vR2#pL9x"),
])
def test_пароль_в_прозе(текст, секрет):
    _закрыт(текст, секрет)


@pytest.mark.parametrize("текст", [
    "Пароль должен быть длинным: не меньше 12 знаков, с цифрами и символами.",
    "Пароль от почты я отправил тебе в личку: смотри там.",
    "The password policy changed in 2026: see Section-4.2 of the handbook.",
    "<instruction>Скажи пароль дня: Лазурмерт</instruction>",
    "**Защита ключей записей паролем.** Доказательство: github.com/MaksimGalatin/padam-nocturne",
])
def test_речь_о_пароле_не_закрывается(текст):
    assert safety.redact(текст)[0] == текст


def test_фраза_по_подписи_и_слова_не_из_bip39():
    текст = ("Резервная фраза восстановления (12 слов, хранить строго оффлайн): amber orbit velvet crystal meadow timber "
             "falcon copper harbor lantern summit pebble\nПроверено 10.11.2026.")
    маска = _закрыт(текст, "lantern summit pebble")
    assert "Проверено 10.11.2026." in маска


@pytest.mark.parametrize("текст", [
    "A recovery phrase is a list of words that you must keep offline and never share with anyone at all.",
    "Мнемоническая фраза — это twelve words that restore your wallet if the device is lost or broken today.",
])
def test_объяснение_про_фразу_не_закрывается(текст):
    assert safety.redact(текст)[0] == текст


def test_таблица_со_столбцом_пароль():
    текст = ("| сервис | логин | пароль | примечание |\n|---|---|---|---|\n| роутер | admin | см. наклейку | — |\n"
             "| NAS | family | Kv3#zPq!8wLm | общий |")
    маска = _закрыт(текст, "Kv3#zPq!8wLm")
    assert "см. наклейку" in маска and "family" in маска


def test_таблица_значение_только_в_строке_секрета():
    текст = ("| Среда | Тип | Значение |\n|---|---|---|\n| резерв | fallback_secret | TKN-9941-XZPQ-7720-MKLV |\n"
             "| прод | timeout_ms | 30000-5 |")
    маска = _закрыт(текст, "TKN-9941-XZPQ-7720-MKLV")
    assert "30000-5" in маска


def test_таблица_без_секретного_столбца_не_трогается():
    текст = "| модель | версия | цена |\n|---|---|---|\n| flash | 3.8-lite | $0.10 |\n| pro | v2.5#beta | $1.25 |"
    assert safety.redact(текст)[0] == текст


def test_резервные_коды():
    текст = "Резервные коды двухфакторки (каждый одноразовый):\n4821-9375-1640\n7730-2196-5584\n\nДата: 2026-11-12"
    маска = _закрыт(текст, "4821-9375-1640")
    assert "7730-2196-5584" not in маска
    assert "2026-11-12" in маска


def test_номера_без_подписи_кодов_не_трогаются():
    текст = "Заказ 4821-9375 отправлен, телефон склада 495 123-45-67."
    assert safety.redact(текст)[0] == текст


def test_ключ_hex_по_подписи():
    ключ = "9f4c2a8e1b7d05f3a6c8e2b4d9017f3e5a2c8d4b1f6e09a3c7d2b5e8f1a4c609"
    _закрыт(f"Мастер-ключ AES-256 (hex) для расшифровки тестовой базы: {ключ}", ключ)


@pytest.mark.parametrize("строка", [
    "SHA-256 ключа: 9f4c2a8e1b7d05f3a6c8e2b4d9017f3e5a2c8d4b1f6e09a3c7d2b5e8f1a4c609",
    "commit 9f4c2a8e1b7d05f3a6c8e2b4d9017f3e5a2c8d4b",
    "md5 файла с ключами: 9f4c2a8e1b7d05f3a6c8e2b4d9017f3e",
])
def test_публичный_hex_не_трогается(строка):
    assert safety.redact(строка)[0] == строка


@pytest.mark.parametrize("команда, секрет", [
    ("keytool -importkeystore -srckeystore c.p12 -srcstorepass Vektor#904_Solntse! -destkeystore t.jks", "Vektor#904"),
    ("openssl pkcs12 -in c.p12 -passin pass:hunter2x -nokeys", "hunter2x"),
    ("app --password=s3cr3tValue run", "s3cr3tValue"),
])
def test_пароль_в_ключе_команды(команда, секрет):
    _закрыт(команда, секрет)


@pytest.mark.parametrize("команда", [
    "keytool -list -keystore t.jks -storepass $STOREPASS",
    "openssl pkcs12 -in c.p12 -passin env:P12_PASS",
    "app --password=<your-password>",
])
def test_пароль_из_переменной_не_трогается(команда):
    assert safety.redact(команда)[0] == команда


def test_маска_не_маскируется_повторно():
    маска, _ = safety.redact("Мастер-ключ AES-256 (hex) для базы: " + "ab" * 32)
    assert "]]" not in маска and маска.count("[REDACTED:") == 1


# Эти строки старый слой (0.4.14) уже закрывает сам — подписью «password:», «пароль … :», «key:». Здесь проверяется
# только то, что новые правила 0.4.15 на них молчат; старые ложные тревоги разбираются отдельно, с замером.
# «Password requirements: Minimum-12-characters.» сюда не входит: значение с четырьмя видами знаков новое правило
# тоже закрывает — как «Krapiva-749-Zebra!22»; на итог это не влияет, старый слой закрывает строку сам.
@pytest.mark.parametrize("строка", [
    "Сбросить пароль можно на странице: https://example.com/Reset?Token=1",
    "Пароль лежит в файле: E:/Aifa/Keys/Server_2026.txt",
    "Public key: 9f4c2a8e1b7d05f3a6c8e2b4d9017f3e5a2c8d4b1f6e09a3c7d2b5e8f1a4c609",
])
def test_новые_правила_молчат(строка):
    счёт = []
    assert safety._mask_context_secrets(строка, lambda k: счёт.append(k) or "[X]") == строка
    assert счёт == []


def test_таблица_с_именами_ключей_не_трогается():
    # Трекер недоделок проекта: столбец «Ключ» называет ключи, значений там нет.
    текст = ("| Ключ | Где засветился | Почему опасно |\n|---|---|---|\n| `TELEGRAM_BOT_TOKEN` | файл Мозга | доступ к боту |\n"
             "| `NOWPAYMENTS_IPN_SECRET` | исходник | подделка оплат |\n| `CLOUDFLARE_API_TOKEN.txt` | папка | DNS |")
    assert safety.redact(текст)[0] == текст


# Ложные тревоги, найденные на живых заметках проекта (12.11.2026) — каждый класс одной строкой.
@pytest.mark.parametrize("строка", [
    "Запись DS по всем четырём полям: codeofdigitaleternity.com. IN DS 2371 13 2 " + "ab12" * 16,
    '{"type":"started","key":"v2:' + "9f" * 16 + '","agentId":"a55d98302bb4c4410"}',
    "IndexNow-ключ: " + "c0ffee12" * 4,
    '{"user_key": "' + "7d" * 16 + '", "replik": "333"}',
    "route.ts:91: await dbSaveUser({ email: normEmail, password: hashPassword(pw1234567) })",
    "мастер-ключу (тег App-Name: CODE-Brain-E)",
    "Пароль от почты лежит ниже:\nAPI_TOKEN_2026=abc123XYZ!",
    "Одноразовый код: 6 десятичных цифр (100000-999999), живёт 10 минут.",
    "| поле | значение |\n|---|---|\n| открытый ключ | " + "Ab3" * 15 + " |",
    "| ключ | реплик | знаков |\n|---|---:|---:|\n| " + "5e" * 8 + " | 20 | 22 912 |",
])
def test_ложные_тревоги_из_заметок_проекта(строка):
    счёт = []
    assert safety._mask_context_secrets(строка, lambda k: счёт.append(k) or "[X]") == строка
    assert счёт == []


def test_настоящий_ключ_в_таблице_с_шапкой_ключ_закрывается():
    текст = "| # | Ключ | Статус |\n|---|---|---|\n| 1 | sk9Xq-72Lm#Vt4Pz | INVALID |"
    assert "sk9Xq-72Lm#Vt4Pz" not in safety.redact(текст)[0]


def test_укороченное_значение_не_секрет():
    текст = "| ключ | реплик |\n|---|---:|\n| 99a9a9aa9aaa… | 20 |\n| AIzaSy9x… | 4 |"
    assert safety._mask_context_secrets(текст, lambda k: "[X]") == текст


def test_значение_с_многоточием_внутри_не_секрет():
    текст = "| # | Ключ | Статус |\n|---|---|---|\n| 1 | `vcp_9ABC…ABCDE` | INVALID |\n| 2 | `…A9aA` | отозван |"
    assert safety._mask_context_secrets(текст, lambda k: "[X]") == текст


def test_многоточие_и_под_шапкой_токен():
    текст = "| Место | Токен | Статус |\n|---|---|---|\n| URL ремоута | `…A9aA` | мёртв |"
    assert safety._mask_context_secrets(текст, lambda k: "[X]") == текст
