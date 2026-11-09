"""Общий детектор секретов (встречный аудит 09.11.2026): устройство строки вместо приставки.

Три слоя: значение после имени поля, длинная случайная строка, номер карты и код к ней. И главное —
что он не трогает: ссылки, адреса и подписи блокчейна, хеши, UUID, идентификаторы Vercel, номера постов,
дел и заказов. Ложная маска молча портит память, поэтому ложных случаев здесь больше, чем секретов.
Значения склеены из частей, чтобы сканеры секретов не принимали тесты за утечку.
"""

import pytest

from padam import safety


@pytest.mark.parametrize("секрет", [
    # 1. значение после имени поля
    '{"refresh_token": "1//0gLm8Nr2Qt6' + 'Vx9Bz3Cd7Fg1Hj5Kl0"}',
    "AccountKey=Lm8Nr2Qt6Vx9Bz3Cd7" + "Fg1Hj5Kl0Mn4Pq==",
    "SharedAccessKey=Qt6Vx9Bz3Cd7" + "Fg1Hj5Kl0Mn4Pq8Rs2",
    "DB_PASSWORD=" + "Hn7#kQ2!vL9z",
    "client_secret: Gh5Jk8Lm2" + "Np6Qr9St3Vw",
    "x-api-key: Tq7Wm3Kp9L" + "z2Vb6Nc4Rd8",
    "sentry_dsn=https://ab12cd34" + "ef56@o12345.ingest.sentry.io/678",
    # 2. длинная случайная строка без известной приставки
    "whsec_Mq7Lr2Vt9Xc4" + "Bn8Kd1Fg6Hj3",
    "SG.Pk4Lm8Nr2Qt6.Vx9Bz3Cd7" + "Fg1Hj5Kl0Mn4Pq8Rs2Tv6Wx",
    "SKa7f3c9e1b5d2a8f4c6" + "e0b9d7a3f1c5e8b2",
    "MTEyMzQ1Njc4OTAxMjM0NTY3OA.GhJkLm." + "Qr5St7Uv9Wx1Yz3Ab5Cd7Ef9Gh1Ij",
    "5KQwrPbwdL6PhXujxW37FSSQZ1Jiws" + "ST4cqQzDeyXtP79zkvFD3",
    "3Bxs4Ht9RzUq7Lm2Kd8Fn5Vc1Wp6Yt4Gh9Jk2Ln5Pq8" + "Rs3Tv6Wx9Za2Cb5De8Fg1Hj4Kl7Mn0Pq3Rs6Tv9Wx",
    "Authorization: Basic dXNlcjpQYXNzdzBy" + "ZDEyMyFAIw==",
    # 3. платёжные данные
    "карта 5500 0000 " + "0000 0004",
    "card number 4111" + "111111111111",
    "CVC 1" + "23",
    "pin-код: 84" + "02",
])
def test_generic_layers_mask_secrets(секрет):
    чистый, сколько = safety.redact(f"заметка: {секрет} конец")
    assert sum(сколько.values()) >= 1, чистый
    assert "[REDACTED:" in чистый


@pytest.mark.parametrize("обычное", [
    "commit e30130ca02a73b3723278b88ef4d3facaa9b444e merged",
    "id 3fa85f64-5717-4562-b3fc-2c963f66afa6",
    "https://github.com/MaksimGalatin/padam-nocturne/blob/main/CHANGELOG.md",
    "файл ПЕРЕДАЧА_КОНТЕКСТА_2026-11-08_ВСЕ_ХВОСТЫ.md",
    "report_final_2026_11_09_v2.docx",
    "PostgreSQLConnectionPoolManager is slow",
    "sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "телефон +593 98 765 4321",
    "заказ ORD-2026-11-09-000123",
    "IBAN DE89 3704 0044 0532 0130 00",
    "padam-nocturne-0.2.2-py3-none-any.whl",
    "адрес кошелька GcuDtN5emjHvm4bPS2uO3xWQ5qumMrdsdqt6WpTB1p8",
    "https://viewblock.io/arweave/tx/E-mB1gQm8Lk2Vt9Xc4Bn8Kd1Fg6Hj3Pq7Rs2Tv6WxtWE",
    "ISBN 978-3-16-148410-0",
    # найдено замером 09.11.2026 на трекере и файле навыков
    "Обращение уже создано (кейс 178912345678901)",
    "пост X 1987654321098765432 и 1987654321098765433 закреплены",
    "проект aifa.digital (prj_AbCdEf0123456789GhIjKlMnOpQrSt)",
    "откат на dpl_7WqU8JVfRSVCMXD6bUq9SyFGsL1H",
    "vercel link --scope team_AbCdEf0123456789GhIjKl",
    "трек open.spotify.com/track/7HDQaB1cD2eF3gH4iJ5kL6",
    "канал UChVx3Kq9Lm2Np5Rs8Tv1Wy4",
])
def test_generic_layers_leave_ordinary_text_alone(обычное):
    чистый, сколько = safety.redact(обычное)
    assert сколько == {}, (обычное, чистый)


def test_short_prefix_and_hex_is_a_key_but_public_prefixes_stay_open():
    for ключ in ("key-" + "3f9a1c7e5b2d8f4a6c0e9b7d3a1f5c8e", "sk_" + "3F9A1C7E5B2D8F4A6C0E9B7D3A1F5C8E2B4D",
                 "mg_" + "0123abcd4567ef890123abcd4567ef89"):
        assert safety.redact(f"ключ {ключ} конец")[1] == {"prefixed_hex_key": 1}, ключ
    for открытое in ("sha-3f9a1c7e5b2d8f4a6c0e9b7d3a1f5c8e", "commit 3f9a1c7e5b2d8f4a6c0e9b7d3a1f5c8e2b4d6f8a",
                     "https://pub-3f9a1c7e5b2d8f4a6c0e9b7d3a1f5c8e.r2.dev/a.png", "tx_3f9a1c7e5b2d8f4a6c0e9b7d3a1f5c8e",
                     "id-3f9a1c7e5b2d8f4a6c0e9b7d3a1f5c8e"):
        assert safety.redact(открытое)[1] == {}, открытое


def test_joined_prefix_and_hex_is_a_key_but_hashes_and_addresses_stay_open():
    # Аудит 09.11.2026: приставка слитно с hex, без разделителя. На 12 000 случайных строках проходили 420.
    import random
    rnd = random.Random(1109)
    for _ in range(300):
        приставка = "".join(rnd.choice("ABCDEFGHJKLMNQRSUVWXYZ") for _ in range(2))
        ключ = приставка + "".join(rnd.choice("0123456789abcdef") for _ in range(32))
        assert ключ not in safety.redact(f"ключ {ключ} конец")[0], ключ
    for ключ in ("SK" + "3f9a1c7e5b2d8f4a6c0e9b7d3a1f5c8e", "key" + "3f9a1c7e5b2d8f4a6c0e9b7d3a1f5c8e",
                 "HH1bd678f4f2d192" + "f92b72fcc73127c538"):          # похож на base58, но это ключ
        assert safety.redact(ключ)[1] == {"prefixed_hex_key": 1}, ключ
    for открытое in ("e30130ca02a73b3723278b88ef4d3facaa9b444e", "deadbeef0123456789abcdef0123456789abcdef",
                     "ABCDEF0123456789ABCDEF0123456789ABCD", "commit fa3b9c1e5d7f2a4b6c8e0d1f3a5b7c9e merged",
                     "адрес кошелька GcuDtN5emjHvm4bPS2uO3xWQ5qumMrdsdqt6WpTB1p8"):
        assert safety.redact(открытое)[1] == {}, открытое


def test_card_needs_grouping_or_a_word_about_cards():
    # Ряд цифр, проходящий Луна, без группировки и без слова «карта» — не карта: это номер поста, дела, заказа.
    assert safety.redact("номер 4111" + "111111111111 в отчёте")[1] == {}
    assert safety.redact("Visa 4111" + "111111111111")[1] == {"card_number": 1}
    assert safety.redact("4111 1111 " + "1111 1111")[1] == {"card_number": 1}
    assert safety.redact("4111 1111 " + "1111 1112")[1] == {}, "не проходит Луна"


@pytest.mark.parametrize("речь", [
    # найдено замером 09.11.2026: все 13 срабатываний «присваивания» на заметках были такими
    "секреты, строки подключения к базам, пары «пароль = значение»",
    "Шаблон «пароль: длинный» в JS маскировался бы как секрет",
    "строки вида «пароль: значение».",
    "ПАРОЛЬ = re.compile(r\"пароль\")",
    "суточный лимит проекта gemini-api-key: flash-lite",
    "консоль спросила у меня пароль contact@codeofdigitaleternity.com",
])
def test_password_words_in_speech_stay_open(речь):
    assert safety.redact(речь)[1] == {}, safety.redact(речь)


@pytest.mark.parametrize("фраза, пароль", [
    ("пароль: correct-horse-" + "battery-staple", "correct-horse-battery-staple"),
    ("password = correct-horse-" + "battery", "correct-horse-battery"),
    ("мой пароль correct-horse-" + "battery-staple", "correct-horse-battery-staple"),
    ("passphrase: tiger_river_" + "lamp_cloud", "tiger_river_lamp_cloud"),
    ('DB_PASSWORD="ocean.maple.' + 'thunder"', "ocean.maple.thunder"),
    ("пароль: зелёный-кот-" + "летит-домой", "зелёный-кот-летит-домой"),
])
def test_passphrase_of_words_is_masked(фраза, пароль):
    assert пароль not in safety.redact(фраза)[0], safety.redact(фраза)


@pytest.mark.parametrize("речь", [
    "пароль: длинный",
    "мой пароль correct-horse-battery",            # без разделителя нужно четыре слова
    "пароль — correct-horse-battery",              # тире — речь, как и пробел
    "password: two-words",
    "api_key: flash-lite-preview",                 # у ключей фраза из слов — имя модели
    "token = state-of-the-art",
])
def test_word_chains_in_speech_stay_open(речь):
    assert safety.redact(речь)[1] == {}, safety.redact(речь)


def test_password_like_still_catches_real_values():
    for значение in ("Hunter2024!x", "«Qwerty12345!»", "P@ssw0rd", "s3cr3t-value", "abc!def#ghi"):
        assert safety.password_like(значение), значение
    for слово in ("значение»", "длинный", "contact@", "user@example.com", "flash-lite"):
        assert not safety.password_like(слово), слово


def test_public_jwk_parts_stay_open():
    закрытая = "AbC123dEf456GhI789jKl012MnO345pQr678StU901vWx234"
    чистый, сколько = safety.redact('{"kty":"RSA","n":"Nn9Kq2Wm7Lz4Vb8Xc3Rd6Tf1Gh5Jk0Pq","e":"AQAB","d":"' + закрытая + '"}')
    assert закрытая not in чистый
    assert "Nn9Kq2Wm7Lz4Vb8Xc3Rd6Tf1Gh5Jk0Pq" in чистый, "модуль ключа открыт"
