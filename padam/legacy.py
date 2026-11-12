"""Завещание памяти: разделение секрета по схеме Шамира.

Парольную фразу, которой защищены ключи записей (`padam protect-keys`), можно разделить на n
долей так, что любые k из них восстанавливают её, а k−1 не дают о ней ничего. Доли раздаются
доверенным людям: память откроется, только когда соберутся k из них.

Схема Шамира над полем GF(256) (многочлен AES, 0x11B), побайтно. Своя реализация на
стандартной библиотеке, без зависимостей; случайность — из `secrets`. Доля — строка
`padam-share-1-<k>-<номер>-<hex>`: номер доли и порог видны, секрет — нет.
"""

from __future__ import annotations

import hashlib
import secrets
from .i18n import t

ПРЕФИКС = "padam-share-1"


def _умножить(a: int, b: int) -> int:
    итог = 0
    while b:
        if b & 1:
            итог ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11B
        b >>= 1
    return итог


def _обратный(a: int) -> int:
    if a == 0:
        raise ZeroDivisionError(t("в GF(256) у нуля нет обратного", "zero has no inverse in GF(256)"))
    # a^254 = a^-1 в GF(256)
    итог, степень, основание = 1, 254, a
    while степень:
        if степень & 1:
            итог = _умножить(итог, основание)
        основание = _умножить(основание, основание)
        степень >>= 1
    return итог


def split(secret: bytes, shares: int, threshold: int) -> list[str]:
    """Делит секрет на `shares` долей, любые `threshold` из которых его восстанавливают."""
    if not 2 <= threshold <= shares <= 255:
        raise ValueError(t("нужно 2 ≤ порог ≤ число долей ≤ 255", "need 2 ≤ threshold ≤ number of shares ≤ 255"))
    if not secret:
        raise ValueError(t("пустой секрет делить нечего", "nothing to split: the secret is empty"))
    # Четыре байта контрольной суммы: подменённая или чужая доля даёт ошибку, а не тихо неверную фразу.
    secret = secret + hashlib.sha256(secret).digest()[:4]
    доли = [bytearray() for _ in range(shares)]
    for байт in secret:
        коэфф = [байт] + [secrets.randbelow(256) for _ in range(threshold - 1)]
        for номер in range(1, shares + 1):
            y, x_степень = 0, 1
            for c in коэфф:
                y ^= _умножить(c, x_степень)
                x_степень = _умножить(x_степень, номер)
            доли[номер - 1].append(y)
    return [f"{ПРЕФИКС}-{threshold}-{номер}-{bytes(д).hex()}" for номер, д in enumerate(доли, 1)]


def _разобрать(доля: str) -> tuple[int, int, bytes]:
    части = доля.strip().split("-")
    if len(части) != 6 or "-".join(части[:3]) != ПРЕФИКС:
        raise ValueError(t("это не доля padam: ожидается padam-share-1-<порог>-<номер>-<hex>",
                            "not a padam share: expected padam-share-1-<threshold>-<index>-<hex>"))
    return int(части[3]), int(части[4]), bytes.fromhex(части[5])


def combine(shares: list[str]) -> bytes:
    """Собирает секрет из долей. Долей меньше порога — ошибка, а не «что-то похожее»."""
    разобранные = [_разобрать(д) for д in shares]
    пороги = {п for п, _, _ in разобранные}
    if len(пороги) != 1:
        raise ValueError(t("доли от разных разделений", "the shares come from different splits"))
    порог = пороги.pop()
    точки: dict[int, bytes] = {}
    for _, номер, данные in разобранные:
        точки[номер] = данные
    if len(точки) < порог:
        raise ValueError(t(f"нужно не меньше {порог} разных долей, есть {len(точки)}",
                            f"need at least {порог} distinct shares, got {len(точки)}"))
    выбранные = list(точки.items())[:порог]
    длины = {len(д) for _, д in выбранные}
    if len(длины) != 1:
        raise ValueError(t("доли разной длины", "the shares have different lengths"))
    длина = длины.pop()
    секрет = bytearray()
    for i in range(длина):
        значение = 0
        for j, (xj, дj) in enumerate(выбранные):
            # Интерполяция Лагранжа в точке 0: Π x_m / (x_m − x_j), в GF(256) вычитание — это XOR.
            числитель, знаменатель = 1, 1
            for m, (xm, _) in enumerate(выбранные):
                if m != j:
                    числитель = _умножить(числитель, xm)
                    знаменатель = _умножить(знаменатель, xm ^ xj)
            значение ^= _умножить(дj[i], _умножить(числитель, _обратный(знаменатель)))
        секрет.append(значение)
    тело, сумма = bytes(секрет[:-4]), bytes(секрет[-4:])
    if hashlib.sha256(тело).digest()[:4] != сумма:
        raise ValueError(t("доли не сходятся: одна из них неверна или от другого разделения",
                            "the shares do not agree: one is wrong or comes from another split"))
    return тело
