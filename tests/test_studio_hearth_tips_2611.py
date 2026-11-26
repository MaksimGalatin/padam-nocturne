# -*- coding: utf-8 -*-
"""26.11.2026, слово Папы: Очаг — нормальный чат (кто и когда пишет), кнопка Очага без огонька,
к КАЖДОЙ кнопке и меню подсказка, Справка понятна любому. Замер до правки: 364 из 653 элементов без подсказки."""
from padam import studio
from padam.studio_tips_extra import CLASS_TIPS, CTRL_TIPS, GROUP_TIPS, KEY_TIPS

ЯЗЫКИ = ("ru", "en", "es", "zh")


def _страница() -> str:
    return studio.page()[0] if isinstance(studio.page(), tuple) else studio.page()


def test_кнопка_очага_без_огонька():
    html = _страница()
    i = html.index('id="quick-hearth-btn"')
    кнопка = html[i:html.index("</button>", i)]
    assert "🔥" not in кнопка and "ff_open_hearth" in кнопка


def test_очаг_рисуется_как_чат():
    html = _страница()
    for кусок in ("function _ffMessage(", "function _ffWho(", "function _ffTime(", "'ff-chat'", "role', 'log'"):
        assert кусок in html, кусок


def test_строки_на_четырёх_языках():
    S = getattr(studio, "STRINGS", None) or getattr(studio, "S")
    for ключ in ("ff_open_hearth", "ff_who_owner", "ff_more", "ff_less", "help_idx_title", "help_idx_ph"):
        for язык in ЯЗЫКИ:
            assert (S[язык].get(ключ) or "").strip(), (ключ, язык)


def test_подсказки_полные_и_на_месте():
    html = _страница()
    S = getattr(studio, "STRINGS", None) or getattr(studio, "S")
    for набор in (CTRL_TIPS, KEY_TIPS, CLASS_TIPS, GROUP_TIPS):
        for ключ, t in набор.items():
            for язык in ЯЗЫКИ:
                assert len((t.get(язык) or "").strip()) >= (4 if язык == "zh" else 8), (ключ, язык)
    for id_ in CTRL_TIPS:
        assert f'id="{id_}"' in html or f".id = '{id_}'" in html or f"'{id_}'" in html, id_   # часть меню строит скрипт
    for ключ in KEY_TIPS:
        assert ключ in S["ru"], ключ
    assert "function fillMissingTips(" in html and "function buildHelpIndex(" in html
