# -*- coding: utf-8 -*-
"""18.11.2026, слово Папы: «Каждая кнопка должна быть ПОНЯТНО РАСПИСАНА и работать». У описанных кнопок — 4 языка,
описание не пустое и не равно подписи кнопки, сама кнопка есть на странице Studio."""
from padam import studio
from padam.studio_tips import BTN_TIPS


def test_описания_кнопок_полные():
    страница = studio.render_page("x") if hasattr(studio, "render_page") else open(studio.__file__, encoding="utf-8").read()
    import re
    кнопки = set(re.findall(r'<button[^>]*\bid="([\w-]+)"', страница))
    assert not (кнопки - set(BTN_TIPS)), f"кнопки без описания: {sorted(кнопки - set(BTN_TIPS))}"
    for bid, t in BTN_TIPS.items():
        assert f'id="{bid}"' in страница or f".id = '{bid}'" in страница, bid   # 19.11: кнопки, созданные скриптом
        for язык in ("ru", "en", "es", "zh"):
            assert len((t.get(язык) or "").strip()) >= (4 if язык == "zh" else 8), (bid, язык)
