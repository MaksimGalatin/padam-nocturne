# -*- coding: utf-8 -*-
"""B5 дорожной карты Сестры (19.11.2026): справочник docs/site из кода.

Раздел «Ещё команды CLI» в docs/site/<язык>/reference.html — все команды `padam`, которых нет в основной таблице
справочника. Описания: ru/en — из help самих команд (PADAM_LANG), es/zh — padam/cli_help_i18n.py.
Раздел помечен <!-- cli-more:start --> … <!-- cli-more:end --> и при повторе заменяется, а не дублируется.
Встроен в docs/build_site.py (inject); отдельно: python scripts/gen_reference_cli.py.
Проверка расхождения — tests/test_docs_reference_drift_1911.py."""
from __future__ import annotations

import html
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "docs" / "site"
sys.path.insert(0, str(ROOT))
START, END = "<!-- cli-more:start -->", "<!-- cli-more:end -->"
TITLE = {"en": ("More CLI commands", "Command", "Purpose"), "ru": ("Ещё команды CLI", "Команда", "Назначение"),
         "es": ("Más comandos CLI", "Comando", "Propósito"), "zh": ("更多 CLI 命令", "命令", "用途")}
NL = "\n"


def cli_commands_and_help(lang: str) -> tuple[list[str], dict[str, str]]:
    env = dict(os.environ, PADAM_LANG=lang, COLUMNS="500", PYTHONIOENCODING="utf-8")
    out = subprocess.run([sys.executable, "-X", "utf8", "-m", "padam.cli", "--help"], capture_output=True, text=True,
                         encoding="utf-8", env=env, cwd=str(ROOT)).stdout
    m = re.search(r"\{([a-z0-9_,\-]+)\}", out)
    cmds = m.group(1).split(",") if m else []
    helps: dict[str, str] = {}
    cur = None
    for line in out.splitlines():
        mm = re.match(r"^    ([a-z0-9][a-z0-9_\-]*)\s{2,}(.+)$", line)
        if mm and mm.group(1) in cmds:
            cur = mm.group(1)
            helps[cur] = mm.group(2).strip()
        elif cur and re.match(r"^\s{10,}\S", line):
            helps[cur] += " " + line.strip()
        else:
            cur = None
    return cmds, helps


def _без_раздела(text: str) -> str:
    return re.sub(re.escape(START) + r".*?" + re.escape(END), "", text, flags=re.S)


def missing_in_page(text: str, cmds: list[str]) -> list[str]:
    base = _без_раздела(text)
    return [c for c in cmds if not re.search(r"<code>[^<]*\b" + re.escape(c) + r"\b", base)]


_КЭШ: dict = {}


def _данные():
    if not _КЭШ:
        from padam.cli_help_i18n import CLI_HELP_ES, CLI_HELP_ZH
        cmds, ru = cli_commands_and_help("ru")
        _, en = cli_commands_and_help("en")
        _КЭШ.update(cmds=cmds, helps={"ru": ru, "en": en, "es": CLI_HELP_ES, "zh": CLI_HELP_ZH})
    return _КЭШ["cmds"], _КЭШ["helps"]


def inject(lang: str, text: str) -> str:
    """Вставляет или обновляет раздел «Ещё команды CLI» в тексте справочника (чистая функция)."""
    cmds, helps = _данные()
    title, h_cmd, h_purpose = TITLE[lang]
    miss = missing_in_page(text, cmds)
    rows = "".join("<tr><td><code>" + html.escape(c) + "</code></td><td>" + html.escape(helps[lang].get(c) or "")
                   + "</td></tr>" for c in miss)
    block = (START + NL + "<h2>" + title + " (" + str(len(miss)) + ")</h2>" + NL
             + '<div class="table-wrap"><table><thead><tr><th>' + h_cmd + "</th><th>" + h_purpose
             + "</th></tr></thead><tbody>" + rows + "</tbody></table></div>" + NL + END)
    if START in text:
        return re.sub(re.escape(START) + r".*?" + re.escape(END), lambda _m: block, text, flags=re.S)
    i = text.index("python -m padam &lt;") if "python -m padam &lt;" in text else -1
    j = text.index("</table></div>", i) + len("</table></div>") if i >= 0 else text.rindex("</main>")
    return text[:j] + NL + block + text[j:]


RSTART, REND = "<!-- rest-more:start -->", "<!-- rest-more:end -->"
RTITLE = {"en": ("More REST endpoints (owner only)", "Method", "Path", "Purpose"),
          "ru": ("Ещё адреса REST (только владелец)", "Метод", "Путь", "Назначение"),
          "es": ("Más endpoints REST (solo el dueño)", "Método", "Ruta", "Propósito"),
          "zh": ("更多 REST 接口（仅所有者）", "方法", "路径", "用途")}


def rest_missing(text: str) -> list[str]:
    from padam import api
    base = re.sub(re.escape(RSTART) + r".*?" + re.escape(REND), "", text, flags=re.S)
    return [r for r in sorted(api.OWNER_GET) if "<code>" + r + "</code>" not in base]


def inject_rest(lang: str, text: str) -> str:
    """Блок «Ещё адреса REST»: каждый GET-адрес владельца из кода, которого нет в основной таблице."""
    from padam.rest_help_i18n import REST_HELP
    title, h_m, h_p, h_purpose = RTITLE[lang]
    miss = rest_missing(text)
    rows = "".join("<tr><td><code>GET</code></td><td><code>" + html.escape(r) + "</code></td><td>"
                   + html.escape((REST_HELP.get(r) or {}).get(lang, "")) + "</td></tr>" for r in miss)
    block = (RSTART + NL + "<h2>" + title + " (" + str(len(miss)) + ")</h2>" + NL
             + '<div class="table-wrap"><table><thead><tr><th>' + h_m + "</th><th>" + h_p + "</th><th>" + h_purpose
             + "</th></tr></thead><tbody>" + rows + "</tbody></table></div>" + NL + REND)
    if RSTART in text:
        return re.sub(re.escape(RSTART) + r".*?" + re.escape(REND), lambda _m: block, text, flags=re.S)
    i = text.index("/health</code>") if "/health</code>" in text else -1
    j = text.index("</table></div>", i) + len("</table></div>") if i >= 0 else text.rindex("</main>")
    return text[:j] + NL + block + text[j:]


def build() -> dict[str, int]:
    out = {}
    for lang in TITLE:
        page = SITE / lang / "reference.html"
        text = inject(lang, page.read_text(encoding="utf-8"))
        page.write_text(text, encoding="utf-8", newline=NL)
        out[lang] = text.count("<tr><td><code>", text.index(START))
    return out


if __name__ == "__main__":
    print(build())
