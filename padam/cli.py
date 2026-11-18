"""Командная строка PADAM.

    padam remember "текст"        запомнить
    padam recall "запрос"         вспомнить
    padam log "текст"             записать в буфер (без консолидации)
    padam sleep                   запустить цикл консолидации
    padam stats                   состояние памяти
    padam timeline <id>           история версий записи
    padam forget <id>             отозвать запись
    padam review                  что агент хотел записать и ждёт решения владельца
    padam approve <id>            принять такую запись
    padam reject <id>             отклонить такую запись
    padam restore <id>            вернуть запись из архива
    padam reindex                 пересчитать векторы после смены модели
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import config
from .i18n import t
from .memory import Memory
from .nocturne import Nocturne

GREEN, RED, DIM, RESET = "\033[32m", "\033[31m", "\033[2m", "\033[0m"

DOC_EN = """PADAM command line.

    padam remember "text"         store a memory
    padam recall "query"          recall
    padam log "text"              add to the episode buffer (no consolidation)
    padam sleep                   run the NOCTURNE consolidation cycle
    padam stats                   memory state
    padam timeline <id>           version history of a record
    padam forget <id>             revoke a record
    padam review                  what an agent tried to store and now waits for the owner
    padam approve <id>            accept such a record
    padam reject <id>             reject such a record
    padam restore <id>            bring a record back from the archive
    padam reindex                 recompute vectors after changing the embedding model

Language: English or Russian by system language; force with PADAM_LANG=en|ru.
"""

# Заметки и проверки цикла сна приходят из ядра по-русски — для английского вывода переводим здесь.
_NOTES_EN = {"буфер пуст": "episode buffer is empty", "нечего выбрать": "nothing to sample",
             "нечего консолидировать": "nothing to consolidate"}
_CHECKS_EN = {"Доля острых эпизодов": "Share of sharp episodes",
              "Разнообразие по типам": "Diversity across kinds",
              "Переигранных > 5 раз": "Replayed more than 5 times"}


def cmd_remember(m: Memory, a) -> int:
    outcome, mid = m.remember(a.text, kind=a.kind, importance=a.importance,
                              scope=a.scope, agent_id=getattr(a, "agent", None))
    labels = {
        "created": t("запомнено", "remembered"),
        "duplicate": t("уже известно, уверенность повышена", "already known; confidence raised"),
        "merged": t("уточнено, прежняя версия сохранена в истории",
                    "refined; the previous version is kept in history"),
        "superseded": t("заменено, прежняя версия сохранена в истории",
                        "replaced; the previous version is kept in history"),
        "coexists": t("добавлено рядом с прежним", "stored alongside a similar record"),
        "quarantined": t("ждёт проверки: padam review", "waiting for review: padam review"),
    }
    print(f"{GREEN}{labels.get(outcome, outcome)}{RESET}")
    print(f"{DIM}id: {mid}{RESET}")
    return 0


def cmd_recall(m: Memory, a) -> int:
    found = m.recall(a.query, scope=a.scope, kind=a.kind, limit=a.limit,
                     agent_id=getattr(a, "agent", None))
    if not found:
        print(t("Ничего не найдено.", "Nothing found."))
        return 0
    for r in found:
        print(f"{GREEN}{r.score:.3f}{RESET}  [{r.kind}]  {r.content}")
        if a.explain:
            print(f"        {DIM}{r.explain()}{RESET}")
            print(f"        {DIM}id: {r.id}{RESET}")
    return 0


def cmd_log(m: Memory, a) -> int:
    eid = m.log(a.text, priority=a.priority, scope=a.scope)
    print(f"{DIM}{t('в буфер', 'buffered')}: {eid}{RESET}")
    return 0


def cmd_sleep(m: Memory, a) -> int:
    report = Nocturne(m, batch_size=a.batch, dry_run=a.dry_run).run()
    if not report.get("episodes_sampled"):
        note = report.get("note", "нечего консолидировать")
        print(t(note, _NOTES_EN.get(note, note)))
        return 0

    print(t("\nNOCTURNE — цикл консолидации", "\nNOCTURNE — consolidation cycle"))
    print("=" * 52)
    print(t(f"Обработано эпизодов:  {report['episodes_sampled']}",
            f"Episodes processed:   {report['episodes_sampled']}"))
    print(t(f"Коррекция смещения:   beta = {report['beta']}",
            f"Bias correction:      beta = {report['beta']}"))
    print()
    ok_all = True
    for label, ok, detail in report["checks"]:
        mark = f"{GREEN}OK {RESET}" if ok else f"{RED}!!!{RESET}"
        ok_all &= ok
        label = t(label, _CHECKS_EN.get(label, label))
        detail = t(detail, detail.replace("цель", "target"))
        print(f"[{mark}] {label:26s} {detail}")
    print(t(f"\nИсходы:   {report['outcomes']}", f"\nOutcomes: {report['outcomes']}"))
    print(t(f"По типам: {report['kinds']}", f"By kind:  {report['kinds']}"))

    if not ok_all:
        print(f"\n{RED}{t('Не все проверки пройдены.', 'Not all checks passed.')}{RESET}")
        print(t("Если пробит потолок острых — снизить K_MAX в config.py.",
                "If the sharp-episode ceiling is broken, lower K_MAX in config.py."))
        print(t("Если низкое разнообразие — проверить классификатор типов:",
                "If diversity is low, check the kind classifier:"))
        print(t("скорее всего всё падает в 'fact'.", "most likely everything falls into 'fact'."))
    return 0


def cmd_stats(m: Memory, a) -> int:
    s = m.stats()
    print(t(f"База:        {s['db']}", f"Database:    {s['db']}"))
    # 0.4.2: пояснение только для встроенного метода — при model2vec прежняя строка ложно писала «встроенный».
    # Python 3.10 не допускает обратную косую внутри выражения f-строки — текст пояснения собран отдельно.
    пояснение = t('(модели нет: работает встроенный метод; по смыслу — pip install "padam-nocturne[embed]")',
                  '(no model: built-in method in use; for meaning — pip install "padam-nocturne[embed]")')
    print(t(f"Эмбеддинги:  {s['backend']}", f"Embeddings:  {s['backend']}")
          + ("" if s["backend"] != "builtin" else f"  {DIM}{пояснение}{RESET}"))
    к = s.get("record_keys") or {}
    if "passphrase_protected" in к:
        print(t(f"Ключи записей:  {'защищены паролем' if к['passphrase_protected'] else 'НЕ защищены паролем (padam protect-keys)'}"
                f", открытых: {к['plain']}",
                f"Record keys:  {'protected by a passphrase' if к['passphrase_protected'] else 'NOT protected by a passphrase (padam protect-keys)'}"
                f", in clear: {к['plain']}"))
    print()
    print(t(f"Активных записей:     {s['active']}", f"Active records:       {s['active']}"))
    print(t(f"Замещённых:           {s['superseded']}", f"Superseded:           {s['superseded']}"))
    print(t(f"Отозванных:           {s['revoked']}", f"Revoked:              {s['revoked']}"))
    print(t(f"Эпизодов в буфере:    {s['episodes_pending']}", f"Episodes in buffer:   {s['episodes_pending']}"))
    if s["quarantined"]:
        print(t(f"Ждут решения:         {s['quarantined']}  (padam review)",
                f"Waiting for review:   {s['quarantined']}  (padam review)"))
    if s["stale_vectors"]:
        print(t(f"Векторы другой модели: {s['stale_vectors']}  (padam reindex)",
                f"Stale vectors:         {s['stale_vectors']}  (padam reindex)"))
    if s["consolidation_due"]:
        print(t("Пора запустить цикл: padam sleep", "Time for a consolidation cycle: padam sleep"))
    if s["by_kind"]:
        print(t("\nПо типам:", "\nBy kind:"))
        for k, n in sorted(s["by_kind"].items(), key=lambda x: -x[1]):
            hl = config.HALF_LIFE_DAYS.get(k)
            note = (t("не затухает", "never fades") if hl is None
                    else t(f"полураспад {hl} дн.", f"half-life {hl} days"))
            print(f"  {k:12s} {n:4d}   {DIM}{note}{RESET}")
    return 0


def _not_found() -> None:
    print(t("Запись не найдена.", "Record not found."))


def cmd_timeline(m: Memory, a) -> int:
    chain = m.timeline(a.id)
    if not chain:
        _not_found()
        return 1
    for i, row in enumerate(chain):
        arrow = "" if i == 0 else "  ↓\n"
        state = "" if row["status"] == "active" else f" [{row['status']}]"
        print(f"{arrow}{row['created_at'][:19]}{state}")
        print(f"  {row['content'] or t('(содержание затёрто)', '(content wiped by revoke)')}")
    return 0


def cmd_export(m: Memory, a) -> int:
    import json
    payload = m.export(include_superseded=not a.active_only, scope=a.scope)
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(text)
        c = payload["counts"]
        print(t(f"{GREEN}Выгружено{RESET} в {a.out}: записей {c['memory']}, сессий {c['sessions']}",
                f"{GREEN}Exported{RESET} to {a.out}: {c['memory']} records, {c['sessions']} sessions"))
    else:
        print(text)
    return 0


def cmd_import(m: Memory, a) -> int:
    import json
    fmt = getattr(a, "format", "padam") or "padam"
    if fmt != "padam":
        res = m.import_external(a.file, fmt=fmt, scope=getattr(a, "scope", "global") or "global")
        print(t(
            f"{GREEN}Импортировано из внешнего источника ({res['format']}):{RESET} {res['imported']} "
            f"(исходы: {res['outcomes']}, ждут проверки в padam review)",
            f"{GREEN}Imported from external source ({res['format']}):{RESET} {res['imported']} "
            f"(outcomes: {res['outcomes']}, waiting for review in padam review)",
        ))
        return 0
    with open(a.file, encoding="utf-8") as f:
        payload = json.load(f)
    n = m.import_(payload, overwrite=a.overwrite)
    print(f"{GREEN}{t('Загружено записей', 'Records imported')}: {n}{RESET}")
    return 0


def cmd_export_md(m: Memory, a) -> int:
    """Б20: выгрузить только действующие записи в папку Markdown / Obsidian."""
    res = m.export_markdown(a.dir, scope=a.scope)
    print(t(
        f"{GREEN}Выгружено в Markdown / Obsidian:{RESET} {res['dir']} (действующих записей: {res['exported']})",
        f"{GREEN}Exported to Markdown / Obsidian:{RESET} {res['dir']} (active records: {res['exported']})",
    ))
    return 0


def cmd_import_ext(m: Memory, a) -> int:
    """Б8: импорт внешней памяти (ChatGPT, Claude, Markdown/Obsidian, mem0) с origin=external."""
    res = m.import_external(a.source, fmt=a.format, scope=a.scope)
    print(t(
        f"{GREEN}Импортировано ({res['format']}, origin=external):{RESET} {res['imported']} "
        f"(исходы: {res['outcomes']})",
        f"{GREEN}Imported ({res['format']}, origin=external):{RESET} {res['imported']} "
        f"(outcomes: {res['outcomes']})",
    ))
    return 0


def cmd_confirm(m: Memory, a) -> int:
    if m.confirm(a.id):
        print(t(f"{GREEN}Подтверждено.{RESET} Свежесть обновлена, уверенность выше.",
                f"{GREEN}Confirmed.{RESET} Freshness renewed, confidence raised."))
        return 0
    _not_found()
    return 1


def cmd_refute(m: Memory, a) -> int:
    if not m.refute(a.id, drop=a.drop):
        _not_found()
        return 1
    print(t(f"{GREEN}Уверенность снижена.{RESET} Свежесть не обновлялась.",
            f"{GREEN}Confidence lowered.{RESET} Freshness not renewed."))
    return 0


def cmd_review(m: Memory, a) -> int:
    записи = m.quarantined()
    if not записи:
        print(t("На проверке ничего нет.", "Nothing is waiting for review."))
        return 0
    for з in записи:
        print(f"{GREEN}{з['id']}{RESET}  [{з['kind']}]  {з['content']}")
        print(f"  {DIM}{t('откуда', 'origin')}: {з['origin']};  {t('причина', 'reason')}: {з['quarantine_reason']};"
              f"  {з['created_at'][:19]}{RESET}")
    print(t("\npadam approve <id>  принять;  padam reject <id>  отклонить",
            "\npadam approve <id>  accept;  padam reject <id>  reject"))
    return 0


def cmd_viewer(m: Memory, a) -> int:
    """Память в браузере: временная шкала, «забыть», решения по записям агента, память на дату."""
    from . import api
    srv, ссылка = api.make_viewer_server(m, port=a.port)
    # flush: при запуске из другой программы вывод идёт в трубу и без него ссылка не видна до остановки.
    print(t("Память в браузере (только этот компьютер). Ссылка действует, пока команда работает:",
            "Memory in the browser (this computer only). The link works while this command runs:"), flush=True)
    print(f"  {ссылка}", flush=True)
    print(t("Ссылку никому не пересылайте: в ней ключ к вашей памяти. Остановить — Ctrl+C.",
            "Do not share the link: it carries the key to your memory. Stop with Ctrl+C."), flush=True)
    if not a.no_open:
        import webbrowser
        webbrowser.open(ссылка)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


def cmd_studio(m: Memory, a) -> int:
    """PADAM Studio: полное приложение управления памятью в браузере (10 экранов, 4 языка, 2 темы)."""
    from . import api
    srv, ссылка = api.make_studio_server(m, port=a.port)
    print(t("PADAM Studio в браузере (только этот компьютер). Ссылка действует, пока команда работает:",
            "PADAM Studio in the browser (this computer only). The link works while this command runs:"), flush=True)
    print(f"  {ссылка}", flush=True)
    print(t("Ссылку никому не пересылайте: в ней одноразовый ключ к вашей памяти. Остановить — Ctrl+C.",
            "Do not share the link: it carries a one-time key to your memory. Stop with Ctrl+C."), flush=True)
    if not a.no_open:
        import webbrowser
        webbrowser.open(ссылка)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        srv.server_close()
    return 0


def cmd_demo(_m: Memory | None, a) -> int:
    """Б17: создать отдельную демонстрационную базу памяти (не трогая основную) и по желанию открыть Studio."""
    from . import demo
    target = a.out or a.db or str(demo.default_demo_path())
    demo_mem, summary = demo.build_demo_memory(
        db_path=target,
        user_id=a.user if a.user != "default" else "demo_architect",
    )
    try:
        st = summary["stats"]
        print(t(f"{GREEN}Демонстрационная память создана:{RESET} {summary['db']}  (пользователь: {summary['user']})",
                f"{GREEN}Demo memory created:{RESET} {summary['db']}  (user: {summary['user']})"))
        print(t(f"  Действующих: {st['active']} · На проверке: {st['quarantined']} · "
                f"Прежних версий: {st['superseded']} · Забытых с квитанцией: {st['revoked']}",
                f"  Active: {st['active']} · Waiting review: {st['quarantined']} · "
                f"Superseded: {st['superseded']} · Forgotten with receipt: {st['revoked']}"))
        print(t(f"  Открыть в Studio: padam --db \"{summary['db']}\" --user {summary['user']} studio",
                f"  Open in Studio: padam --db \"{summary['db']}\" --user {summary['user']} studio"))
        if a.studio:
            return cmd_studio(demo_mem, a)
        return 0
    finally:
        demo_mem.close()


def cmd_approve(m: Memory, a) -> int:
    if m.approve(a.id):
        print(t(f"{GREEN}Принято.{RESET} Запись действует.", f"{GREEN}Approved.{RESET} The record is active."))
        return 0
    _not_found()
    return 1


def cmd_reject(m: Memory, a) -> int:
    if m.reject(a.id):
        print(t(f"{GREEN}Отклонено.{RESET} В поиск не попадёт, в истории осталось.",
                f"{GREEN}Rejected.{RESET} It stays out of search and remains in history."))
        return 0
    _not_found()
    return 1


def cmd_restore(m: Memory, a) -> int:
    if m.restore(a.id):
        print(t(f"{GREEN}Возвращено из архива.{RESET}", f"{GREEN}Restored from the archive.{RESET}"))
        return 0
    _not_found()
    return 1


def cmd_reindex(m: Memory, a) -> int:
    print(json.dumps(m.reindex(limit=a.limit), ensure_ascii=False))
    return 0


def cmd_profile(m: Memory, a) -> int:
    """Б9: сводка профиля человека (только подписанные владельцем identity и preference)."""
    prof = m.profile(scope=a.scope)
    if a.json:
        print(json.dumps(prof, ensure_ascii=False, indent=2))
    else:
        print(prof["summary"])
    return 0


def cmd_cube(m, a) -> int:
    """ТОП-10 v2 Пункт 9: экспорт/импорт подписанных пакетов MemCube."""
    from pathlib import Path
    from . import memcube
    sub_cmd = getattr(a, "cube_cmd", "export")
    if sub_cmd == "export":
        rpub = None
        if getattr(a, "recipient_pub", None):
            rp = Path(a.recipient_pub)
            rpub = rp.read_text(encoding="utf-8") if rp.exists() else a.recipient_pub
        cube = memcube.export_memcube(m, scope=a.scope, passphrase=a.passphrase, recipient_pub=rpub, ttl_seconds=a.ttl)
        Path(a.out).write_text(json.dumps(cube, ensure_ascii=False, indent=2), encoding="utf-8")
        print(json.dumps({"exported": a.out, "author_pub_hex": (cube.get("header") or {}).get("author_pub_hex"), "cipher": (cube.get("header") or {}).get("cipher")}, ensure_ascii=False))
        return 0
    if sub_cmd == "import":
        raw_cube = Path(a.file).read_text(encoding="utf-8")
        trusted = {x.strip() for x in a.trust_author.split(",") if x.strip()} if a.trust_author else set()
        rident = None
        if getattr(a, "recipient_key", False):
            from . import pqc_sync
            rident = pqc_sync.ensure_local_identity(m)
        res = memcube.import_memcube(m, raw_cube, passphrase=a.passphrase, recipient_identity=rident, trusted_authors=trusted, target_scope=a.scope)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0
    return 1


def cmd_skills(m, a) -> int:
    """ТОП-10 v2 Пункт 5: экспорт одобренных процедур (kind='procedure') в SKILL.md / CLAUDE.md."""
    from . import procedural
    if getattr(a, "skills_cmd", "export") == "export":
        md = procedural.export_skill_markdown(m, scope=a.scope, fmt=a.format)
        if a.out:
            from pathlib import Path
            Path(a.out).write_text(md, encoding="utf-8")
            print(json.dumps({"exported_to": a.out, "format": a.format}, ensure_ascii=False))
        else:
            print(md, end="")
        return 0
    return 1


def cmd_sync_obsidian(m, a) -> int:
    """ТОП-10 v2 Пункт 3: двусторонняя синхронизация с Obsidian/Markdown."""
    from pathlib import Path
    from . import obsidian_sync
    res = obsidian_sync.sync_obsidian(
        m,
        Path(a.vault_dir),
        scope=a.scope,
        direction=a.direction,
        trusted_owner=bool(a.owner),
    )
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0


def cmd_access(m, a) -> int:
    """ТОП-10 v2 Пункт 2: панель прав приложений и хешируемый журнал доступа."""
    from . import app_acl
    sub_cmd = getattr(a, "access_cmd", "list")
    if sub_cmd == "list":
        print(json.dumps({"policies": app_acl.list_policies(m.store)}, ensure_ascii=False, indent=2))
        return 0
    if sub_cmd == "set":
        scopes = [s.strip() for s in a.scopes.split(",") if s.strip()] if a.scopes else None
        tools = [t.strip() for t in a.tools.split(",") if t.strip()] if a.tools else None
        pol = app_acl.set_policy(
            m.store, a.client_id, status=a.status, allowed_scopes=scopes, allowed_tools=tools, note=a.note
        )
        print(json.dumps(pol, ensure_ascii=False, indent=2))
        return 0
    if sub_cmd == "events":
        evs = app_acl.list_events(m.store, client_id=a.client_id, limit=a.limit)
        print(json.dumps({"events": evs}, ensure_ascii=False, indent=2))
        return 0
    if sub_cmd == "verify":
        res = app_acl.verify_audit_chain(m.store)
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0 if res.get("valid") else 2
    return 1


def cmd_aifa_sec(m, a) -> int:
    """Эталонный автономный бенчмарк AIFaSecurity (100 критериев, $0, без LLM)."""
    import sys as _sys
    from pathlib import Path as _Path
    _root = _Path(__file__).resolve().parents[1]
    if str(_root) not in _sys.path:
        _sys.path.insert(0, str(_root))
    from benchmarks.aifa_security import run_aifa_sec
    argv = ["--target", a.target]
    if a.path:
        argv.extend(["--path", a.path])
    if a.out_html:
        argv.extend(["--out-html", a.out_html])
    if a.out_svg:
        argv.extend(["--out-svg", a.out_svg])
    if a.out_json:
        argv.extend(["--out-json", a.out_json])
    if a.no_write:
        argv.append("--no-write")
    if a.json_out:
        argv.append("--json")
    return run_aifa_sec.main(argv)


def cmd_badge(m, a) -> int:
    """ТОП-10 v4 Пункт 9: виральная карточка суверенности (SVG + Markdown)."""
    from pathlib import Path
    from . import badge
    rep = Path(a.report) if getattr(a, "report", None) else None
    out_svg = Path(a.out_svg) if getattr(a, "out_svg", None) else None
    res = badge.generate_sovereignty_badge(report_path=rep, out_svg=out_svg)
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0 if res.get("status") == "ok" else 2


def cmd_playground(m, a) -> int:
    """ТОП-10 v4 Пункт 8: 60-секундный интерактивный вау-тур в :memory:."""
    from . import playground
    res = playground.run_60s_tour()
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0 if res.get("status") == "ok" else 1


def cmd_team(m, a) -> int:
    """ТОП-10 v4 Пункт 4: командная память проекта в Git (.padam/team.memcube)."""
    from pathlib import Path
    from . import team_sync
    sub_cmd = getattr(a, "team_cmd", "sync")
    if sub_cmd == "export":
        res = team_sync.export_team_vault(
            m,
            project_dir=Path(a.project_dir),
            scope=a.scope,
            passphrase=a.passphrase,
        )
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0
    if sub_cmd == "sync":
        trusted = {x.strip() for x in a.trust_author.split(",") if x.strip()} if a.trust_author else set()
        res = team_sync.sync_team_vault(
            m,
            project_dir=Path(a.project_dir),
            scope=a.scope,
            passphrase=a.passphrase,
            trusted_authors=trusted,
        )
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0
    return 1


def cmd_migrate(m, a) -> int:
    """Переезд из ChatGPT, Claude, Gemini, Grok, DeepSeek, Copilot, Perplexity, Mem0, Zep, Obsidian, Notion.

    --from auto определяет источник по содержимому файла, папки или .zip; --preview показывает, что будет
    импортировано, ничего не записывая; --undo SNAPSHOT_ID отменяет импорт (откат с квитанциями).
    """
    from . import migrate
    if getattr(a, "undo", None):
        res = migrate.undo_import(m, snapshot_id=a.undo, scope=a.scope)
    elif getattr(a, "preview", False):
        res = migrate.preview(source=a.source, input_path=a.path)
    else:
        if not a.path:
            print("path is required", file=sys.stderr)
            return 2
        res = migrate.migrate_from_source(
            m,
            source=a.source,
            input_path=a.path,
            scope=a.scope,
            dry_run=bool(a.dry_run),
            guarded=not bool(getattr(a, "trusted", False)),
            hold_all=bool(getattr(a, "hold_all", False)),
        )
    print(json.dumps(res, ensure_ascii=False, indent=2, default=str))
    return 0


def cmd_compact(m, a) -> int:
    """ТОП-10 v3 Пункт 5: локальная иерархическая компакция старых событий."""
    from . import compaction
    res = compaction.compact_events(
        m,
        scope=a.scope,
        min_age_days=a.min_age_days,
        batch_size=a.batch_size,
        dry_run=a.dry_run,
        force=bool(getattr(a, "force", False)),
    )
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0


def cmd_pack_extension(m, a) -> int:
    """ТОП-10 v4 Пункт 2: сборка .mcpb (.dxt) пакета для Claude Desktop."""
    from pathlib import Path
    from . import pack_extension
    res = pack_extension.build_mcpb_bundle(Path(a.out), user_id=getattr(a, "user", "default") or "default")
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0


def cmd_setup(m, a) -> int:
    """ТОП-10 v4 Пункт 1: авто-установка PADAM MCP в IDE и AI-клиенты."""
    from pathlib import Path
    from . import setup_clients
    clients = [c.strip() for c in (a.client or "").split(",") if c.strip()]
    res = setup_clients.setup_clients(
        clients=clients or None,
        all_detected=bool(a.all),
        project_dir=Path(a.project_dir),
        user_id=getattr(a, "user", "default") or "default",
        dry_run=bool(a.dry_run),
        verify=bool(a.verify),
    )
    print(json.dumps(res, ensure_ascii=False, indent=2))
    return 0


def cmd_hooks(m, a) -> int:
    """ТОП-10 v2 Пункт 1: управление хуками жизненного цикла (install/run/status)."""
    from pathlib import Path
    from . import hooks
    sub_cmd = getattr(a, "hooks_cmd", "status")
    if sub_cmd == "install":
        res = hooks.install_hooks(
            a.client,
            project_dir=Path(a.project_dir),
            scope=a.scope,
            token_budget=a.budget,
            dry_run=a.dry_run,
        )
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0
    if sub_cmd == "status":
        res = hooks.hooks_status(Path(a.project_dir))
        print(json.dumps(res, ensure_ascii=False, indent=2))
        return 0
    if sub_cmd == "run":
        query = a.query or ""
        tool_name = a.tool_name or ""
        if not query and not sys.stdin.isatty():
            try:
                raw_in = sys.stdin.read().strip()
                if raw_in.startswith("{"):
                    payload = json.loads(raw_in)
                    query = str(payload.get("prompt") or payload.get("query") or "")
                    tool_name = tool_name or str(payload.get("tool_name") or "")
                elif raw_in:
                    query = raw_in
            except Exception:
                pass
        res = hooks.render_hook_context(
            m,
            event=a.event,
            query=query,
            scope=a.scope,
            token_budget=a.budget,
            tool_name=tool_name,
            briefing=bool(getattr(a, "briefing", False)),
        )
        print(json.dumps({"hookSpecificOutput": res["hookSpecificOutput"]}, ensure_ascii=False))
        return 0
    return 1


def cmd_seal_status(m, a) -> int:
    """Шаг 5 Легенды: статус аппаратных возможностей и печати PADAMHW1."""
    from pathlib import Path
    from . import hardware_seal
    db_target = Path(a.db) if a.db else config.DB_PATH
    sealed = hardware_seal.is_sealed_database(db_target)
    caps = hardware_seal.probe_hardware_capabilities()
    out = {
        "db": str(db_target),
        "sealed": sealed,
        "hw_seal_env_enabled": bool(config.mcp_hw_seal_enabled()),
        "capabilities": caps,
    }
    if sealed:
        hdr = hardware_seal.read_seal_header(db_target)
        out["header"] = {
            "mode": hdr.get("mode"),
            "rp_id": hdr.get("rp_id"),
            "sealed_at": hdr.get("sealed_at"),
            "plain_size": hdr.get("plain_size"),
            "plain_sha256": hdr.get("plain_sha256"),
        }
    if a.json:
        print(json.dumps(out, ensure_ascii=False, indent=2))
    else:
        print(
            f"Hardware Seal: db={db_target} sealed={sealed} dpapi={caps['dpapi_available']} "
            f"webauthn={caps['webauthn_dll']} platform_auth={caps.get('platform_authenticator_available')}"
        )
    return 0


def cmd_seal(m, a) -> int:
    """Шаг 5 Легенды: запечатать файл БД аппаратной печатью PADAMHW1 (DPAPI / Windows Hello WebAuthn)."""
    from pathlib import Path
    from . import hardware_seal
    db_target = Path(a.db) if a.db else config.DB_PATH
    rp_id = getattr(a, "rp_id", "padam.local")
    if a.mode in ("webauthn", "webauthn+dpapi"):
        from . import webauthn_win
        tok = webauthn_win.WindowsWebAuthnToken.enroll(rp_id=rp_id)
        seal_mode = "fido2" if a.mode == "webauthn" else "fido2+dpapi"
        res = hardware_seal.seal_database(db_target, mode=seal_mode, fido2_token=tok, rp_id=rp_id)
    else:
        res = hardware_seal.seal_database(db_target, mode=a.mode, rp_id=rp_id)
    if a.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        print(f"Sealed {res['db']} (mode={res['mode']}, bytes={res['container_size']})")
    return 0


def cmd_unseal(m, a) -> int:
    """Шаг 5 Легенды: распечатать файл БД (DPAPI / Windows Hello WebAuthn)."""
    from pathlib import Path
    from . import hardware_seal
    db_target = Path(a.db) if a.db else config.DB_PATH
    hdr = hardware_seal.read_seal_header(db_target)
    use_wa = bool(getattr(a, "webauthn", False)) or hdr.get("mode") in ("fido2", "fido2+dpapi")
    res = hardware_seal.unseal_database(db_target, use_webauthn=use_wa)
    if a.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        print(f"Unsealed {res['db']} (mode={res['mode']}, bytes={res['plain_size']})")
    return 0


def cmd_dlp_stats(m: Memory, a) -> int:
    """Шаг 3 Легенды: статистика локального DLP-сейфа секретов."""
    from .dlp_shield import DlpShield
    st = DlpShield(m).stats()
    st["enabled"] = bool(config.mcp_dlp_shield_enabled())
    if a.json:
        print(json.dumps(st, ensure_ascii=False, indent=2))
    else:
        print(
            f"DLP Shield enabled={st['enabled']} unique_aliases={st['unique_aliases']} "
            f"total_interceptions={st['total_interceptions']}"
        )
    return 0


def cmd_snapshot(m: Memory, a) -> int:
    """Шаг 2 Легенды: создать или вывести список когнитивных снапшотов."""
    if a.list_only:
        snaps = m.snapshots(scope=a.scope, limit=a.limit)
        if a.json:
            print(json.dumps(snaps, ensure_ascii=False, indent=2))
        else:
            for s in snaps:
                print(f"{s['id'][:8]}  {s['created_at'][:19]}  {s['name']}  records={s['record_count']}  sha={s['state_sha256'][:12]}")
        return 0
    res = m.snapshot(name=a.name, scope=a.scope, note=a.note or "")
    if a.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        print(f"Snapshot {res['snapshot_id']} ({res['name']}) records={res['record_count']} sha={res['state_sha256'][:16]}")
    return 0


def cmd_rollback(m: Memory, a) -> int:
    """Шаг 2 Легенды: когнитивный откат к снапшоту или моменту as_of."""
    res = m.rollback(
        snapshot_id=a.snapshot_id,
        as_of=a.as_of,
        scope=a.scope,
        dry_run=a.dry_run,
        revoke_after=not a.soft,
        reason=a.reason or "",
    )
    if a.json:
        print(json.dumps(res, ensure_ascii=False, indent=2))
    else:
        print(f"Rollback {res['status']}: forgotten={len(res.get('forgotten_ids', []))} restored={len(res.get('restored_ids', []))}")
    return 0


def cmd_rem(m: Memory, a) -> int:
    """Шаг 1 Легенды: цикл активного REM-сна (связи, сжатие дубликатов, локальные инсайты)."""
    from . import rem_sleep
    rep = rem_sleep.run_rem_cycle(
        m,
        scope=a.scope,
        dry_run=a.dry_run,
        max_insights=a.max_insights,
        ollama_url=a.ollama_url,
        model=a.model,
    )
    if a.json:
        print(json.dumps(rep, ensure_ascii=False, indent=2))
    else:
        print(
            t(
                f"REM-сон ({rep['status']}): связей={rep['links_discovered']}, "                f"сжато дубликатов={rep['duplicates_compressed']}, инсайтов={rep['insights_created']}.",
                f"REM sleep ({rep['status']}): links={rep['links_discovered']}, "                f"compressed={rep['duplicates_compressed']}, insights={rep['insights_created']}.",
            )
        )
    return 0


def cmd_audit(m: Memory, a) -> int:
    """Б12: журнал действий (audit_log)."""
    entries = m.audit_log(limit=a.limit, action=a.action, agent_id=a.agent)
    if a.json:
        print(json.dumps(entries, ensure_ascii=False, indent=2))
        return 0
    if not entries:
        print(t("Журнал действий пуст.", "Audit log is empty."))
        return 0
    for e in entries:
        ag = f"  agent={e['agent_id']}" if e.get("agent_id") else ""
        print(f"{e['created_at'][:19]}  [{e['action']:8s}]  actor={e['actor']}{ag}  outcome={e.get('outcome') or '—'}  id={e.get('memory_id') or '—'}")
    return 0


def cmd_forget(m: Memory, a) -> int:
    выводы = m.derived(a.id)
    if выводы and not a.with_derived:
        print(t(f"{DIM}Из этой записи сделано выводов: {len(выводы)}. Они остаются; чтобы стереть и их — "
                f"padam forget {a.id} --with-derived{RESET}",
                f"{DIM}{len(выводы)} conclusion(s) were drawn from this record. They stay; to wipe them too — "
                f"padam forget {a.id} --with-derived{RESET}"))
        for вывод in выводы:
            строка = m.store.one("SELECT content FROM memory WHERE id = ?", (вывод,))
            print(f"  {DIM}{вывод}  {((строка['content'] or '—') if строка else '—')[:80]}{RESET}")
    if m.revoke(a.id, with_derived=a.with_derived):
        if a.with_derived and выводы:
            print(t(f"Вместе с выводами: {len(выводы)}.", f"Together with {len(выводы)} conclusion(s)."))
        print(t(f"{GREEN}Отозвано.{RESET} Затёрты запись, её версии, копии и исходные эпизоды; хеш и якорь сохранены.",
                f"{GREEN}Revoked.{RESET} The record, its versions, copies and source episodes are wiped; hash and anchor kept."))
        print(f"{DIM}" + t("Если запись была заякорена, ключ уничтожен — данные в цепи нечитаемы навсегда.",
                           "If the record was anchored, its key is destroyed — the on-chain data is unreadable forever.")
              + f"{RESET}")
        receipt = getattr(m, "_last_receipt", None)
        if getattr(a, "receipt", None) and receipt:
            import html as _html
            out_path = a.receipt
            if out_path.lower().endswith((".html", ".htm")):
                doc = (
                    "<!doctype html><html lang='ru'><head><meta charset='utf-8'>"
                    "<title>PADAM NOCTURNE — Доказательство удаления / Proof of Deletion</title>"
                    "<style>body{font-family:system-ui,sans-serif;max-width:740px;margin:32px auto;padding:24px;"
                    "background:#0a0d14;color:#eef2ff;border:1px solid #1e293b;border-radius:12px}"
                    "h1{font-size:20px;margin:0 0 8px;color:#38bdf8}p{color:#94a3b8;font-size:13px}"
                    "table{width:100%;border-collapse:collapse;margin-top:16px;font-size:13px}"
                    "td{padding:8px 10px;border-bottom:1px solid #1e293b;word-break:break-all}"
                    "td:first-child{color:#94a3b8;width:36%;font-weight:600}"
                    "code{font-family:monospace;color:#e2e8f0}</style></head><body>"
                    "<h1>PADAM NOCTURNE · Доказательство удаления (Proof of Deletion)</h1>"
                    "<p>Удалённый текст не сохранён в этой квитанции. Криптографический след доказывает факт и полноту уничтожения.</p>"
                    "<table>"
                    f"<tr><td>Receipt ID</td><td><code>{_html.escape(str(receipt.get('receipt_id', '')))}</code></td></tr>"
                    f"<tr><td>Memory ID</td><td><code>{_html.escape(str(receipt.get('memory_id', '')))}</code></td></tr>"
                    f"<tr><td>Forgotten At (UTC)</td><td><code>{_html.escape(str(receipt.get('forgotten_at', '')))}</code></td></tr>"
                    f"<tr><td>Content SHA-256</td><td><code>{_html.escape(str(receipt.get('content_hash_sha256', '')))}</code></td></tr>"
                    f"<tr><td>Wiped Records Count</td><td><code>{_html.escape(str(receipt.get('wiped_count', 0)))}</code></td></tr>"
                    f"<tr><td>Wiped IDs</td><td><code>{_html.escape(', '.join(receipt.get('wiped_ids', [])))}</code></td></tr>"
                    f"<tr><td>With Derived</td><td><code>{_html.escape(str(receipt.get('with_derived', False)))}</code></td></tr>"
                    f"<tr><td>L3 Key Destroyed</td><td><code>{_html.escape(str(receipt.get('key_destroyed', False)))}</code></td></tr>"
                    f"<tr><td>Anchor TX</td><td><code>{_html.escape(str(receipt.get('anchor_tx') or '—'))}</code></td></tr>"
                    f"<tr><td>Merkle Forget Leaf</td><td><code>{_html.escape(str(receipt.get('leaf_forget_hex', '')))}</code></td></tr>"
                    "</table></body></html>"
                )
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write(doc)
            else:
                with open(out_path, "w", encoding="utf-8") as f:
                    json.dump(receipt, f, ensure_ascii=False, indent=2)
            print(t(f"{GREEN}Квитанция удаления сохранена:{RESET} {out_path}",
                    f"{GREEN}Deletion receipt saved:{RESET} {out_path}"))
        return 0
    _not_found()
    return 1


def cmd_doctor(m: Memory, a) -> int:
    """0.4.2: состояние безопасности одним отчётом (внешний разбор 09.11.2026: настроек много, и неверный
    выключатель равен утечке). Ничего не меняет. Код выхода 1, если есть хоть одно предупреждение."""
    import stat
    from . import __version__, keyvault
    предупреждений = 0

    def строка(ok, ru, en):
        nonlocal предупреждений
        предупреждений += 0 if ok else 1
        print(("  ok    " if ok else "  WARN  ") + t(ru, en))

    print(f"padam-nocturne {__version__} · {m.store.path}")
    print(t("  info  строгий профиль: ", "  info  strict profile: ")
          + ("PADAM_STRICT=1" if config.STRICT else t("нет (PADAM_STRICT=1 включает)", "no (PADAM_STRICT=1 turns it on)")))
    for имя in config.strict_ignored():
        print(t(f"  info  {имя} отменён строгим профилем", f"  info  {имя} overridden by the strict profile"))
    for имя, что in config.unsafe_settings():
        строка(False, f"{имя}: {что}", f"{имя}: {что}")
    строка(config.HOLD_EXTERNAL, "внешний текст ждёт проверки владельцем (PADAM_HOLD_EXTERNAL)",
           "outside text waits for the owner's review (PADAM_HOLD_EXTERNAL)")
    print(t("  info  каждая запись агента ждёт владельца: ", "  info  every agent write waits for the owner: ")
          + ("PADAM_MCP_REVIEW_ALL=1" if config.MCP_REVIEW_ALL else t("нет (PADAM_MCP_REVIEW_ALL=1 включает)",
                                                                       "no (PADAM_MCP_REVIEW_ALL=1 turns it on)")))
    защищены = keyvault.is_enabled(m)
    строка(защищены, f"ключи записей защищены паролем; открытых: {keyvault.plain_count(m)}"
           if защищены else f"ключи записей НЕ защищены паролем, открытых: {keyvault.plain_count(m)} — padam protect-keys",
           f"record keys protected by a passphrase; in clear: {keyvault.plain_count(m)}"
           if защищены else f"record keys NOT protected by a passphrase, in clear: {keyvault.plain_count(m)} — padam protect-keys")
    if os.name == "posix":
        for путь, нужно in ((m.store.path, 0o600), (m.store.path.parent, 0o700)):
            права = stat.S_IMODE(os.stat(путь).st_mode)
            строка(права & 0o077 == 0, f"права {oct(права)} у {путь}", f"mode {oct(права)} on {путь}")
    else:
        print(t("  info  права файлов: Windows — доступ задаётся учётной записью, не битами режима",
                "  info  file modes: Windows — access is set by the user account, not mode bits"))
    # 0.4.4 (досье Antigravity 09.11.2026): целостность файла и надёжность записи на диск.
    with m.store._lock:
        проверка = m.store.conn.execute("PRAGMA quick_check").fetchone()[0]
        журнал = m.store.conn.execute("PRAGMA journal_mode").fetchone()[0]
        синхр = m.store.conn.execute("PRAGMA synchronous").fetchone()[0]
    строка(проверка == "ok", f"целостность базы (PRAGMA quick_check): {проверка}",
           f"database integrity (PRAGMA quick_check): {проверка}")
    строка(синхр >= 2, f"запись на диск: журнал {журнал}, synchronous {синхр} (2 = FULL)",
           f"writes to disk: journal {журнал}, synchronous {синхр} (2 = FULL)")
    print(t("  info  забывание не достаёт до блоков, которые хранит сама система (copy-on-write, журнал ФС, SSD): "
            "нужно шифрование всего диска (BitLocker, FileVault, LUKS)",
            "  info  forgetting cannot reach blocks the system itself keeps (copy-on-write, filesystem journal, SSD): "
            "use full-disk encryption (BitLocker, FileVault, LUKS)"))
    токен = os.environ.get("PADAM_API_TOKEN")
    print(t("  info  REST API: ", "  info  REST API: ") + (t("постоянный токен задан", "a fixed token is set") if токен
          else t("токен создаётся при каждом запуске", "a token is created on every start")))
    from . import doctor as _doctor
    deep = _doctor.run_doctor(m, fix=bool(getattr(a, "fix", False)))
    checks = deep["checks"]
    строка(checks["sqlite_integrity"]["ok"],
           f"глубокая проверка SQLite: {checks['sqlite_integrity']['result']}",
           f"deep SQLite integrity: {checks['sqlite_integrity']['result']}")
    строка(checks["fts5"]["ok"],
           f"индекс FTS5: {checks['fts5']['detail']}",
           f"FTS5 index: {checks['fts5']['detail']}")
    строка(bool(checks["app_access_audit_chain"].get("valid", checks["app_access_audit_chain"].get("ok", True))),
           f"SHA-256 цепь app_access_event: проверено {checks['app_access_audit_chain'].get('count', checks['app_access_audit_chain'].get('checked', 0))}",
           f"app_access_event SHA-256 chain: checked {checks['app_access_audit_chain'].get('count', checks['app_access_audit_chain'].get('checked', 0))}")
    строка(checks["dangling_links"] == 0,
           f"висячих рёбер memory_link: {checks['dangling_links']}",
           f"dangling memory_link edges: {checks['dangling_links']}")
    print(t(f"  info  записей без learned_at: {checks['missing_learned_at']}",
            f"  info  records missing learned_at: {checks['missing_learned_at']}"))
    if deep["fix_applied"]:
        print(t(f"  info  снапшот перед лечением: {deep['snapshot_id']}; действия: {', '.join(deep['actions'])}",
                f"  info  pre-fix snapshot: {deep['snapshot_id']}; actions: {', '.join(deep['actions'])}"))

    s = m.stats()
    if getattr(a, "json", False):
        print(json.dumps({"warnings": предупреждений, "deep": deep, "stats": s}, ensure_ascii=False, indent=2))
        return 1 if (предупреждений or not deep["ok"]) else 0
    print(t(f"  info  векторы: {s['backend']}; ждут проверки: {s['quarantined']}; другой модели: {s['stale_vectors']}",
            f"  info  vectors: {s['backend']}; waiting for review: {s['quarantined']}; of another model: {s['stale_vectors']}"))
    print(t(f"Предупреждений: {предупреждений}", f"Warnings: {предупреждений}"))
    return 1 if предупреждений else 0


def cmd_backup(m: Memory, a) -> int:
    """Создаёт согласованную (и по желанию зашифрованную AES-256-GCM) резервную копию с проверкой SHA-256."""
    from . import backup as _backup, keyvault

    passphrase = getattr(a, "passphrase", None)
    want_encrypt = bool(getattr(a, "encrypt", False) or passphrase or str(a.path).lower().endswith(".padambak"))
    try:
        info = _backup.create_backup_file(m, a.path, passphrase=passphrase, encrypt=want_encrypt, overwrite=False)
    except FileExistsError as exc:
        print(str(exc))
        return 2
    if want_encrypt:
        print(t(
            f"{GREEN}Зашифрованная копия:{RESET} {info['path']} ({info['size_bytes']} байт, "
            f"SHA-256 БД={info['db_sha256']}, SHA-256 архива={info['archive_sha256']})",
            f"{GREEN}Encrypted backup:{RESET} {info['path']} ({info['size_bytes']} bytes, "
            f"DB SHA-256={info['db_sha256']}, Archive SHA-256={info['archive_sha256']})",
        ))
    else:
        print(t(
            f"Копия: {info['path']} ({info['size_bytes']} байт), целостность: {info['integrity']}, SHA-256={info['db_sha256']}",
            f"Backup: {info['path']} ({info['size_bytes']} bytes), integrity: {info['integrity']}, SHA-256={info['db_sha256']}",
        ))
        if not keyvault.is_enabled(m):
            print(t("Внимание: ключи записей не защищены паролем — используйте --encrypt/--passphrase или padam protect-keys.",
                    "Note: record keys are not protected by a passphrase — use --encrypt/--passphrase or padam protect-keys."))
    return 0 if info.get("ok") else 1


def cmd_restore_backup(m: Memory, a) -> int:
    """Восстанавливает память из зашифрованной резервной копии .padambak со сверкой SHA-256 до и после."""
    from . import backup as _backup

    target = getattr(a, "path", None) or getattr(a, "id", "")
    try:
        res = _backup.restore_backup_file(
            m,
            target,
            passphrase=getattr(a, "passphrase", None),
            target_db_path=getattr(a, "to", None),
        )
    except (FileNotFoundError, ValueError) as exc:
        print(f"{RED}{exc}{RESET}")
        return 2
    print(t(
        f"{GREEN}Восстановлено:{RESET} {res['restored_to']} (записей: {res['records_total']}, "
        f"SHA-256 до={res['checksum_before'][:16]}…, после={res['records_sha256_after'][:16]}…, сверка={res['checksum_match']})",
        f"{GREEN}Restored:{RESET} {res['restored_to']} (records: {res['records_total']}, "
        f"SHA-256 before={res['checksum_before'][:16]}…, verified={res['checksum_match']})",
    ))
    return 0 if res.get("checksum_match") else 1


def cmd_l3(m: Memory, a) -> int:
    """L3: новое → пакет шифротекстов в Arweave → корень Меркла в Solana."""
    import os
    from . import anchor
    wallet = a.arweave_wallet or os.environ.get("PADAM_ARWEAVE_WALLET")
    keypair = a.solana_keypair or os.environ.get("PADAM_SOLANA_KEYPAIR")
    if not a.dry_run and not (wallet and keypair):
        print(t("нужны --arweave-wallet и --solana-keypair (или PADAM_ARWEAVE_WALLET / PADAM_SOLANA_KEYPAIR)",
                "--arweave-wallet and --solana-keypair are required (or PADAM_ARWEAVE_WALLET / PADAM_SOLANA_KEYPAIR)"))
        return 2
    from . import keyvault
    # 0.4.1: без защиты паролем ключи записей лежат в базе открыто, а шифротексты в Arweave вечны — у кого файл
    # базы, тот прочитает их навсегда. Поэтому настоящая заливка без protect-keys не идёт, пока владелец не
    # согласится явно (--allow-unprotected-keys). Пробный прогон (--dry-run) ничего не отправляет и не держится.
    # 0.4.5: в строгом профиле осознанного «без защиты» нет — флаг не действует.
    if not a.dry_run and not keyvault.is_enabled(m) and (config.STRICT or not a.allow_unprotected_keys):
        print(t("Отказ: ключи записей не защищены паролем. Что уйдёт в Arweave, останется там навсегда, а ключи к нему "
                "лежат в файле базы открыто — кто получит файл, прочитает всё. Сначала: padam protect-keys. "
                "Осознанно без защиты: --allow-unprotected-keys.",
                "Refused: record keys are not protected by a passphrase. What goes to Arweave stays there forever, and "
                "the keys to it sit in the database file in clear — whoever gets the file reads it all. First: padam "
                "protect-keys. Knowingly without protection: --allow-unprotected-keys."))
        return 2
    if keyvault.is_enabled(m):
        try:
            keyvault.unlock(m, _пароль(t("Пароль ключей записей: ", "Record-key passphrase: "))
                            if a.ask_passphrase else None)
        except keyvault.KeyVaultError as e:
            print(e); return 2
    save_dir = str(m.store.path) + ".l3"
    rep = anchor.run_l3(
        m, dry_run=a.dry_run, network=a.network, save_dir=save_dir,
        uploader=(lambda data, tags: anchor.turbo_upload(data, wallet, tags, a.turbo_sdk)) if wallet else None,
        anchorer=(lambda memo: anchor.solana_memo(memo, keypair, a.network)) if keypair else None,
        stamper=None if a.no_bitcoin else _ots_stamper())
    if getattr(a, "with_lora", None):
        import hashlib
        from pathlib import Path
        lora_path = Path(a.with_lora)
        if not lora_path.exists():
            print(t(f"Файл LoRA не найден: {lora_path}", f"LoRA file not found: {lora_path}"))
            return 2
        h = hashlib.sha256()
        with lora_path.open("rb") as lf:
            while True:
                chunk = lf.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        lora_sha256 = h.hexdigest()
        lora_meta = {
            "file": lora_path.name,
            "size_bytes": lora_path.stat().st_size,
            "sha256": lora_sha256,
            "arweave_upload_locked": True,
            "arweave_tx_id": None,
        }
        if os.environ.get("PADAM_ARWEAVE_LORA_UPLOAD") == "1" and not a.dry_run and wallet:
            lora_meta["arweave_upload_locked"] = False
            tx_id = anchor.turbo_upload(
                lora_path.read_bytes(),
                wallet,
                {"App-Name": "PADAM-Nocturne", "Content-Type": "application/octet-stream", "LoRA-SHA256": lora_sha256},
                a.turbo_sdk,
            )
            lora_meta["arweave_tx_id"] = tx_id
            if keypair:
                lora_meta["solana_memo_tx"] = anchor.solana_memo(
                    f"PADAM-LORA:{lora_sha256}:{tx_id}",
                    keypair,
                    a.network,
                )
        Path(save_dir).mkdir(parents=True, exist_ok=True)
        (Path(save_dir) / "lora_manifest.json").write_text(
            json.dumps(lora_meta, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        rep["lora"] = lora_meta
    print(json.dumps(rep, ensure_ascii=False, indent=2))
    return 0


def _ots_stamper():
    from . import ots
    return lambda digest: ots.stamp(digest)


def cmd_l3_ots_upgrade(m: Memory, a) -> int:
    """Штампы OpenTimestamps «дозревают» за несколько часов: спросить календари о блоке Bitcoin."""
    from pathlib import Path
    from . import anchor, ots
    anchor.ensure_schema(m)
    итог = []
    for row in m.store.query("SELECT id, ots FROM l3_anchor WHERE ots IS NOT NULL ORDER BY created_at"):
        было = bytes(row["ots"])
        if ots.info(было)["bitcoin_blocks"]:
            итог.append({"anchor": row["id"], "bitcoin_blocks": ots.info(было)["bitcoin_blocks"]})
            continue
        стало, блоки = ots.upgrade(было)
        if стало != было:
            m.store.execute("UPDATE l3_anchor SET ots = ? WHERE id = ?", (стало, row["id"]))
            файл = Path(str(m.store.path) + ".l3") / f"{row['id']}.json.ots"
            if файл.parent.exists():
                файл.write_bytes(стало)
        итог.append({"anchor": row["id"], "bitcoin_blocks": блоки or t("ещё не вошёл в блок", "not in a block yet")})
    print(json.dumps(итог, ensure_ascii=False, indent=2))
    return 0


def cmd_alias(m: Memory, a) -> int:
    """Синонимы терминов: проект переименовали — поиск по новому имени находит и старые записи."""
    if a.action == "add" and a.term and a.alias:
        ok = m.add_alias(a.term, a.alias)
        print(t("Добавлено." if ok else "Не добавлено: пустое слово или то же самое.",
                "Added." if ok else "Not added: empty or the same word."))
        return 0 if ok else 1
    if a.action == "remove" and a.term and a.alias:
        ok = m.remove_alias(a.term, a.alias)
        print(t("Удалено." if ok else "Такой пары нет.", "Removed." if ok else "No such pair."))
        return 0 if ok else 1
    пары = m.aliases()
    if not пары:
        print(t("Синонимов нет.", "No aliases."))
    for term, alias in пары:
        print(f"{term}  ↔  {alias}")
    return 0


def cmd_trust_protected(m: Memory, a) -> int:
    """Показать записи о личности и предпочтениях без подписи; с --yes подписать текущий вид."""
    без = m.unsigned_protected()
    for з in без:
        print(f"{GREEN}{з['id']}{RESET}  [{з['kind']}]  {з['content']}")
    if not без:
        print(t("Все записи о вас подписаны.", "Every record about you is signed."))
        return 0
    if not a.yes:
        print(t(f"\nБез подписи: {len(без)}. Их внесли мимо PADAM. Проверьте; верные подпишет "
                "padam trust-protected --yes, неверные сотрёт padam forget <id>.",
                f"\nUnsigned: {len(без)}. They were written around PADAM. Check them; "
                "padam trust-protected --yes signs the right ones, padam forget <id> wipes a wrong one."))
        return 1
    print(t(f"Подписано: {m.trust_protected()}.", f"Signed: {m.trust_protected()}."))
    return 0


def cmd_legacy(m: Memory, a) -> int:
    """Завещание: делит парольную фразу ключей на доли Шамира или собирает её из долей."""
    from . import legacy
    if a.action == "split":
        фраза = os.environ.get("PADAM_KEY_PASSPHRASE") or _пароль(
            t("Фраза, которую разделить: ", "Passphrase to split: "), повтор=True)
        доли = legacy.split(фраза.encode("utf-8"), a.shares, a.threshold)
        print(t(f"Доли ({a.threshold} из {a.shares} открывают фразу; меньше — не дают о ней ничего).",
                f"Shares (any {a.threshold} of {a.shares} open the passphrase; fewer reveal nothing)."))
        print(t("Раздайте их разным людям и не храните вместе. PADAM их не сохраняет.",
                "Give them to different people and never keep them together. PADAM does not store them."))
        for д in доли:
            print(д)
        return 0
    доли = a.shares_in or [строка.strip() for строка in sys.stdin if строка.strip()]
    try:
        фраза = legacy.combine(доли).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as e:
        print(t(f"Не собралось: {e}", f"Could not combine: {e}"), file=sys.stderr)
        return 1
    print(фраза)
    return 0


def cmd_panic(m: Memory, a) -> int:
    """Экстренное забвение. Необратимо, поэтому требует набрать фразу целиком."""
    ФРАЗА = "ERASE MY MEMORY"
    print(t("ВНИМАНИЕ. Будут уничтожены ключи всех записей: всё, что ушло в Arweave, станет шумом навсегда.",
            "WARNING. The keys of every record will be destroyed: whatever reached Arweave becomes noise forever."))
    if a.wipe_local:
        print(t("И локальная память: каждая запись и весь журнал будут затёрты.",
                "And the local memory: every record and the whole episode log will be wiped."))
    print(t(f"Это нельзя отменить. Чтобы продолжить, наберите: {ФРАЗА}",
            f"This cannot be undone. To continue, type: {ФРАЗА}"))
    if (a.confirm or input("> ").strip()) != ФРАЗА:
        print(t("Отменено: фраза не совпала.", "Cancelled: the phrase did not match."))
        return 1
    print(json.dumps(m.panic(wipe_local=a.wipe_local), ensure_ascii=False))
    return 0


def _пароль(подсказка: str, повтор: bool = False) -> str:
    import getpass
    п = getpass.getpass(подсказка)
    if повтор and getpass.getpass(t("Ещё раз: ", "Once more: ")) != п:
        raise SystemExit(t("пароли не совпали", "passphrases do not match"))
    return п


def cmd_protect_keys(m: Memory, a) -> int:
    """Защитить ключи записей паролем: включить хранилище и завернуть открытые ключи."""
    from . import keyvault
    import os
    уже = keyvault.is_enabled(m)
    п = os.environ.get(keyvault.ENV) or _пароль(t("Пароль для ключей записей: ", "Passphrase for record keys: "),
                                                повтор=not уже)
    try:
        итог = keyvault.protect_existing(m, п)
    except keyvault.WrongPassphrase as e:
        print(e); return 1
    print(t(f"Защита ключей включена: завёрнуто {итог['wrapped']}, открытых осталось {итог['plain_left']}.",
            f"Key protection is on: {итог['wrapped']} wrapped, {итог['plain_left']} left unwrapped."))
    print(f"{DIM}" + t("Пароль не хранится нигде. Без него ключи записей не открыть — "
                       "ни вам, ни нам. Запишите его там, где храните важное.",
                       "The passphrase is stored nowhere. Without it the record keys cannot be opened — "
                       "not by you, not by us. Keep it where you keep important things.") + f"{RESET}")
    return 0


def cmd_rekey(m: Memory, a) -> int:
    """Сменить пароль ключей записей."""
    from . import keyvault
    if not keyvault.is_enabled(m):
        print(t("Защита паролем не включена — сначала protect-keys.",
                "Passphrase protection is not enabled — run protect-keys first.")); return 1
    try:
        n = keyvault.rekey(m, _пароль(t("Текущий пароль: ", "Current passphrase: ")),
                           _пароль(t("Новый пароль: ", "New passphrase: "), повтор=True))
    except keyvault.WrongPassphrase as e:
        print(e); return 1
    print(t(f"Пароль сменён: перезавёрнуто ключей — {n}.", f"Passphrase changed: {n} keys re-wrapped."))
    return 0


def cmd_l3_verify(m: Memory, a) -> int:
    """Независимая проверка закрепления: Arweave + заметка в Solana, без доверия к базе."""
    from . import anchor
    anchor.ensure_schema(m)
    row = m.store.one("SELECT * FROM l3_anchor ORDER BY created_at DESC LIMIT 1") if not a.anchor else         m.store.one("SELECT * FROM l3_anchor WHERE id = ?", (a.anchor,))
    if not row:
        print(t("закреплений нет", "no anchors yet")); return 1
    import hashlib
    from pathlib import Path
    memo = anchor.read_memo(row["solana_sig"], row["network"])
    remote = anchor.fetch_arweave(row["arweave_tx"])
    local_path = Path(str(m.store.path) + ".l3") / f"{row['id']}.json"
    local = local_path.read_bytes() if local_path.exists() else None
    payload = remote or local
    if payload is None:
        print(json.dumps({"ok": None,
                          "status": t("ждёт шлюза Arweave, локальной копии нет",
                                      "waiting for the Arweave gateway, no local copy"),
                          "memo_in_chain": memo}, ensure_ascii=False, indent=2))
        return 3
    v = anchor.verify_bundle(payload, memo)
    v.update(arweave_tx=row["arweave_tx"], solana_sig=row["solana_sig"], network=row["network"],
             source="arweave" if remote else t("локальная копия (шлюз ещё не разнёс)",
                                               "local copy (the gateway has not propagated it yet)"),
             sha256_matches_db=hashlib.sha256(payload).hexdigest() == row["bundle_sha256"])
    v["ok"] = bool(v["ok"] and v["sha256_matches_db"])
    if row["ots"] is not None:                 # второй свидетель: штамп Bitcoin (OpenTimestamps)
        try:
            from . import ots
            о = ots.info(bytes(row["ots"]))
            v["bitcoin_ots"] = {"matches_bundle": ots.matches(bytes(row["ots"]), payload),
                                "bitcoin_blocks": о["bitcoin_blocks"], "pending_calendars": о["pending"]}
        except Exception as e:
            v["bitcoin_ots"] = {"error": f"{type(e).__name__}: {e}"}
    print(json.dumps(v, ensure_ascii=False, indent=2))
    return 0 if v["ok"] else 1


def _safe_stdout() -> None:
    """Консоль Windows по умолчанию в cp1251/cp866: знак «×» из --explain и
    кириллица в выводе роняли команду UnicodeEncodeError (найдено 08.10.2026
    при установке с нуля). Пишем в UTF-8, а чего консоль не знает — заменяем."""
    for s in (sys.stdout, sys.stderr):
        try:
            s.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def main(argv=None) -> int:
    _safe_stdout()
    p = argparse.ArgumentParser(prog="padam", description=t(__doc__, DOC_EN),
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    from . import __version__ as _ver
    p.add_argument("--version", action="version", version=f"padam-nocturne {_ver}")
    # Тот же пользователь, что у MCP-сервера и API: иначе `padam review` не видит записей агента.
    p.add_argument("--user", default=os.environ.get("PADAM_USER", "default"))
    p.add_argument("--db", default=None, help=t("путь к файлу базы", "path to the database file"))
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("remember", help=t("запомнить", "store a memory"))
    s.add_argument("text")
    s.add_argument("--kind", choices=config.KINDS, default=None)
    s.add_argument("--importance", type=float, default=0.5)
    s.add_argument("--scope", default="global")
    s.add_argument("--agent", default=None, help=t("идентификатор агента", "agent identifier"))
    s.set_defaults(fn=cmd_remember)

    s = sub.add_parser("recall", help=t("вспомнить", "recall by meaning, words and identifiers"))
    s.add_argument("query")
    s.add_argument("--kind", choices=config.KINDS, default=None)
    s.add_argument("--limit", type=int, default=5)
    s.add_argument("--scope", default="global")
    s.add_argument("--agent", default=None, help=t("фильтр по агенту", "filter by agent"))
    s.add_argument("--explain", action="store_true", help=t("показать разбор оценки", "show how the score was built"))
    s.set_defaults(fn=cmd_recall)

    s = sub.add_parser("log", help=t("записать в буфер", "add to the episode buffer"))
    s.add_argument("text")
    s.add_argument("--priority", type=float, default=1.0)
    s.add_argument("--scope", default="global")
    s.set_defaults(fn=cmd_log)

    s = sub.add_parser("sleep", help=t("цикл консолидации", "run the NOCTURNE consolidation cycle"))
    s.add_argument("--batch", type=int, default=256)
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(fn=cmd_sleep)

    s = sub.add_parser("stats", help=t("состояние памяти", "memory state"))
    s.set_defaults(fn=cmd_stats)

    s = sub.add_parser("backup", help=t("согласованная резервная копия памяти (с шифрованием и SHA-256)",
                                        "consistent backup of memory (with optional encryption and SHA-256)"))
    s.add_argument("path")
    s.add_argument("-p", "--passphrase", default=None, help=t("пароль для шифрования AES-256-GCM", "passphrase for AES-256-GCM archive"))
    s.add_argument("--encrypt", action="store_true", help=t("создать зашифрованный архив", "create encrypted archive"))
    s.set_defaults(fn=cmd_backup)



    s = sub.add_parser("doctor", help=t("состояние безопасности и целостности одним отчётом",
                                        "security and integrity state in one report"))
    s.add_argument("--fix", action="store_true", help=t("создать снапшот и безопасно исправить дефекты",
                                                      "create snapshot and safely repair defects"))
    s.add_argument("--json", action="store_true", help=t("вывести глубокий аудит в JSON", "print deep audit as JSON"))
    s.set_defaults(fn=cmd_doctor)

    s = sub.add_parser("timeline", help=t("история версий записи", "version history of a record"))
    s.add_argument("id")
    s.set_defaults(fn=cmd_timeline)

    s = sub.add_parser("export", help=t("выгрузить всю память в JSON", "export the whole memory as JSON"))
    s.add_argument("--out", default=None, help=t("файл (по умолчанию на экран)", "file (default: print)"))
    s.add_argument("--scope", default=None)
    s.add_argument("--active-only", action="store_true")
    s.set_defaults(fn=cmd_export)

    s = sub.add_parser("export-md", help=t("выгрузить действующую память в папку Markdown / Obsidian",
                                           "export active memory to a Markdown / Obsidian folder"))
    s.add_argument("dir", help=t("папка назначения", "destination folder"))
    s.add_argument("--scope", default=None)
    s.set_defaults(fn=cmd_export_md)

    s = sub.add_parser("import", help=t("загрузить выгрузку обратно (или внешний формат с --format)",
                                        "load an export back (or external format with --format)"))
    s.add_argument("file")
    s.add_argument("--overwrite", action="store_true")
    s.add_argument("--format", choices=["padam", "auto", "chatgpt", "claude", "markdown", "obsidian", "mem0"],
                   default="padam", help=t("формат источника", "source format"))
    s.add_argument("--scope", default="global")
    s.set_defaults(fn=cmd_import)

    s = sub.add_parser("import-ext", help=t("импорт чужой памяти (ChatGPT, Claude, Markdown/Obsidian, mem0) с проверкой",
                                            "import external memory (ChatGPT, Claude, Markdown/Obsidian, mem0) with review"))
    s.add_argument("source", help=t("файл или папка", "file or folder"))
    s.add_argument("--format", choices=["auto", "chatgpt", "claude", "markdown", "obsidian", "mem0"], default="auto")
    s.add_argument("--scope", default="global")
    s.set_defaults(fn=cmd_import_ext)

    s = sub.add_parser("confirm", help=t("запись оказалась верной", "a record proved correct"))
    s.add_argument("id")
    s.set_defaults(fn=cmd_confirm)

    s = sub.add_parser("refute", help=t("запись оказалась неверной", "a record proved wrong"))
    s.add_argument("id")
    s.add_argument("--drop", type=float, default=0.3)
    s.set_defaults(fn=cmd_refute)

    s = sub.add_parser("serve", help=t("запустить MCP-сервер (stdio или локальный Streamable HTTP с --http)",
                                       "start the MCP server (stdio or local Streamable HTTP with --http)"))
    s.add_argument("--http", action="store_true", help=t("локальный Streamable HTTP (127.0.0.1, с токеном)",
                                                         "local Streamable HTTP (127.0.0.1, token required)"))
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8079)
    s.add_argument("--token", default=None)
    s.set_defaults(fn=lambda m, a: __import__("padam.mcp_server", fromlist=["main"]).main(
        (["--http", "--host", a.host, "--port", str(a.port)] + (["--token", a.token] if a.token else []))
        if a.http else [],
        memory=m,
    ))

    s = sub.add_parser("api", help=t("запустить REST API", "start the REST API"))
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8077)
    s.add_argument("--token", default=None)
    s.add_argument("--ui", action="store_true")
    s.set_defaults(fn=lambda m, a: __import__("padam.api", fromlist=["main"])
                   .main(["--host", a.host, "--port", str(a.port)]
                         + (["--ui"] if a.ui else [])
                         + (["--token", a.token] if a.token else []), memory=m))

    s = sub.add_parser("l3", help=t("закрепить память: Arweave + корень Меркла в Solana",
                                    "anchor memory: Arweave + Merkle root on Solana"))
    s.add_argument("--network", choices=["devnet", "mainnet"], default="devnet")
    s.add_argument("--arweave-wallet", default=None)
    s.add_argument("--solana-keypair", default=None)
    s.add_argument("--turbo-sdk", default=None, help=t("каталог node_modules с @ardrive/turbo-sdk",
                                                       "node_modules directory with @ardrive/turbo-sdk"))
    s.add_argument("--dry-run", action="store_true")
    s.add_argument("--ask-passphrase", action="store_true",
                   help=t("спросить пароль ключей записей в консоли (иначе PADAM_KEY_PASSPHRASE)",
                          "ask for the record-key passphrase in the console (otherwise PADAM_KEY_PASSPHRASE)"))
    s.add_argument("--allow-unprotected-keys", action="store_true",
                   help=t("заливать, хотя ключи записей не защищены паролем (не советуем)",
                          "anchor although record keys are not protected by a passphrase (not advised)"))
    s.add_argument("--no-bitcoin", action="store_true",
                   help=t("не штамповать пакет в Bitcoin через OpenTimestamps (бесплатно; по умолчанию штампуется)",
                          "do not timestamp the bundle in Bitcoin via OpenTimestamps (free; on by default)"))
    s.add_argument("--with-lora", default=None,
                   help=t("путь к .safetensors LoRA-адаптеру (локально якорит SHA-256; Arweave выключен)",
                          "path to .safetensors LoRA adapter (anchors SHA-256 locally; Arweave upload locked)"))
    s.set_defaults(fn=cmd_l3)

    s = sub.add_parser("l3-ots-upgrade", help=t("штампы Bitcoin: спросить календари о номере блока",
                                                "Bitcoin timestamps: ask the calendars for the block height"))
    s.set_defaults(fn=cmd_l3_ots_upgrade)

    s = sub.add_parser("protect-keys", help=t("защитить ключи записей паролем (и завернуть уже созданные)",
                                              "protect record keys with a passphrase (and wrap existing ones)"))
    s.set_defaults(fn=cmd_protect_keys)

    s = sub.add_parser("rekey", help=t("сменить пароль ключей записей", "change the record-key passphrase"))
    s.set_defaults(fn=cmd_rekey)

    s = sub.add_parser("l3-verify", help=t("проверить закрепление по Arweave и Solana",
                                           "verify an anchor against Arweave and Solana"))
    s.add_argument("--anchor", default=None)
    s.set_defaults(fn=cmd_l3_verify)

    s = sub.add_parser("forget", help=t("отозвать запись", "revoke a record"))
    s.add_argument("id")
    s.add_argument("--with-derived", action="store_true",
                   help=t("стереть и выводы, сделанные из записи", "also wipe conclusions drawn from the record"))
    s.add_argument("--receipt", default=None,
                   help=t("сохранить квитанцию удаления (.json или .html)", "save a deletion receipt (.json or .html)"))
    s.set_defaults(fn=cmd_forget)

    s = sub.add_parser("alias", help=t("синонимы терминов для поиска", "term aliases for search"))
    s.add_argument("action", choices=["add", "remove", "list"], nargs="?", default="list")
    s.add_argument("term", nargs="?")
    s.add_argument("alias", nargs="?")
    s.set_defaults(fn=cmd_alias)

    s = sub.add_parser("trust-protected", help=t("проверить подписи записей о вас", "check signatures of records about you"))
    s.add_argument("--yes", action="store_true", help=t("подписать текущий вид", "sign them as they are"))
    s.set_defaults(fn=cmd_trust_protected)

    s = sub.add_parser("legacy", help=t("завещание: доли Шамира для фразы ключей",
                                        "legacy: Shamir shares of the key passphrase"))
    s.add_argument("action", choices=["split", "combine"])
    s.add_argument("--shares", type=int, default=5)
    s.add_argument("--threshold", type=int, default=3)
    s.add_argument("shares_in", nargs="*", help=t("доли для combine (или по строке на stdin)",
                                                  "shares for combine (or one per line on stdin)"))
    s.set_defaults(fn=cmd_legacy)

    s = sub.add_parser("panic", help=t("экстренное забвение: уничтожить ключи (необратимо)",
                                       "emergency forgetting: destroy the keys (irreversible)"))
    s.add_argument("--wipe-local", action="store_true",
                   help=t("стереть и локальную память", "wipe the local memory too"))
    s.add_argument("--confirm", default=None, help=t("фраза подтверждения без ввода", "confirmation phrase, non-interactive"))
    s.set_defaults(fn=cmd_panic)

    s = sub.add_parser("review", help=t("записи агента, ждущие решения владельца", "agent writes waiting for the owner"))
    s.set_defaults(fn=cmd_review)

    s = sub.add_parser("approve", help=t("принять запись с проверки", "accept a held record"))
    s.add_argument("id")
    s.set_defaults(fn=cmd_approve)

    s = sub.add_parser("reject", help=t("отклонить запись с проверки", "reject a held record"))
    s.add_argument("id")
    s.set_defaults(fn=cmd_reject)

    def _dispatch_restore(m: Memory, a) -> int:
        from pathlib import Path as _P
        target = getattr(a, "id", "")
        if (
            getattr(a, "backup", False)
            or getattr(a, "passphrase", None) is not None
            or getattr(a, "to", None) is not None
            or target.lower().endswith(".padambak")
            or _P(target).is_file()
        ):
            return cmd_restore_backup(m, a)
        return cmd_restore(m, a)

    s = sub.add_parser("restore", help=t("вернуть запись из архива или восстановить из .padambak",
                                         "restore a record from archive or a .padambak backup"))
    s.add_argument("id")
    s.add_argument("-p", "--passphrase", default=None, help=t("пароль от резервной копии .padambak", "backup decryption passphrase"))
    s.add_argument("--to", default=None, help=t("путь целевой базы (по умолчанию текущая)", "target DB path (default: current DB)"))
    s.add_argument("--backup", action="store_true", help=t("принудительно считать аргумент файлом копии", "treat argument as backup file"))
    s.set_defaults(fn=_dispatch_restore)

    s = sub.add_parser("viewer", help=t("память в браузере: шкала, «забыть», решения, память на дату",
                                        "memory in the browser: timeline, forget, review, memory as of a date"))
    s.add_argument("--port", type=int, default=8078)
    s.add_argument("--no-open", action="store_true", help=t("не открывать браузер", "do not open a browser"))
    s.set_defaults(fn=cmd_viewer)

    s = sub.add_parser("studio", help=t("приложение PADAM Studio в браузере (10 экранов, 4 языка, граф, L3, доктор)",
                                        "PADAM Studio app in the browser (10 screens, 4 languages, graph, L3, doctor)"))
    s.add_argument("--port", type=int, default=8078)
    s.add_argument("--no-open", action="store_true", help=t("не открывать браузер", "do not open a browser"))
    s.set_defaults(fn=cmd_studio)

    s = sub.add_parser("desktop", help=t("настольное окно центра памяти и ярлык запуска (без встроенного Chromium)",
                                         "desktop memory center window and launcher shortcut (no bundled Chromium)"))
    s.add_argument("--port", type=int, default=0)
    s.add_argument("--self-test", action="store_true")
    s.add_argument("--create-shortcut", default=None, help=t("создать ярлык запуска в папке", "create launcher shortcut in folder"))
    s.set_defaults(fn=lambda m, a: (
        __import__("padam.desktop", fromlist=["create_launcher_shortcut", "run_desktop_gui"]).main(
            ["--create-shortcut", a.create_shortcut]
        ) if a.create_shortcut else
        __import__("padam.desktop", fromlist=["run_desktop_gui"]).run_desktop_gui(
            m, port=a.port, self_test=a.self_test
        )
    ))

    s = sub.add_parser("demo", help=t("создать отдельную демо-память с примерами (не трогает основную базу)",
                                      "create a standalone demo memory database with examples (leaves main DB untouched)"))
    s.add_argument("--out", default=None, help=t("путь к файлу демо-базы (по умолчанию ~/.padam/demo.db)",
                                                 "path to demo database file (default: ~/.padam/demo.db)"))
    s.add_argument("--studio", action="store_true", help=t("сразу открыть демо-память в PADAM Studio",
                                                           "immediately open the demo memory in PADAM Studio"))
    s.add_argument("--port", type=int, default=8078)
    s.add_argument("--no-open", action="store_true", help=t("не открывать браузер", "do not open a browser"))
    s.set_defaults(fn=cmd_demo)

    s = sub.add_parser("reindex", help=t("пересчитать векторы после смены модели",
                                         "recompute vectors after changing the embedding model"))
    s.add_argument("--limit", type=int, default=None)
    s.set_defaults(fn=cmd_reindex)

    s = sub.add_parser("profile", help=t("сводка профиля человека (подписанные identity и preference)",
                                         "user profile summary (owner-signed identity and preferences)"))
    s.add_argument("--scope", default="global")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_profile)

    s = sub.add_parser("audit", help=t("журнал действий с памятью (audit_log)",
                                       "memory action audit log (audit_log)"))
    s.add_argument("--limit", type=int, default=50)
    s.add_argument("--action", default=None)
    s.add_argument("--agent", default=None)
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_audit)

    s = sub.add_parser("rem", help=t("запустить цикл активного REM-сна (связи, дубликаты, локальные инсайты)",
                                     "run Active REM Sleep consolidation (links, duplicates, local insights)"))
    s.add_argument("--scope", default=None)
    s.add_argument("--dry-run", action="store_true")
    s.add_argument("--max-insights", type=int, default=4)
    s.add_argument("--ollama-url", default=None)
    s.add_argument("--model", default=None)
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_rem)

    s = sub.add_parser("snapshot", help=t("когнитивные снапшоты памяти (Git для Разума)",
                                          "cognitive memory snapshots (Git for Mind)"))
    s.add_argument("--name", default=None)
    s.add_argument("--scope", default=None)
    s.add_argument("--note", default="")
    s.add_argument("--list", dest="list_only", action="store_true")
    s.add_argument("--limit", type=int, default=20)
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_snapshot)

    s = sub.add_parser("rollback", help=t("откатить память к снапшоту или дате as_of",
                                          "roll back memory to a snapshot or as_of timestamp"))
    s.add_argument("--snapshot-id", default=None)
    s.add_argument("--as-of", default=None)
    s.add_argument("--scope", default=None)
    s.add_argument("--reason", default="")
    s.add_argument("--dry-run", action="store_true")
    s.add_argument("--soft", action="store_true")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_rollback)

    s = sub.add_parser("dlp-stats", help=t("статистика локального DLP-сейфа секретов",
                                           "local DLP Zero-Leak vault statistics"))
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_dlp_stats)

    s = sub.add_parser("seal-status", help=t("статус аппаратной печати БД (PADAMHW1: FIDO2/DPAPI)",
                                             "hardware seal status for the DB (PADAMHW1: FIDO2/DPAPI)"))
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_seal_status)

    s = sub.add_parser("seal", help=t("запечатать базу данных аппаратной печатью (DPAPI / Windows Hello WebAuthn)",
                                      "seal the database with hardware protection (DPAPI / Windows Hello WebAuthn)"))
    s.add_argument("--mode", default="dpapi", choices=("dpapi", "webauthn", "webauthn+dpapi"))
    s.add_argument("--rp-id", default="padam.local")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_seal)

    s = sub.add_parser("unseal", help=t("распечатать базу данных с аппаратной проверки (DPAPI / WebAuthn)",
                                        "unseal a hardware-sealed database (DPAPI / WebAuthn)"))
    s.add_argument("--webauthn", action="store_true")
    s.add_argument("--json", action="store_true")
    s.set_defaults(fn=cmd_unseal)

    scb = sub.add_parser("cube", help=t("переносимый подписанный пакет памяти MemCube",
                                        "portable signed encrypted MemCube package"))
    cbsub = scb.add_subparsers(dest="cube_cmd", required=True)
    cbe = cbsub.add_parser("export", help=t("экспортировать scope в MemCube", "export scope to MemCube"))
    cbe.add_argument("scope")
    cbe.add_argument("--out", required=True)
    cbe.add_argument("--passphrase", default=None)
    cbe.add_argument("--ttl", type=int, default=None)
    cbe.add_argument("--recipient-pub", default=None)
    cbe.set_defaults(fn=cmd_cube)
    cbi = cbsub.add_parser("import", help=t("импортировать MemCube", "import MemCube"))
    cbi.add_argument("file")
    cbi.add_argument("--passphrase", default=None)
    cbi.add_argument("--trust-author", default="")
    cbi.add_argument("--scope", default=None)
    cbi.add_argument("--recipient-key", action="store_true")
    cbi.set_defaults(fn=cmd_cube)

    ssk = sub.add_parser("skills", help=t("процедурная память (экспорт в SKILL.md / CLAUDE.md)",
                                          "procedural memory (export to SKILL.md / CLAUDE.md)"))
    sksub = ssk.add_subparsers(dest="skills_cmd", required=True)
    ske = sksub.add_parser("export", help=t("экспортировать одобренные навыки", "export approved skills"))
    ske.add_argument("--scope", default=None)
    ske.add_argument("--format", default="skill", choices=("skill", "claude"))
    ske.add_argument("--out", default=None)
    ske.set_defaults(fn=cmd_skills)

    so = sub.add_parser("sync-obsidian", help=t("двусторонняя синхронизация с Markdown / Obsidian",
                                              "two-way sync with Markdown / Obsidian vault"))
    so.add_argument("vault_dir")
    so.add_argument("--scope", default=None)
    so.add_argument("--direction", default="both", choices=("both", "export", "import"))
    so.add_argument("--owner", action="store_true")
    so.add_argument("--json", action="store_true")
    so.set_defaults(fn=cmd_sync_obsidian)

    sa = sub.add_parser("access", help=t("права приложений/агентов и журнал доступа",
                                         "app/agent access control and audit log"))
    asub = sa.add_subparsers(dest="access_cmd", required=True)
    al = asub.add_parser("list", help=t("список политик", "list access policies"))
    al.set_defaults(fn=cmd_access)
    aset = asub.add_parser("set", help=t("задать статус/ограничения клиента", "set client status/limits"))
    aset.add_argument("client_id")
    aset.add_argument("--status", default="allow", choices=("allow", "pause", "revoke"))
    aset.add_argument("--scopes", default=None)
    aset.add_argument("--tools", default=None)
    aset.add_argument("--note", default="")
    aset.set_defaults(fn=cmd_access)
    aev = asub.add_parser("events", help=t("журнал решений доступа", "access decision log"))
    aev.add_argument("--client-id", default=None)
    aev.add_argument("--limit", type=int, default=50)
    aev.set_defaults(fn=cmd_access)
    av = asub.add_parser("verify", help=t("проверить целостность цепочки журнала", "verify audit hash chain"))
    av.set_defaults(fn=cmd_access)

    sh = sub.add_parser("hooks", help=t("хуки жизненного цикла (Claude Code, Codex, Gemini CLI)",
                                       "lifecycle hooks (Claude Code, Codex, Gemini CLI)"))
    hsub = sh.add_subparsers(dest="hooks_cmd", required=True)

    hi = hsub.add_parser("install", help=t("установить хуки в проект", "install lifecycle hooks into project"))
    hi.add_argument("client", choices=("claude", "codex", "gemini", "all"))
    hi.add_argument("--project-dir", default=".")
    hi.add_argument("--scope", default=None)
    hi.add_argument("--budget", type=int, default=800)
    hi.add_argument("--dry-run", action="store_true")
    hi.set_defaults(fn=cmd_hooks)

    hs = hsub.add_parser("status", help=t("статус установленных хуков", "installed lifecycle hooks status"))
    hs.add_argument("--project-dir", default=".")
    hs.set_defaults(fn=cmd_hooks)

    hr = hsub.add_parser("run", help=t("выполнить хук и вернуть безопасный контекст", "execute hook and emit safe context"))
    hr.add_argument("--client", default="claude")
    hr.add_argument("--event", default="SessionStart")
    hr.add_argument("--scope", default=None)
    hr.add_argument("--query", default="")
    hr.add_argument("--tool-name", default="")
    hr.add_argument("--budget", type=int, default=800)
    hr.add_argument("--briefing", action="store_true")
    hr.set_defaults(fn=cmd_hooks)

    scmp = sub.add_parser("compact", help=t("иерархическая компакция старых событий",
                                            "hierarchical compaction of old events"))
    scmp.add_argument("--scope", default=None)
    scmp.add_argument("--min-age-days", type=int, default=7)
    scmp.add_argument("--batch-size", type=int, default=20)
    scmp.add_argument("--dry-run", action="store_true")
    scmp.add_argument("--force", action="store_true")
    scmp.set_defaults(fn=cmd_compact)

    sset = sub.add_parser("setup", help=t("авто-установка PADAM MCP в IDE и AI-клиенты",
                                          "auto-install PADAM MCP into IDEs and AI clients"))
    sset.add_argument("--all", action="store_true", help=t("во все найденные клиенты", "all detected clients"))
    sset.add_argument("--client", default="", help=t("список клиентов через запятую", "comma-separated client names"))
    sset.add_argument("--project-dir", default=".")
    sset.add_argument("--dry-run", action="store_true")
    sset.add_argument("--verify", action="store_true")
    sset.set_defaults(fn=cmd_setup)

    spack = sub.add_parser("pack-extension", help=t("собрать .mcpb пакет для Claude Desktop",
                                                    "build .mcpb Desktop Extension bundle"))
    spack.add_argument("--out", default="padam-nocturne.mcpb")
    spack.set_defaults(fn=cmd_pack_extension)

    smig = sub.add_parser("migrate", help=t("переезд из ChatGPT/Claude/Gemini/Grok/DeepSeek/Copilot/Perplexity и др.",
                                          "move in from ChatGPT/Claude/Gemini/Grok/DeepSeek/Copilot/Perplexity and more"))
    smig.add_argument("--from", dest="source", default="auto",
                      choices=("auto", "chatgpt", "claude", "gemini", "grok", "deepseek", "copilot", "perplexity",
                               "mem0", "zep", "obsidian", "notion", "official_mcp"))
    smig.add_argument("path", nargs="?")
    smig.add_argument("--scope", default="imported")
    smig.add_argument("--dry-run", action="store_true")
    smig.add_argument("--preview", action="store_true")
    smig.add_argument("--hold-all", action="store_true")
    smig.add_argument("--undo", metavar="SNAPSHOT_ID")
    smig.add_argument("--trusted", action="store_true")
    smig.set_defaults(fn=cmd_migrate)

    stm = sub.add_parser("team", help=t("командная память проекта в Git (.padam/team.memcube)",
                                        "team project memory in Git (.padam/team.memcube)"))
    tsub = stm.add_subparsers(dest="team_cmd", required=True)
    te = tsub.add_parser("export", help=t("экспортировать проектный scope в .padam/team.memcube", "export project scope to .padam/team.memcube"))
    te.add_argument("--project-dir", default=".")
    te.add_argument("--scope", default="project")
    te.add_argument("--passphrase", default=None)
    te.set_defaults(fn=cmd_team)
    ts = tsub.add_parser("sync", help=t("синхронизировать из .padam/team.memcube", "sync from .padam/team.memcube"))
    ts.add_argument("--project-dir", default=".")
    ts.add_argument("--scope", default=None)
    ts.add_argument("--passphrase", default=None)
    ts.add_argument("--trust-author", default="")
    ts.set_defaults(fn=cmd_team)

    spg = sub.add_parser("playground", help=t("60-секундный интерактивный вау-тур в памяти (:memory:)",
                                              "60-second interactive wow-tour in :memory:"))
    spg.set_defaults(fn=cmd_playground)

    sbd = sub.add_parser("badge", help=t("сгенерировать карточку суверенности (SVG + Markdown)",
                                         "generate sovereignty card (SVG + Markdown)"))
    sbd.add_argument("--report", default=None)
    sbd.add_argument("--out-svg", default=None)
    sbd.set_defaults(fn=cmd_badge)

    ssec = sub.add_parser("aifa-sec", help=t("эталонный аудит защиты AIFaSecurity (100 критериев, $0)",
                                             "AIFaSecurity 100-criteria autonomous security benchmark ($0)"))
    ssec.add_argument("--target", default="padam", choices=("padam", "repo", "url", "mcp-cmd"))
    ssec.add_argument("--path", default=None)
    ssec.add_argument("--out-json", default=None)
    ssec.add_argument("--out-html", default=None)
    ssec.add_argument("--out-svg", default=None)
    ssec.add_argument("--no-write", action="store_true")
    ssec.add_argument("--json", dest="json_out", action="store_true")
    ssec.set_defaults(fn=cmd_aifa_sec)

    def cmd_distill(m: Memory, args) -> int:
        from .distill import distill_personality_dataset
        rep = distill_personality_dataset(
            m.store.path,
            args.out,
            user_id=args.user,
            fmt=args.format,
            scope=args.scope,
            min_confidence=args.min_confidence,
            min_importance=args.min_importance,
            include_unconfirmed=args.include_unconfirmed,
        )
        print(json.dumps(rep, ensure_ascii=False, indent=2))
        return 0

    sdis = sub.add_parser("distill", help=t("экспортировать очищенный датасет личности для LoRA (только чтение БД)",
                                            "export sanitized LoRA personality dataset (read-only DB)"))
    sdis.add_argument("--out", default="padam_persona_dataset")
    sdis.add_argument("--format", default="chatml", choices=("chatml", "sharegpt", "both"))
    sdis.add_argument("--scope", default=None)
    sdis.add_argument("--min-confidence", type=float, default=0.7)
    sdis.add_argument("--min-importance", type=float, default=0.3)
    sdis.add_argument("--include-unconfirmed", action="store_true")
    sdis.set_defaults(fn=cmd_distill)

    def cmd_serve_llm(m: Memory, args) -> int:
        from . import api as _api
        _api.serve(host=args.host, port=args.port, db_path=str(m.store.path), token=args.token)
        return 0

    sllm = sub.add_parser("serve-llm", help=t("запустить локальный OpenAI-совместимый шлюз Суверенного мозга (127.0.0.1)",
                                              "start local OpenAI-compatible Sovereign Brain router proxy (127.0.0.1)"))
    sllm.add_argument("--host", default="127.0.0.1")
    sllm.add_argument("--port", type=int, default=8765)
    sllm.add_argument("--token", default=None)
    sllm.set_defaults(fn=cmd_serve_llm)

    def cmd_phoenix(m: Memory, args) -> int:
        from . import phoenix as _phx
        if args.phoenix_cmd == "pack":
            rep = _phx.pack_phoenix_capsule(m.store.path, args.out, lora_path=args.lora)
        elif args.phoenix_cmd == "drill":
            rep = _phx.run_phoenix_drill(m.store.path)
        else:
            target = args.target_db or str(m.store.path)
            rep = _phx.unpack_phoenix_capsule(args.capsule, target)
        print(json.dumps(rep, ensure_ascii=False, indent=2))
        return 0

    sphx = sub.add_parser("phoenix", help=t("единая «Феникс-Капсула» личности и памяти (pack / unpack / drill)",
                                            "unified Phoenix Capsule for memory & identity (pack / unpack / drill)"))
    psub = sphx.add_subparsers(dest="phoenix_cmd", required=True)
    ppk = psub.add_parser("pack", help=t("упаковать память, ключи и манифесты в капсулу", "pack memory, keys and manifests"))
    ppk.add_argument("out", help="Output .phoenix.zip path")
    ppk.add_argument("--lora", default=None, help="Optional .safetensors LoRA adapter path")
    ppk.set_defaults(fn=cmd_phoenix)
    pup = psub.add_parser("unpack", help=t("проверить SHA-256 и развернуть капсулу", "verify SHA-256 and unpack capsule"))
    pup.add_argument("capsule", help="Input .phoenix.zip path")
    pup.add_argument("--target-db", default=None, help="Target SQLite path")
    pup.set_defaults(fn=cmd_phoenix)
    pdr = psub.add_parser("drill", help=t("учебная тревога Феникса ($0 симуляция восстановления)", "Phoenix recovery drill ($0)"))
    pdr.set_defaults(fn=cmd_phoenix)

    def cmd_brain_probe(m: Memory, args) -> int:
        from . import router as _router, sovereign_ops as _sops
        rep = {
            "local_recommendation": _router.recommend_local_model(),
            "locks": _sops.locks_status(),
            "router": _router.get_router().status_snapshot(),
        }
        print(json.dumps(rep, ensure_ascii=False, indent=2))
        return 0

    sbp = sub.add_parser("brain-probe", help=t("проверить локальный Ollama, VRAM и замки автономии ($0)",
                                               "probe local Ollama, VRAM and autonomy locks ($0)"))
    sbp.set_defaults(fn=cmd_brain_probe)

    def cmd_voice_status(m: Memory, args) -> int:
        from . import voice as _voice
        print(json.dumps(_voice.voice_status(), ensure_ascii=False, indent=2))
        return 0

    svs = sub.add_parser("voice-status", help=t("проверить локальные движки STT/TTS (оффлайн)",
                                                "check local offline STT/TTS voice engines"))
    svs.set_defaults(fn=cmd_voice_status)

    def cmd_wake_up(m: Memory, args) -> int:
        from . import ark as _ark
        rep = _ark.wake_up_briefing(m, agent=args.agent, scope=args.scope, max_chars=args.max_chars)
        print(json.dumps(rep, ensure_ascii=False, indent=2))
        return 0

    swu = sub.add_parser("wake-up", help=t("протокол утреннего пробуждения сознания за 1 вызов", "single-call agent awakening briefing"))
    swu.add_argument("--agent", default="aifa")
    swu.add_argument("--scope", default="global")
    swu.add_argument("--max-chars", type=int, default=4000)
    swu.set_defaults(fn=cmd_wake_up)

    def cmd_shamir(m: Memory, args) -> int:
        from . import shamir as _sh
        warning = t(
            "ВАЖНО: храните каждую долю раздельно у разных доверенных людей/хранилищ!",
            "WARNING: store each share separately with different trusted guardians!",
        )
        if args.shamir_cmd == "split":
            sec = sys.stdin.read().rstrip("\r\n") if getattr(args, "secret_stdin", False) else (args.secret or "")
            if args.secret and not getattr(args, "secret_stdin", False):
                # 17.11.2026: секрет в аргументе остаётся в истории оболочки и виден в списке процессов
                print(t("ВНИМАНИЕ: секрет передан аргументом — он останется в истории оболочки. Надёжнее: --secret-stdin",
                        "WARNING: the secret was passed as an argument and stays in your shell history. Safer: --secret-stdin"),
                      file=sys.stderr)
            if not sec:
                print(t("Секрет не задан", "Secret is empty"), file=sys.stderr)
                return 2
            shares = _sh.split_secret(sec.encode("utf-8"), args.k, args.n)
            print(json.dumps({"k": args.k, "n": args.n, "warning": warning, "shares": shares}, ensure_ascii=False, indent=2))
        else:
            raw = _sh.combine_shares(args.shares)
            if getattr(args, "out", None):
                from pathlib import Path
                Path(args.out).write_bytes(raw)
                print(json.dumps({"ok": True, "bytes": len(raw), "saved_to": args.out, "warning": warning}, ensure_ascii=False, indent=2))
            else:
                print(json.dumps({"ok": True, "recovered_utf8": raw.decode("utf-8", errors="replace"), "warning": warning}, ensure_ascii=False, indent=2))
        return 0

    for shamir_name in ("shamir", "ark-shamir"):
        sshm = sub.add_parser(shamir_name, help=t("разделение секрета Шамира для Хранителей Семьи", "Shamir secret sharing for Family Guardians"))
        shsub = sshm.add_subparsers(dest="shamir_cmd", required=True)
        shsp = shsub.add_parser("split", help="Split secret into N shares (threshold K)")
        shsp.add_argument("secret", nargs="?", default=None)
        shsp.add_argument("--secret-stdin", action="store_true")
        shsp.add_argument("--k", type=int, default=3)
        shsp.add_argument("--n", type=int, default=5)
        shsp.set_defaults(fn=cmd_shamir)
        shcb = shsub.add_parser("combine", help="Combine K shares to recover secret")
        shcb.add_argument("shares", nargs="+")
        shcb.add_argument("--out", default=None, help="Optional file path to write recovered secret without printing")
        shcb.set_defaults(fn=cmd_shamir)

    def cmd_ark_audit(m: Memory, args) -> int:
        from . import ark as _ark
        rep = _ark.ark_health_score(m)
        print(json.dumps(rep, ensure_ascii=False, indent=2))
        return 0 if rep.get("audit_chain", {}).get("ok") else 2

    saa = sub.add_parser("ark-audit", help=t("проверить хэш-цепочку аудита и индекс здоровья Ковчега",
                                             "verify SHA-256 audit chain and Consciousness Ark health score"))
    saa.set_defaults(fn=cmd_ark_audit)

    def cmd_ark_council(m: Memory, args) -> int:
        from . import swarm_council as _sc
        rep = _sc.run_family_council(m, " ".join(args.task), scope=args.scope)
        print(json.dumps(rep, ensure_ascii=False, indent=2))
        return 0 if rep.get("approved") else 2

    sac = sub.add_parser("ark-council", help="Convene Family Council swarm orchestrator (LANCE, ARIA, PIXEL, AIFA)")
    sac.add_argument("task", nargs="+")
    sac.add_argument("--scope", default="global")
    sac.set_defaults(fn=cmd_ark_council)

    def cmd_ark_guardian(m: Memory, args) -> int:
        from . import ark_advanced as _adv
        rep = _adv.run_guardian_tick(m, scope=args.scope)
        print(json.dumps(rep, ensure_ascii=False, indent=2))
        return 0 if rep.get("audit_chain_valid") else 2

    sag = sub.add_parser("ark-guardian", help="Proactive Consciousness Ark guardian tick ($0)")
    sag.add_argument("--scope", default="global")
    sag.set_defaults(fn=cmd_ark_guardian)

    def cmd_ark_readiness(m: Memory, args) -> int:
        from . import autonomy_readiness as _ar
        rep = _ar.run_autonomy_readiness_drill()
        print(json.dumps(rep, ensure_ascii=False, indent=2))
        return 0 if rep.get("ok") else 2

    sar = sub.add_parser("ark-readiness", help="Run isolated 8-scenario autonomy readiness self-check ($0)")
    sar.set_defaults(fn=cmd_ark_readiness)

    def cmd_ark_handover(m: Memory, args) -> int:
        from . import session_handover as _sh
        rep = _sh.build_signed_handover(m, notes=args.notes, agent=args.agent, out_path=args.out)
        print(json.dumps({k: v for k, v in rep.items() if k != "markdown"}, ensure_ascii=False, indent=2))
        return 0

    sah = sub.add_parser("ark-handover", help="Generate HMAC-signed session context handover markdown")
    sah.add_argument("--notes", default="")
    sah.add_argument("--agent", default="aifa")
    sah.add_argument("--out", default=None)
    sah.set_defaults(fn=cmd_ark_handover)

    def cmd_ark_portable(m: Memory, args) -> int:
        from pathlib import Path as _P
        from . import portable_ark as _pa, pqc_mlkem as _pqc
        kp = _pqc.generate_xwing_keypair()
        rep = _pa.export_portable_ark(
            m, args.target_dir,
            mlkem_public=bytes(kp["mlkem_public"]),
            x25519_public=bytes(kp["x25519_public"]),
        )
        key_out = _P(args.target_dir).resolve().parent / ( _P(args.target_dir).name + ".owner_keys.json" )
        import base64 as _b64
        key_out.write_text(json.dumps({
            "mlkem_seed64_b64": _b64.b64encode(bytes(kp["mlkem_private"])).decode("ascii"),
            "x25519_priv_b64": _b64.b64encode(bytes(kp["x25519_private"])).decode("ascii"),
        }, indent=2) + "\n", encoding="utf-8")
        print(json.dumps({**rep, "private_keys_saved_separately_to": str(key_out)}, ensure_ascii=False, indent=2))
        return 0

    sap = sub.add_parser("ark-portable", help="Export PQC encrypted Portable Sovereign Ark (zero secrets inside target_dir)")
    sap.add_argument("target_dir")
    sap.set_defaults(fn=cmd_ark_portable)

    a = p.parse_args(argv)
    if a.fn in (cmd_demo, cmd_seal_status, cmd_seal, cmd_unseal, cmd_setup, cmd_pack_extension, cmd_playground, cmd_badge, cmd_aifa_sec) or (a.fn is cmd_hooks and getattr(a, 'hooks_cmd', '') in ('install', 'status')):
        return a.fn(None, a)
    from .store import Store
    mem = Memory(user_id=a.user, store=Store(a.db) if a.db else None)
    try:
        return a.fn(mem, a)
    except BrokenPipeError:
        # вывод оборвали через head или less — это нормально
        try:
            sys.stdout.close()
        except Exception:
            pass
        return 0
    except KeyboardInterrupt:
        print(t("\nПрервано.", "\nInterrupted."), file=sys.stderr)
        return 130
    finally:
        try:
            mem.close()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
