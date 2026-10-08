"""Командная строка PADAM.

    padam remember "текст"        запомнить
    padam recall "запрос"         вспомнить
    padam log "текст"             записать в буфер (без консолидации)
    padam sleep                   запустить цикл консолидации
    padam stats                   состояние памяти
    padam timeline <id>           история версий записи
    padam forget <id>             отозвать запись
"""

from __future__ import annotations

import argparse
import json
import sys

from . import config
from .memory import Memory
from .nocturne import Nocturne

GREEN, RED, DIM, RESET = "\033[32m", "\033[31m", "\033[2m", "\033[0m"


def cmd_remember(m: Memory, a) -> int:
    outcome, mid = m.remember(a.text, kind=a.kind, importance=a.importance,
                              scope=a.scope)
    labels = {
        "created": "запомнено",
        "duplicate": "уже известно, уверенность повышена",
        "merged": "уточнено, прежняя версия сохранена в истории",
        "superseded": "заменено, прежняя версия сохранена в истории",
        "coexists": "добавлено рядом с прежним",
    }
    print(f"{GREEN}{labels.get(outcome, outcome)}{RESET}")
    print(f"{DIM}id: {mid}{RESET}")
    return 0


def cmd_recall(m: Memory, a) -> int:
    found = m.recall(a.query, scope=a.scope, kind=a.kind, limit=a.limit)
    if not found:
        print("Ничего не найдено.")
        return 0
    for r in found:
        print(f"{GREEN}{r.score:.3f}{RESET}  [{r.kind}]  {r.content}")
        if a.explain:
            print(f"        {DIM}{r.explain()}{RESET}")
            print(f"        {DIM}id: {r.id}{RESET}")
    return 0


def cmd_log(m: Memory, a) -> int:
    eid = m.log(a.text, priority=a.priority, scope=a.scope)
    print(f"{DIM}в буфер: {eid}{RESET}")
    return 0


def cmd_sleep(m: Memory, a) -> int:
    report = Nocturne(m, batch_size=a.batch, dry_run=a.dry_run).run()
    if not report.get("episodes_sampled"):
        print(report.get("note", "нечего консолидировать"))
        return 0

    print("\nNOCTURNE — цикл консолидации")
    print("=" * 52)
    print(f"Обработано эпизодов:  {report['episodes_sampled']}")
    print(f"Коррекция смещения:   beta = {report['beta']}")
    print()
    ok_all = True
    for label, ok, detail in report["checks"]:
        mark = f"{GREEN}OK {RESET}" if ok else f"{RED}!!!{RESET}"
        ok_all &= ok
        print(f"[{mark}] {label:26s} {detail}")
    print(f"\nИсходы:   {report['outcomes']}")
    print(f"По типам: {report['kinds']}")

    if not ok_all:
        print(f"\n{RED}Не все проверки пройдены.{RESET}")
        print("Если пробит потолок острых — снизить K_MAX в config.py.")
        print("Если низкое разнообразие — проверить классификатор типов:")
        print("скорее всего всё падает в 'fact'.")
    return 0


def cmd_stats(m: Memory, a) -> int:
    s = m.stats()
    print(f"База:        {s['db']}")
    print(f"Эмбеддинги:  {s['backend']}"
          + ("" if s["backend"] == "ollama" else
             f"  {DIM}(Ollama не найдена, работает встроенный метод){RESET}"))
    print()
    print(f"Активных записей:     {s['active']}")
    print(f"Замещённых:           {s['superseded']}")
    print(f"Отозванных:           {s['revoked']}")
    print(f"Эпизодов в буфере:    {s['episodes_pending']}")
    if s["by_kind"]:
        print("\nПо типам:")
        for k, n in sorted(s["by_kind"].items(), key=lambda x: -x[1]):
            hl = config.HALF_LIFE_DAYS.get(k)
            note = "не затухает" if hl is None else f"полураспад {hl} дн."
            print(f"  {k:12s} {n:4d}   {DIM}{note}{RESET}")
    return 0


def cmd_timeline(m: Memory, a) -> int:
    chain = m.timeline(a.id)
    if not chain:
        print("Запись не найдена.")
        return 1
    for i, row in enumerate(chain):
        arrow = "" if i == 0 else "  ↓\n"
        state = "" if row["status"] == "active" else f" [{row['status']}]"
        print(f"{arrow}{row['created_at'][:19]}{state}")
        print(f"  {row['content'] or '(содержание затёрто)'}")
    return 0


def cmd_export(m: Memory, a) -> int:
    import json
    payload = m.export(include_superseded=not a.active_only, scope=a.scope)
    text = json.dumps(payload, ensure_ascii=False, indent=2)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(text)
        c = payload["counts"]
        print(f"{GREEN}Выгружено{RESET} в {a.out}: "
              f"записей {c['memory']}, сессий {c['sessions']}")
    else:
        print(text)
    return 0


def cmd_import(m: Memory, a) -> int:
    import json
    with open(a.file, encoding="utf-8") as f:
        payload = json.load(f)
    n = m.import_(payload, overwrite=a.overwrite)
    print(f"{GREEN}Загружено записей: {n}{RESET}")
    return 0


def cmd_confirm(m: Memory, a) -> int:
    if m.confirm(a.id):
        print(f"{GREEN}Подтверждено.{RESET} Свежесть обновлена, уверенность выше.")
        return 0
    print("Запись не найдена.")
    return 1


def cmd_refute(m: Memory, a) -> int:
    m.refute(a.id, drop=a.drop)
    print(f"{GREEN}Уверенность снижена.{RESET} Свежесть не обновлялась.")
    return 0


def cmd_forget(m: Memory, a) -> int:
    if m.revoke(a.id):
        print(f"{GREEN}Отозвано.{RESET} Содержание затёрто, хеш и якорь сохранены.")
        print(f"{DIM}Если запись была заякорена, ключ уничтожен — "
              f"данные в цепи нечитаемы навсегда.{RESET}")
        return 0
    print("Запись не найдена.")
    return 1


def cmd_l3(m: Memory, a) -> int:
    """L3: новое → пакет шифротекстов в Arweave → корень Меркла в Solana."""
    import os
    from . import anchor
    wallet = a.arweave_wallet or os.environ.get("PADAM_ARWEAVE_WALLET")
    keypair = a.solana_keypair or os.environ.get("PADAM_SOLANA_KEYPAIR")
    if not a.dry_run and not (wallet and keypair):
        print("нужны --arweave-wallet и --solana-keypair (или PADAM_ARWEAVE_WALLET / PADAM_SOLANA_KEYPAIR)")
        return 2
    save_dir = str(m.store.path) + ".l3"
    rep = anchor.run_l3(
        m, dry_run=a.dry_run, network=a.network, save_dir=save_dir,
        uploader=(lambda data, tags: anchor.turbo_upload(data, wallet, tags, a.turbo_sdk)) if wallet else None,
        anchorer=(lambda memo: anchor.solana_memo(memo, keypair, a.network)) if keypair else None)
    print(json.dumps(rep, ensure_ascii=False, indent=2))
    return 0


def cmd_l3_verify(m: Memory, a) -> int:
    """Независимая проверка закрепления: Arweave + заметка в Solana, без доверия к базе."""
    from . import anchor
    anchor.ensure_schema(m)
    row = m.store.one("SELECT * FROM l3_anchor ORDER BY created_at DESC LIMIT 1") if not a.anchor else         m.store.one("SELECT * FROM l3_anchor WHERE id = ?", (a.anchor,))
    if not row:
        print("закреплений нет"); return 1
    import hashlib
    from pathlib import Path
    memo = anchor.read_memo(row["solana_sig"], row["network"])
    remote = anchor.fetch_arweave(row["arweave_tx"])
    local_path = Path(str(m.store.path) + ".l3") / f"{row['id']}.json"
    local = local_path.read_bytes() if local_path.exists() else None
    payload = remote or local
    if payload is None:
        print(json.dumps({"ok": None, "status": "ждёт шлюза Arweave, локальной копии нет",
                          "memo_in_chain": memo}, ensure_ascii=False, indent=2))
        return 3
    v = anchor.verify_bundle(payload, memo)
    v.update(arweave_tx=row["arweave_tx"], solana_sig=row["solana_sig"], network=row["network"],
             source="arweave" if remote else "локальная копия (шлюз ещё не разнёс)",
             sha256_matches_db=hashlib.sha256(payload).hexdigest() == row["bundle_sha256"])
    v["ok"] = bool(v["ok"] and v["sha256_matches_db"])
    print(json.dumps(v, ensure_ascii=False, indent=2))
    return 0 if v["ok"] else 1


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="padam", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--user", default="default")
    p.add_argument("--db", default=None, help="путь к файлу базы")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("remember", help="запомнить")
    s.add_argument("text")
    s.add_argument("--kind", choices=config.KINDS, default=None)
    s.add_argument("--importance", type=float, default=0.5)
    s.add_argument("--scope", default="global")
    s.set_defaults(fn=cmd_remember)

    s = sub.add_parser("recall", help="вспомнить")
    s.add_argument("query")
    s.add_argument("--kind", choices=config.KINDS, default=None)
    s.add_argument("--limit", type=int, default=5)
    s.add_argument("--scope", default="global")
    s.add_argument("--explain", action="store_true", help="показать разбор оценки")
    s.set_defaults(fn=cmd_recall)

    s = sub.add_parser("log", help="записать в буфер")
    s.add_argument("text")
    s.add_argument("--priority", type=float, default=1.0)
    s.add_argument("--scope", default="global")
    s.set_defaults(fn=cmd_log)

    s = sub.add_parser("sleep", help="цикл консолидации")
    s.add_argument("--batch", type=int, default=256)
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(fn=cmd_sleep)

    s = sub.add_parser("stats", help="состояние памяти")
    s.set_defaults(fn=cmd_stats)

    s = sub.add_parser("timeline", help="история версий записи")
    s.add_argument("id")
    s.set_defaults(fn=cmd_timeline)

    s = sub.add_parser("export", help="выгрузить всю память в JSON")
    s.add_argument("--out", default=None, help="файл (по умолчанию на экран)")
    s.add_argument("--scope", default=None)
    s.add_argument("--active-only", action="store_true")
    s.set_defaults(fn=cmd_export)

    s = sub.add_parser("import", help="загрузить выгрузку обратно")
    s.add_argument("file")
    s.add_argument("--overwrite", action="store_true")
    s.set_defaults(fn=cmd_import)

    s = sub.add_parser("confirm", help="запись оказалась верной")
    s.add_argument("id")
    s.set_defaults(fn=cmd_confirm)

    s = sub.add_parser("refute", help="запись оказалась неверной")
    s.add_argument("id")
    s.add_argument("--drop", type=float, default=0.3)
    s.set_defaults(fn=cmd_refute)

    s = sub.add_parser("serve", help="запустить MCP-сервер (stdio)")
    s.set_defaults(fn=lambda m, a: __import__("padam.mcp_server",
                                              fromlist=["main"]).main())

    s = sub.add_parser("api", help="запустить REST API")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8077)
    s.add_argument("--token", default=None)
    s.set_defaults(fn=lambda m, a: __import__("padam.api", fromlist=["main"])
                   .main(["--host", a.host, "--port", str(a.port)]
                         + (["--token", a.token] if a.token else [])))

    s = sub.add_parser("l3", help="закрепить память: Arweave + корень Меркла в Solana")
    s.add_argument("--network", choices=["devnet", "mainnet"], default="devnet")
    s.add_argument("--arweave-wallet", default=None)
    s.add_argument("--solana-keypair", default=None)
    s.add_argument("--turbo-sdk", default=None, help="каталог node_modules с @ardrive/turbo-sdk")
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(fn=cmd_l3)

    s = sub.add_parser("l3-verify", help="проверить закрепление по Arweave и Solana")
    s.add_argument("--anchor", default=None)
    s.set_defaults(fn=cmd_l3_verify)

    s = sub.add_parser("forget", help="отозвать запись")
    s.add_argument("id")
    s.set_defaults(fn=cmd_forget)

    a = p.parse_args(argv)
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
        print("\nПрервано.", file=sys.stderr)
        return 130
    finally:
        try:
            mem.close()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
