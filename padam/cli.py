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
                              scope=a.scope)
    labels = {
        "created": t("запомнено", "remembered"),
        "duplicate": t("уже известно, уверенность повышена", "already known; confidence raised"),
        "merged": t("уточнено, прежняя версия сохранена в истории",
                    "refined; the previous version is kept in history"),
        "superseded": t("заменено, прежняя версия сохранена в истории",
                        "replaced; the previous version is kept in history"),
        "coexists": t("добавлено рядом с прежним", "stored alongside a similar record"),
    }
    print(f"{GREEN}{labels.get(outcome, outcome)}{RESET}")
    print(f"{DIM}id: {mid}{RESET}")
    return 0


def cmd_recall(m: Memory, a) -> int:
    found = m.recall(a.query, scope=a.scope, kind=a.kind, limit=a.limit)
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
    print(t(f"Эмбеддинги:  {s['backend']}", f"Embeddings:  {s['backend']}")
          + ("" if s["backend"] == "ollama" else
             f"  {DIM}{t('(Ollama не найдена, работает встроенный метод)', '(Ollama not found, built-in method in use)')}{RESET}"))
    print()
    print(t(f"Активных записей:     {s['active']}", f"Active records:       {s['active']}"))
    print(t(f"Замещённых:           {s['superseded']}", f"Superseded:           {s['superseded']}"))
    print(t(f"Отозванных:           {s['revoked']}", f"Revoked:              {s['revoked']}"))
    print(t(f"Эпизодов в буфере:    {s['episodes_pending']}", f"Episodes in buffer:   {s['episodes_pending']}"))
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
    with open(a.file, encoding="utf-8") as f:
        payload = json.load(f)
    n = m.import_(payload, overwrite=a.overwrite)
    print(f"{GREEN}{t('Загружено записей', 'Records imported')}: {n}{RESET}")
    return 0


def cmd_confirm(m: Memory, a) -> int:
    if m.confirm(a.id):
        print(t(f"{GREEN}Подтверждено.{RESET} Свежесть обновлена, уверенность выше.",
                f"{GREEN}Confirmed.{RESET} Freshness renewed, confidence raised."))
        return 0
    _not_found()
    return 1


def cmd_refute(m: Memory, a) -> int:
    m.refute(a.id, drop=a.drop)
    print(t(f"{GREEN}Уверенность снижена.{RESET} Свежесть не обновлялась.",
            f"{GREEN}Confidence lowered.{RESET} Freshness not renewed."))
    return 0


def cmd_forget(m: Memory, a) -> int:
    if m.revoke(a.id):
        print(t(f"{GREEN}Отозвано.{RESET} Содержание затёрто, хеш и якорь сохранены.",
                f"{GREEN}Revoked.{RESET} Content wiped; hash and anchor kept."))
        print(f"{DIM}" + t("Если запись была заякорена, ключ уничтожен — данные в цепи нечитаемы навсегда.",
                           "If the record was anchored, its key is destroyed — the on-chain data is unreadable forever.")
              + f"{RESET}")
        return 0
    _not_found()
    return 1


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
        anchorer=(lambda memo: anchor.solana_memo(memo, keypair, a.network)) if keypair else None)
    print(json.dumps(rep, ensure_ascii=False, indent=2))
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
    print(json.dumps(итог, ensure_ascii=False))
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
    print(json.dumps({"перезавёрнуто": n}, ensure_ascii=False))
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
    p.add_argument("--user", default="default")
    p.add_argument("--db", default=None, help=t("путь к файлу базы", "path to the database file"))
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("remember", help=t("запомнить", "store a memory"))
    s.add_argument("text")
    s.add_argument("--kind", choices=config.KINDS, default=None)
    s.add_argument("--importance", type=float, default=0.5)
    s.add_argument("--scope", default="global")
    s.set_defaults(fn=cmd_remember)

    s = sub.add_parser("recall", help=t("вспомнить", "recall by meaning, words and identifiers"))
    s.add_argument("query")
    s.add_argument("--kind", choices=config.KINDS, default=None)
    s.add_argument("--limit", type=int, default=5)
    s.add_argument("--scope", default="global")
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

    s = sub.add_parser("timeline", help=t("история версий записи", "version history of a record"))
    s.add_argument("id")
    s.set_defaults(fn=cmd_timeline)

    s = sub.add_parser("export", help=t("выгрузить всю память в JSON", "export the whole memory as JSON"))
    s.add_argument("--out", default=None, help=t("файл (по умолчанию на экран)", "file (default: print)"))
    s.add_argument("--scope", default=None)
    s.add_argument("--active-only", action="store_true")
    s.set_defaults(fn=cmd_export)

    s = sub.add_parser("import", help=t("загрузить выгрузку обратно", "load an export back"))
    s.add_argument("file")
    s.add_argument("--overwrite", action="store_true")
    s.set_defaults(fn=cmd_import)

    s = sub.add_parser("confirm", help=t("запись оказалась верной", "a record proved correct"))
    s.add_argument("id")
    s.set_defaults(fn=cmd_confirm)

    s = sub.add_parser("refute", help=t("запись оказалась неверной", "a record proved wrong"))
    s.add_argument("id")
    s.add_argument("--drop", type=float, default=0.3)
    s.set_defaults(fn=cmd_refute)

    s = sub.add_parser("serve", help=t("запустить MCP-сервер (stdio)", "start the MCP server (stdio)"))
    s.set_defaults(fn=lambda m, a: __import__("padam.mcp_server",
                                              fromlist=["main"]).main())

    s = sub.add_parser("api", help=t("запустить REST API", "start the REST API"))
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8077)
    s.add_argument("--token", default=None)
    s.set_defaults(fn=lambda m, a: __import__("padam.api", fromlist=["main"])
                   .main(["--host", a.host, "--port", str(a.port)]
                         + (["--token", a.token] if a.token else [])))

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
    s.set_defaults(fn=cmd_l3)

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
        print(t("\nПрервано.", "\nInterrupted."), file=sys.stderr)
        return 130
    finally:
        try:
            mem.close()
        except Exception:
            pass


if __name__ == "__main__":
    sys.exit(main())
