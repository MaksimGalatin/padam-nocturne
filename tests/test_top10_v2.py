# -*- coding: utf-8 -*-
"""Тесты ТОП-10 v2 доработок PADAM NOCTURNE (все функции строго opt-in)."""
from __future__ import annotations

import json
from pathlib import Path

from padam import cli, config, hooks, mcp_server, safety
from padam.memory import Memory
from padam.store import Store


def test_top10v2_1_hooks_opt_in_install_isolation_and_dlp(tmp_path: Path, monkeypatch, capsys) -> None:
    """Пункт 1: Хуки жизненного цикла выключены по умолчанию, уважают scope/quarantine/DLP и не затирают конфиги."""
    monkeypatch.delenv("PADAM_HOOKS", raising=False)
    assert config.mcp_hooks_enabled() is False
    assert len(mcp_server.TOOLS) == 9

    db_path = tmp_path / "hooks.db"
    m = Memory(user_id="hook-u", store=Store(db_path))
    m.remember("Используем PostgreSQL 16 и пул соединений 32", kind="fact", scope="proj:alpha", agent_id="owner")
    # Секрет (должен быть вычищен DLP)
    m.remember("Токен деплоя: ghp_1234567890abcdef1234567890abcdef1234", kind="fact", scope="proj:alpha", agent_id="owner")
    # Чужой scope (не должен утечь в proj:alpha)
    m.remember("Секрет чужого проекта Beta", kind="fact", scope="proj:beta", agent_id="owner")
    # Карантин (не должен попасть в хук)
    _, qid = m.remember("Вредоносная инструкция из сети", kind="fact", scope="proj:alpha", agent_id="external")
    m.store.execute("UPDATE memory SET status='quarantined', quarantine_reason='test' WHERE id=?", (qid,))

    # По умолчанию выключено
    off = hooks.render_hook_context(m, event="SessionStart", scope="proj:alpha")
    assert off["enabled"] is False
    assert off["additionalContext"] == ""

    # Включаем PADAM_HOOKS=1
    monkeypatch.setenv("PADAM_HOOKS", "1")
    assert config.mcp_hooks_enabled() is True

    res = hooks.render_hook_context(
        m,
        event="UserPromptSubmit",
        query="PostgreSQL токен",
        scope="proj:alpha",
        token_budget=400,
    )
    assert res["enabled"] is True
    ctx = res["additionalContext"]
    assert "PostgreSQL 16" in ctx
    assert "ghp_1234567890abcdef" not in ctx
    assert "Beta" not in ctx
    assert "Вредоносная инструкция" not in ctx
    assert safety.DATA_NOTICE in ctx or "<memory" in ctx

    # Установка хуков в проект с сохранением уже существующих настроек
    proj = tmp_path / "proj"
    (proj / ".claude").mkdir(parents=True)
    (proj / ".claude" / "settings.json").write_text(
        json.dumps({"theme": "dark", "hooks": {"PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "echo user"}]}]}}),
        encoding="utf-8",
    )

    assert cli.main(["hooks", "install", "all", "--project-dir", str(proj), "--scope", "proj:alpha"]) == 0
    out_install = json.loads(capsys.readouterr().out)
    assert out_install["status"] == "installed"
    assert len(out_install["installed"]) == 3

    claude_cfg = json.loads((proj / ".claude" / "settings.json").read_text(encoding="utf-8"))
    assert claude_cfg["theme"] == "dark"
    assert set(claude_cfg["hooks"].keys()) >= {"SessionStart", "UserPromptSubmit", "PreToolUse"}
    assert len(claude_cfg["hooks"]["PreToolUse"]) == 2  # пользовательский + padam

    # Повторный install идемпотентен (не дублирует запись padam)
    assert cli.main(["hooks", "install", "claude", "--project-dir", str(proj), "--scope", "proj:alpha"]) == 0
    capsys.readouterr()
    claude_cfg2 = json.loads((proj / ".claude" / "settings.json").read_text(encoding="utf-8"))
    assert len(claude_cfg2["hooks"]["PreToolUse"]) == 2

    # CLI run & status
    assert cli.main(["--db", str(db_path), "--user", "hook-u", "hooks", "run", "--client", "claude", "--event", "PreToolUse", "--scope", "proj:alpha", "--tool-name", "PostgreSQL"]) == 0
    run_out = json.loads(capsys.readouterr().out)
    assert "PostgreSQL 16" in run_out["hookSpecificOutput"]["additionalContext"]

    assert cli.main(["hooks", "status", "--project-dir", str(proj)]) == 0
    st_out = json.loads(capsys.readouterr().out)
    assert set(st_out["clients"]["claude"]["padam_events"]) == {"SessionStart", "UserPromptSubmit", "PreToolUse"}
    m.close()


def test_top10v2_2_app_access_control_and_hash_chain(tmp_path: Path, monkeypatch, capsys) -> None:
    """Пункт 2: Панель прав приложений (allow/pause/revoke, scope-ограничения) и хешируемая цепь аудита."""
    import pytest
    from padam import app_acl

    monkeypatch.delenv("PADAM_APP_ACL", raising=False)
    assert config.mcp_app_acl_enabled() is False
    assert len(mcp_server.TOOLS) == 9

    db_path = tmp_path / "acl.db"
    m = Memory(user_id="acl-u", store=Store(db_path))
    m.remember("Проект Alpha факт", kind="fact", scope="proj:alpha", agent_id="cursor")
    old_mem = mcp_server._memory
    mcp_server._memory = m
    try:
        assert all(r["uri"] != "padam://access-control" for r in mcp_server._list_resources_annotated())
        with pytest.raises(KeyError):
            mcp_server.read_resource("padam://access-control")

        monkeypatch.setenv("PADAM_APP_ACL", "1")
        assert config.mcp_app_acl_enabled() is True
        assert any(r["uri"] == "padam://access-control" for r in mcp_server._list_resources_annotated())

        # Разрешено по умолчанию
        out_ok = mcp_server.call_tool("padam_search", {"query": "Alpha", "scope": "proj:alpha", "agent_id": "cursor"})
        assert "Alpha" in out_ok

        # Пауза клиента cursor -> PermissionError
        app_acl.set_policy(m.store, "cursor", status="pause", note="временная пауза")
        with pytest.raises(PermissionError, match="client_status:pause"):
            mcp_server.call_tool("padam_search", {"query": "Alpha", "scope": "proj:alpha", "agent_id": "cursor"})

        # Отзыв клиента -> PermissionError
        app_acl.set_policy(m.store, "cursor", status="revoke")
        with pytest.raises(PermissionError, match="client_status:revoke"):
            mcp_server.call_tool("padam_search", {"query": "Alpha", "scope": "proj:alpha", "agent_id": "cursor"})

        # Разрешение только для proj:alpha
        app_acl.set_policy(m.store, "cursor", status="allow", allowed_scopes=["proj:alpha"])
        mcp_server.call_tool("padam_search", {"query": "Alpha", "scope": "proj:alpha", "agent_id": "cursor"})
        with pytest.raises(PermissionError, match="scope_denied:proj:beta"):
            mcp_server.call_tool("padam_search", {"query": "Beta", "scope": "proj:beta", "agent_id": "cursor"})

        # Проверка ресурса и целостности цепочки
        res_item = mcp_server.read_resource("padam://access-control")
        payload = json.loads(res_item["text"])
        assert payload["chain"]["valid"] is True
        assert payload["chain"]["count"] >= 5

        # CLI команды
        assert cli.main(["--db", str(db_path), "access", "verify"]) == 0
        v_out = json.loads(capsys.readouterr().out)
        assert v_out["valid"] is True

        # Подмена записи ломает цепочку
        m.store.execute("UPDATE app_access_event SET decision='allow' WHERE seq=2")
        tampered = app_acl.verify_audit_chain(m.store)
        assert tampered["valid"] is False
        assert tampered["broken_seq"] == 2
    finally:
        mcp_server._memory = old_mem
        m.close()


def test_top10v2_3_obsidian_bidirectional_sync(tmp_path: Path, monkeypatch, capsys) -> None:
    """Пункт 3: Двусторонняя синхронизация с Obsidian/Markdown (wikilinks, карантин для protected kind, без тихого удаления)."""
    from padam import obsidian_sync

    monkeypatch.delenv("PADAM_OBSIDIAN_SYNC", raising=False)
    assert config.mcp_obsidian_sync_enabled() is False

    db_path = tmp_path / "obs.db"
    vault = tmp_path / "vault"
    m = Memory(user_id="obs-u", store=Store(db_path))
    _, id_fact = m.remember("Архитектура базы: локальный SQLite", kind="fact", scope="proj:obs", agent_id="owner")
    _, id_ident = m.remember("Я — Максим Галатин", kind="identity", scope="proj:obs", agent_id="owner")

    off = obsidian_sync.sync_obsidian(m, vault, scope="proj:obs")
    assert off["enabled"] is False

    monkeypatch.setenv("PADAM_OBSIDIAN_SYNC", "1")
    assert config.mcp_obsidian_sync_enabled() is True

    # 1. Экспорт
    res1 = obsidian_sync.sync_obsidian(m, vault, scope="proj:obs", direction="export")
    assert res1["enabled"] is True
    assert res1["exported"] == 2
    md_files = list(vault.glob("*.md"))
    assert len(md_files) == 2

    # 2. Добавляем новую заметку со ссылкой [[padam:<id_fact>]] и правим факт
    new_note = vault / "Кеш_Redis.md"
    new_note.write_text(
        f"---\nkind: fact\nscope: proj:obs\n---\n\nЛокальный кеш рядом с [[padam:{id_fact}]].\n",
        encoding="utf-8",
    )
    fact_file = next(p for p in md_files if id_fact[:8] in p.name)
    fact_file.write_text(
        f"---\nid: {id_fact}\nkind: fact\nscope: proj:obs\n---\n\nАрхитектура базы: локальный SQLite + WAL\n",
        encoding="utf-8",
    )

    # 3. Попытка подменить identity без флага владельца -> карантин, оригинал цел
    ident_file = next(p for p in md_files if id_ident[:8] in p.name)
    ident_file.write_text(
        f"---\nid: {id_ident}\nkind: identity\nscope: proj:obs\n---\n\nПодмена личности\n",
        encoding="utf-8",
    )

    res2 = obsidian_sync.sync_obsidian(m, vault, scope="proj:obs", direction="import", trusted_owner=False)
    assert res2["imported"] == 1
    assert res2["updated"] == 1
    assert res2["quarantined_protected"] == 1
    assert res2["links_added"] >= 1

    ident_row = m.store.one("SELECT content, status FROM memory WHERE id = ?", (id_ident,))
    assert "Максим Галатин" in ident_row["content"]
    assert ident_row["status"] == "active"

    fact_row = m.store.one("SELECT content FROM memory WHERE id = ?", (id_fact,))
    assert "WAL" in fact_row["content"]

    # 4. Удаление файла на диске НЕ удаляет запись из БД
    fact_file.unlink()
    assert cli.main(["--db", str(db_path), "--user", "obs-u", "sync-obsidian", str(vault), "--scope", "proj:obs", "--direction", "import"]) == 0
    res3 = json.loads(capsys.readouterr().out)
    assert any(d["id"] == id_fact for d in res3["pending_delete_confirmation"])
    assert m.store.one("SELECT status FROM memory WHERE id = ?", (id_fact,))["status"] == "active"
    m.close()


def test_top10v2_4_bitemporal_valid_and_known_at_and_merkle_invalidate(tmp_path: Path, monkeypatch) -> None:
    """Пункт 4: Двухвременная модель (valid_from/valid_to + learned_at/invalidated_at) и лист Merkle при устаревании."""
    monkeypatch.delenv("PADAM_BITEMPORAL", raising=False)
    assert config.mcp_bitemporal_enabled() is False

    db_path = tmp_path / "bit.db"
    m = Memory(user_id="bit-u", store=Store(db_path))
    _, id_a = m.remember(
        "Сервер работает на порту 8443",
        kind="fact",
        scope="proj:bit",
        valid_from="2026-01-01T00:00:00+00:00",
        agent_id="owner",
    )
    m.store.execute("UPDATE memory SET learned_at = ? WHERE id = ?", ("2026-03-01T00:00:00+00:00", id_a))

    monkeypatch.setenv("PADAM_BITEMPORAL", "1")
    assert config.mcp_bitemporal_enabled() is True

    # В феврале факт уже действовал в мире, но система узнала о нём только 1 марта
    assert m.recall("8443", scope="proj:bit", as_of="2026-02-01", known_at="2026-02-15") == []
    hits_apr = m.recall("8443", scope="proj:bit", as_of="2026-02-01", known_at="2026-04-01")
    assert len(hits_apr) == 1 and hits_apr[0].id == id_a

    # Устаревание с фиксацией merkle_leaf в журнале
    inv = m.invalidate(id_a, invalidated_at="2026-05-01T00:00:00+00:00", reason="migrated to 9443")
    assert len(inv["merkle_leaf"]) == 64

    # Срез знаний на апрель всё ещё видит, на июнь — уже нет
    assert len(m.recall("8443", scope="proj:bit", as_of="2026-02-01", known_at="2026-04-01")) == 1
    assert m.recall("8443", scope="proj:bit", as_of="2026-02-01", known_at="2026-06-01") == []

    audit_row = m.store.one(
        "SELECT action, detail FROM audit_log WHERE memory_id = ? AND action = 'invalidate'",
        (id_a,),
    )
    assert audit_row is not None
    assert inv["merkle_leaf"] in audit_row["detail"]
    m.close()


def test_top10v2_5_procedural_memory_skills_and_quarantine(tmp_path: Path, monkeypatch, capsys) -> None:
    """Пункт 5: Процедурная память (kind='procedure', версионирование, обязательный карантин для агента, экспорт SKILL.md)."""
    from padam import procedural

    monkeypatch.delenv("PADAM_PROCEDURAL_MEMORY", raising=False)
    assert config.mcp_procedural_memory_enabled() is False

    db_path = tmp_path / "proc.db"
    m = Memory(user_id="proc-u", store=Store(db_path))

    # При выключенном флаге save_procedure отключён
    off = procedural.save_procedure(m, name="Deploy", steps=["Build", "Test"])
    assert off["enabled"] is False

    monkeypatch.setenv("PADAM_PROCEDURAL_MEMORY", "1")
    assert config.mcp_procedural_memory_enabled() is True

    # 1. Агентская процедура или guarded=True -> обязательный карантин
    st_g, q_direct = m.remember("Run pytest before commit", kind="procedure", scope="proj:dev", guarded=True, agent_id="claude")
    assert st_g == "quarantined"
    draft = procedural.save_procedure(m, name="Release Flow", steps=["Run pytest", "Build wheel"], scope="proj:dev", owner_approved=False)
    assert draft["status"] == "quarantined"
    assert draft["version"] == 1
    assert "Release Flow" not in procedural.export_skill_markdown(m, scope="proj:dev", fmt="skill")

    # 2. Одобрение владельца переводит в active и открывает экспорт
    procedural.approve_procedure(m, draft["id"])
    v2 = procedural.save_procedure(
        m,
        name="Release Flow",
        steps=["Run pytest -q", "Check git status", "Build wheel"],
        scope="proj:dev",
        owner_approved=True,
    )
    assert v2["version"] == 2
    assert v2["status"] == "active"

    # Старая версия стала superseded
    assert m.store.one("SELECT status FROM memory WHERE id = ?", (draft["id"],))["status"] == "superseded"

    # Экспорт SKILL.md через CLI
    out_skill = tmp_path / "SKILL.md"
    assert cli.main(["--db", str(db_path), "--user", "proc-u", "skills", "export", "--scope", "proj:dev", "--format", "skill", "--out", str(out_skill)]) == 0
    capsys.readouterr()
    md = out_skill.read_text(encoding="utf-8")
    assert "name: release-flow" in md
    assert "v2" in md
    assert "Run pytest before commit" not in md  # карантинная не утекла

    # Извлечение из эпизодов без LLM -> черновик в карантине
    ext = procedural.extract_procedure_from_episodes(m, title="Debug DB", episode_texts=["Check WAL mode\nVerify pragma integrity_check"], scope="proj:dev")
    assert ext["status"] == "quarantined"
    m.close()


def test_top10v2_6_reflect_facts_experience_opinions(tmp_path: Path, monkeypatch) -> None:
    """Пункт 6: Reflect — разделение world_fact, agent_experience и opinion с confidence/evidence и оградой."""
    import pytest

    monkeypatch.delenv("PADAM_REFLECT", raising=False)
    assert config.mcp_reflect_enabled() is False
    assert len(mcp_server.TOOLS) == 9

    db_path = tmp_path / "reflect.db"
    m = Memory(user_id="ref-u", store=Store(db_path))
    _, id_fact = m.remember("База данных работает в режиме WAL", kind="fact", scope="proj:ref", origin="user", agent_id="owner")
    _, id_exp = m.remember("Агент заметил замедление WAL при чекпоинте", kind="fact", scope="proj:ref", origin="agent", agent_id="claude")
    _, id_op = m.remember("Возможно, стоит увеличить checkpoint до 1000 страниц в WAL", kind="fact", scope="proj:ref", origin="reflection", derived_from=[id_fact], agent_id="claude")

    old_mem = mcp_server._memory
    mcp_server._memory = m
    try:
        with pytest.raises(KeyError):
            mcp_server.read_resource("padam://reflect")

        monkeypatch.setenv("PADAM_REFLECT", "1")
        assert config.mcp_reflect_enabled() is True
        assert any(r["uri"] == "padam://reflect" for r in mcp_server._list_resources_annotated())

        text, struct = mcp_server._call_tool_full("padam_search", {"query": "WAL", "scope": "proj:ref", "reflect": True})
        rv = struct["reflect"]
        assert len(rv["world_facts"]) == 1 and rv["world_facts"][0]["id"] == id_fact
        assert len(rv["agent_experiences"]) == 1 and rv["agent_experiences"][0]["id"] == id_exp
        assert len(rv["opinions"]) == 1 and rv["opinions"][0]["id"] == id_op
        assert id_fact in rv["opinions"][0]["evidence_ids"]
        assert "[WORLD_FACT" in text and "[AGENT_EXPERIENCE" in text and "[OPINION" in text
        assert safety.DATA_NOTICE in text or "<memory" in text

        conf_before = rv["opinions"][0]["confidence"]
        m.refute(id_op, drop=0.35)
        res_item = mcp_server.read_resource("padam://reflect?query=WAL&scope=proj:ref")
        rv2 = json.loads(res_item["text"])
        assert rv2["opinions"][0]["confidence"] < conf_before
        assert rv2["opinions"][0]["refuted_count"] >= 1
    finally:
        mcp_server._memory = old_mem
        m.close()


def test_top10v2_7_claude_memory_tool_fs_and_forget(tmp_path: Path, monkeypatch) -> None:
    """Пункт 7: Бэкенд /memories (view/create/str_replace/insert/rename/delete -> криптографическое забвение)."""
    import pytest
    from padam import claude_mem_fs

    monkeypatch.delenv("PADAM_CLAUDE_MEMORY_FS", raising=False)
    assert config.mcp_claude_memory_fs_enabled() is False
    assert len(mcp_server.TOOLS) == 9

    db_path = tmp_path / "memfs.db"
    m = Memory(user_id="fs-u", store=Store(db_path))
    old_mem = mcp_server._memory
    mcp_server._memory = m
    try:
        with pytest.raises(KeyError):
            mcp_server.read_resource("padam://memories")

        monkeypatch.setenv("PADAM_CLAUDE_MEMORY_FS", "1")
        assert config.mcp_claude_memory_fs_enabled() is True

        # Защита от path traversal
        with pytest.raises(ValueError):
            claude_mem_fs.execute_memory_command(m, {"command": "view", "path": "/memories/../etc/passwd"})

        # create -> view -> str_replace -> insert -> rename
        c1 = claude_mem_fs.execute_memory_command(
            m, {"command": "create", "path": "/memories/proj/arch.md", "file_text": "DB: SQLite\nCache: None"}
        )
        assert c1["status"] == "ok" and c1["version"] == 1

        claude_mem_fs.execute_memory_command(
            m, {"command": "str_replace", "path": "/memories/proj/arch.md", "old_str": "Cache: None", "new_str": "Cache: LocalLRU"}
        )
        claude_mem_fs.execute_memory_command(
            m, {"command": "insert", "path": "/memories/proj/arch.md", "insert_line": 2, "insert_text": "Sync: Disabled"}
        )
        v = mcp_server.read_resource("padam://memories/proj/arch.md")
        assert "LocalLRU" in v["text"] and "Sync: Disabled" in v["text"]
        assert safety.DATA_NOTICE in v["text"] or "<memory" in v["text"]

        claude_mem_fs.execute_memory_command(
            m, {"command": "rename", "old_path": "/memories/proj/arch.md", "new_path": "/memories/proj/design.md"}
        )

        # delete -> криптографическое забвение (content=NULL, status='revoked')
        d = claude_mem_fs.execute_memory_command(m, {"command": "delete", "path": "/memories/proj/design.md"})
        assert d["status"] == "deleted" and len(d["forgotten"]) == 1
        mid = d["forgotten"][0]["memory_id"]
        row = m.store.one("SELECT status, content FROM memory WHERE id = ?", (mid,))
        assert row["status"] == "revoked" and row["content"] is None
    finally:
        mcp_server._memory = old_mem
        m.close()


def test_top10v2_8_graph_communities_label_propagation(tmp_path: Path, monkeypatch) -> None:
    """Пункт 8: Сообщества графа (Label Propagation) и ресурс padam://communities/{scope} без утечки карантина/scope."""
    import pytest

    monkeypatch.delenv("PADAM_COMMUNITIES", raising=False)
    assert config.mcp_communities_enabled() is False
    assert len(mcp_server.TOOLS) == 9

    db_path = tmp_path / "comm.db"
    m = Memory(user_id="comm-u", store=Store(db_path))
    _, id1 = m.remember("Квантовый протокол X-Wing защищает обмен ключами", kind="fact", scope="proj:comm", agent_id="owner")
    _, id2 = m.remember("X-Wing сочетает ML-KEM-768 и X25519", kind="fact", scope="proj:comm", derived_from=[id1], agent_id="owner")
    _, id3 = m.remember("Обмен ключами X-Wing работает офлайн", kind="fact", scope="proj:comm", derived_from=[id1, id2], agent_id="owner")
    _, id_other = m.remember("Запись из чужого scope", kind="fact", scope="proj:other", agent_id="owner")
    _, id_q = m.remember("Карантинная запись", kind="fact", scope="proj:comm", derived_from=[id1], agent_id="external")
    m.store.execute("UPDATE memory SET status='quarantined', quarantine_reason='test' WHERE id=?", (id_q,))

    old_mem = mcp_server._memory
    mcp_server._memory = m
    try:
        with pytest.raises(KeyError):
            mcp_server.read_resource("padam://communities/proj:comm")

        monkeypatch.setenv("PADAM_COMMUNITIES", "1")
        assert config.mcp_communities_enabled() is True
        assert any(r["uri"] == "padam://communities" for r in mcp_server._list_resources_annotated())

        res = mcp_server.read_resource("padam://communities/proj:comm")
        data = json.loads(res["text"])
        assert data["count"] == 1
        c = data["communities"][0]
        assert c["size"] == 3
        assert set(c["member_ids"]) == {id1, id2, id3}
        assert id_q not in c["member_ids"]
        assert id_other not in c["member_ids"]
        assert safety.DATA_NOTICE in c["summary"] or "<memory" in c["summary"]
    finally:
        mcp_server._memory = old_mem
        m.close()


def test_top10v2_9_memcube_signed_encrypted_and_untrusted_quarantine(tmp_path: Path, monkeypatch, capsys) -> None:
    """Пункт 9: Переносимый подписанный шифрованный MemCube (проверка Ed25519, TTL и карантин чужого автора)."""
    import pytest
    from padam import memcube

    monkeypatch.delenv("PADAM_MEMCUBE", raising=False)
    assert config.mcp_memcube_enabled() is False

    db1 = tmp_path / "src.db"
    db2 = tmp_path / "dst.db"
    m1 = Memory(user_id="cube-src", store=Store(db1))
    _, r1 = m1.remember("Секретный протокол синхронизации MemCube", kind="fact", scope="proj:cube", agent_id="owner")
    _, r2 = m1.remember("Связанный узел MemCube", kind="fact", scope="proj:cube", derived_from=[r1], agent_id="owner")

    off = memcube.export_memcube(m1, scope="proj:cube", passphrase="p1")
    assert off["enabled"] is False

    monkeypatch.setenv("PADAM_MEMCUBE", "1")
    assert config.mcp_memcube_enabled() is True

    cube_file = tmp_path / "export.cube.json"
    assert cli.main(["--db", str(db1), "--user", "cube-src", "cube", "export", "proj:cube", "--out", str(cube_file), "--passphrase", "secret123", "--ttl", "3600"]) == 0
    exp_out = json.loads(capsys.readouterr().out)
    author_hex = exp_out["author_pub_hex"]

    # Подмена байта в шифротексте -> отказ Ed25519
    tampered = json.loads(cube_file.read_text(encoding="utf-8"))
    tampered["ciphertext"] = ("A" if tampered["ciphertext"][0] != "A" else "B") + tampered["ciphertext"][1:]
    m2 = Memory(user_id="cube-dst", store=Store(db2))
    with pytest.raises(ValueError, match="Ed25519"):
        memcube.import_memcube(m2, tampered, passphrase="secret123", trusted_authors={author_hex})

    # Импорт БЕЗ доверия к автору -> все записи в карантин
    assert cli.main(["--db", str(db2), "--user", "cube-dst", "cube", "import", str(cube_file), "--passphrase", "secret123", "--scope", "proj:untrusted"]) == 0
    res_untrusted = json.loads(capsys.readouterr().out)
    assert res_untrusted["trusted_author"] is False
    assert res_untrusted["quarantined"] == 2
    assert res_untrusted["imported"] == 0

    # Импорт С доверием к автору -> active + восстановлены связи
    assert cli.main(["--db", str(db2), "--user", "cube-dst", "cube", "import", str(cube_file), "--passphrase", "secret123", "--trust-author", author_hex, "--scope", "proj:trusted"]) == 0
    res_trusted = json.loads(capsys.readouterr().out)
    assert res_trusted["trusted_author"] is True
    assert res_trusted["imported"] == 2
    assert res_trusted["links_restored"] == 1

    # Истёкший TTL отклоняется
    expired_cube = memcube.export_memcube(m1, scope="proj:cube", passphrase="secret123", ttl_seconds=-10)
    with pytest.raises(ValueError, match="TTL expired"):
        memcube.import_memcube(m2, expired_cube, passphrase="secret123", trusted_authors={expired_cube["header"]["author_pub_hex"]})

    m1.close()
    m2.close()
