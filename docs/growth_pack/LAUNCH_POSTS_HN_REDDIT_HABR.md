# Готовые технические публикации (Show HN, Reddit, Habr / Dev.to)

Все числа строго соответствуют проверенным замерам текущего релиза (`padam-nocturne 0.6.5`, ветка `agentic-shield-1911`). Никаких выдуманных QPS или маркетинговой воды.

---

## 1. Show HN (Hacker News)

**Заголовок:** `Show HN: PADAM – Local SQLite AI memory with 4 security rings, quarantine & crypto-shredding (AGPL-3.0)`
**URL:** `https://github.com/MaksimGalatin/padam-nocturne`

**Первый комментарий автора (EN):**
> Hi HN, author here.
>
> Most AI agent memory layers (mem0, Zep, markdown files) focus purely on retrieval. In practice, if an untrusted web page or external MCP tool slips a hidden `<IMPORTANT>` prompt injection, invisible Unicode Tag (`U+E00xx`), or API key into the agent's context, that poisoned memory gets persisted and executed in future sessions.
>
> We built **PADAM NOCTURNE** — a single-file local SQLite memory server (`pip install padam-nocturne`) with zero cloud telemetry (`$0` runtime cost) and 4 deterministic defense rings:
> 1. **Quarantine & Schema Pinning:** untrusted writes / hidden directives go to owner quarantine rather than active recall (`PADAM_STRICT=1` holds every agent write), and MCP tool schemas are SHA-256 pinned against Rug-Pull mutations.
> 2. **Secret Redaction Before Disk:** 20+ secret formats (`sk-`, `ghp_`, `AIza`, Solana keys, Luhn cards) are masked *before* hitting SQLite or WAL/SHM.
> 3. **Outbound Payee-Swap Gate:** blocks unapproved EVM/BTC/TRON/Solana addresses, mod-97 IBANs, and Levenshtein <= 2 domain typosquatting.
> 4. **CI Action (Apache-2.0) & Web SRI/CSP:** GitHub Action generating SARIF 2.1.0 + signed HMAC webhooks.
>
> Everything is locally reproducible with zero external network calls:
> - `python redteam/run.py redteam/public_cases.jsonl` -> **214 / 214** (88 benign, 73 command, 53 secret)
> - `python benchmarks/aifa_security/run_aifa_sec.py --no-write` -> **Grade S (100/100)**
>
> Honest limits: this is not a formal SOC 2 / ISO 27001 replacement, and heuristic rules won't catch novel zero-day semantic paraphrase attacks without LLM review (optional local Ollama supported). Feedback and Red Team edge cases are very welcome!

---

## 2. Reddit (`r/LocalLLaMA`, `r/ClaudeAI`, `r/cybersecurity`)

**Заголовок:** `[Open Source] Built a local-first SQLite MCP memory firewall that stops MCP tool poisoning, payee-swaps & secret leaks at $0 cloud cost`

**Текст поста (EN):**
> After watching how easily untrusted MCP tool descriptions (`<IMPORTANT>`), hidden Unicode tags, and web CDN supply-chain compromises hijack agent workflows, I added a 4-ring Agentic Shield to **PADAM NOCTURNE** (`AGPL-3.0-only` core, `Apache-2.0` GitHub Action).
>
> **What you can run locally in 30 seconds (`$0`, no API keys required):**
> ```bash
> pip install padam-nocturne
> padam setup --all   # auto-configures 13 clients (Claude Code, Cursor, VS Code, Antigravity, Codex, Windsurf...)
> python -m benchmarks.aifa_security.run_aifa_sec --no-write
> ```
>
> **Measured locally (offline):**
> - **214 / 214** Red Team cases passed (`benign: 88/88, command: 73/73, secret: 53/53`)
> - **34 / 34** cross-record secret / SSRF / DNS-rebinding webhook cases passed
> - **100 / 100 (Grade S)** on `AIFaSecurity-100`
>
> Repo: https://github.com/MaksimGalatin/padam-nocturne (and Studio desktop UI included via `padam studio`). Happy to answer questions about our SHA-256 tool pinning, DNS-pinned SIEM webhooks, or NOCTURNE consolidation!

---

## 3. Habr / Dev.to (RU-версия разбора)

**Заголовок:** `Как скрытый приказ в MCP-ответе ворует ключи из памяти ИИ-агента — и как остановить это локальным SQLite-карантином за 0 ₽`

**Ключевые тезисы (RU):**
1. **Вектор атаки:** отравление памяти (Memory Poisoning), скрытые `<IMPORTANT>` в описаниях MCP-инструментов (Rug-Pull после подключения), невидимые символы `U+E00xx` и подмена платёжного адреса (Payee-Swap).
2. **Почему векторная база без карантина опасна:** обычный RAG сохраняет яд в индекс, а на следующий день агент исполняет его как «воспоминание пользователя».
3. **Архитектура `PADAM NOCTURNE`:** 4 кольца защиты + два времени у записи (`last_seen_at` vs `last_confirmed_at`) + крипто-стирание (`AES-256-GCM`) без уничтожения остальной базы.
4. **Воспроизведение читателем за 1 минуту:** `pip install padam-nocturne`, запуск `redteam/run.py` (`214/214`) и `run_aifa_sec.py` (`Grade S 100/100`), плюс открытый `Apache-2.0` GitHub Action.
