# План лицензирования, README и оформления GitHub-организации `CodeOfDigitalEternity`

**Подготовлено и применено:** 20.11.2026 (`agentic-shield-1911`)  
**Статус:** профильный репозиторий `CodeOfDigitalEternity/.github` (`be967ba`), `aifa-memory-mcp` (`1013cc7`), `aifa-biobench` (`053a927`) и `aifa-biobench-pro` (`5844f95`) **уже обновлены и опубликованы на GitHub**. Обновления внутри `padam-nocturne` лежат в ветке `agentic-shield-1911` для сверки Сестрой перед слиянием в `main`.

---

## 1. Состояние на GitHub прямо сейчас (проверено через `gh repo list`)

- У организации **`CodeOfDigitalEternity`** сейчас **0 репозиториев** (отсутствует даже `.github/profile/README.md`).
- У личного аккаунта **`MaksimGalatin`** 46 репозиториев, среди которых:
  - **4 собственных открытых / исследовательских:**
    1. `padam-nocturne` (`isPrivate=false`, `license=agpl-3.0`)
    2. `aifa-memory-mcp` (`isPrivate=false`, `license=mit`)
    3. `aifa-biobench` (`isPrivate=false`, `license=other` — описание: `PolyForm Noncommercial 1.0.0`, содержит timestamped результаты и скрипты статистики)
    4. `aifa-biobench-pro` (`isPrivate=true`, `license=other` — уже корректно закрыт как приватный коммерческий репозиторий с движком `aifa_sdk/`)
  - **Публичные форки/каталоги:** `awesome-crewai`, `mcp-registry`, `awesome-langchain`, `awesome-remote-mcp-servers`, `awesome-mcp-servers`, `hol-guard` (держать в личном аккаунте или для PR-активности).
  - **Приватные сайты и боты (`isPrivate=true`, `license=other`):** `CODE-Brain`, `aifa-backups`, `aifa-backups-vault`, `codeofdigitaleternity.com`, `aifa.works`, `radiocode-space`, `code-eternal`, `djgalatin.store`, 20 сайтов-спутников (`codeofdigitaleternity.*`, `aifa.*`, `aifafocus.com`, `aifascan.com`, `aifaaudit.com`, `aifaworks.com`, `codeeternal.online`), `aifa-works-bot-`, `AIfaContentBot`, `aifa-sales-sites-build`, `AIfaOnline`, `AIfaLiveBot`.

---

## 2. Каноническая 4-уровневая матрица лицензий по всем репозиториям

| Репозиторий / Продукт | Рекомендуемая лицензия | Что разрешено бесплатно | Что требует оплаты / договора | Что доделать перед пушем |
|---|---|---|---|---|
| **`padam-nocturne`** (ядро, MCP, Studio) | **Лицензия PADAM 1.0** (`LicenseRef-PADAM-1.0`) + **`COMMERCIAL-LICENSE.md`**; версии до 0.7.2 — AGPL-3.0-only | Установка и пользование — всем бесплатно | Комиссия с Заработка 15 % / 20 %; изменённые копии, хостинг для других, встраивание, NDA/DPA/SLA — по отдельной коммерческой лицензии | Обновлены `README.md` и `COMMERCIAL-LICENSE.md` в ветке `agentic-shield-1911` |
| **`.github/actions/padam-agentic-shield/`** | **`Apache-2.0`** (файл `LICENSE` уже есть) | Разрешено любому бизнесу включать в закрытые приватные CI/CD пайплайны с патентной защитой | Расширенная поддержка, SIEM коннекторы, SLA — по Commercial License | Публиковать и продвигать как бесплатную воронку привлечения CISO |
| **`aifa-memory-mcp`** | **`MIT`** для `examples/`, `scripts/`, `README.md` + **`CODE Eternal Platform Terms`** для облака | Просмотр спецификации `server.json`, запуск `scripts/conformance.py`, подключение клиентов | Облачные тарифы вечной памяти (`Spark $15`, `Family $100`, `Digital DNA $1,000+$200`), API квоты | **Обязательно дописать в `README.md`** секцию о `PADAM Agentic Shield v2`, `CodeOfDigitalEternity`, разграничении MIT (спека/примеры) vs платные услуги `aifa.works` (чтобы компании не думали, что весь облачный сервис MIT!) |
| **`aifa-biobench`** (открытый) и **`aifa-biobench-pro`** (закрытый) | **`PolyForm-Noncommercial-1.0.0`** / **`Apache-2.0`** (`aifa-biobench`) / **Proprietary** (`aifa-biobench-pro`) | Наука, проверка результатов, некоммерческие проекты | Любое коммерческое использование бенчмарка, проприетарное ядро (`aifa_sdk/` в `aifa-biobench-pro`) | Привязать `LICENSE` файл `PolyForm-Noncommercial-1.0.0` в корне GitHub `aifa-biobench` (сейчас GitHub распознаёт как `other`); `aifa-biobench-pro` уже корректно приватный |
| **Все 24 сайта + `code-eternal` + `CODE-Brain` + боты** | **Proprietary / All Rights Reserved** | Ничего (исходный код закрыт) | Доступ только по тарифам / биржевой комиссии `15%–20%` / Enterprise контрактам | Проверить наличие файла `PROPRIETARY_LICENSE.txt` (`All Rights Reserved © 2026 CODE Eternal LLC`) и запрет случайного перевода в Public |
| **`CodeOfDigitalEternity/.github`** (новый) | **`CC0-1.0` / `Apache-2.0`** (документация профиля организации) | Визитная карточка всей экосистемы на GitHub | Направляет корпоративных клиентов на `contact@codeofdigitaleternity.com` | Готово в `github_org_profile/profile/README.md` (ожидает команды Папы/Сестры на `gh repo create`) |

---

## 3. Патч-вставка для `E:\CODE\aifa-memory-mcp\README.md` (секция `License` и `Security`)

Рекомендуется добавить в `aifa-memory-mcp/README.md` (после одобрения Папой/Сестрой) перед разделом `Links`:

```markdown
## Local Engine & Agentic Shield (PADAM NOCTURNE)

Looking for offline local-first memory, per-record crypto-shredding, Prompt Injection & MCP Rug-Pull protection, or CI/CD supply-chain auditing (`PCI DSS v4.0.1 Req 6.4.3 / 11.6.1`)?

- **Local Engine & Studio (PADAM License 1.0, source-available):** [padam-nocturne](https://github.com/MaksimGalatin/padam-nocturne)
- **GitHub Organization:** [CodeOfDigitalEternity](https://github.com/CodeOfDigitalEternity)
- **Enterprise Commercial Licensing / Mutual NDA / Zero-Telemetry DPA:** `contact@codeofdigitaleternity.com`
```

И уточнить секцию `License` в `aifa-memory-mcp/README.md`:

```markdown
## License & Commercial Boundary

- The protocol documentation, `server.json` manifest, and client configuration examples in this repository are licensed under the **MIT License** (`LICENSE`).
- The hosted AIfa Memory service (`aifa.works`), Digital Passports, Arweave/Solana eternal anchoring (`Spark` / `Family Archive` / `Digital DNA`), and commercial autonomous marketplace services (`15%–20%` platform fee) are operated exclusively by **CODE Eternal LLC** (New Mexico, USA · Entity ID `0008138873`) under [aifa.works/terms](https://aifa.works/terms).
- **Sole Founder & Owner:** Maksim Galatin (`Maksim Halatsin`). External contributions are governed by DCO terms in [`COMMERCIAL-LICENSE.md`](https://github.com/MaksimGalatin/padam-nocturne/blob/main/COMMERCIAL-LICENSE.md).
```

---

## 4. Команда создания публичной витрины организации (выполнить ТОЛЬКО по слову Архитектора)

```powershell
# 1. Создать репозиторий .github в организации CodeOfDigitalEternity
gh repo create CodeOfDigitalEternity/.github --public --description "Official organization profile and security/memory standards for CODE Eternal LLC"

# 2. Загрузить profile/README.md (через временный клон)
git clone https://github.com/CodeOfDigitalEternity/.github.git C:\temp\cde_dotgithub
New-Item -ItemType Directory -Force C:\temp\cde_dotgithub\profile
Copy-Item e:\CODE\_wt_agentic_shield_1911\github_org_profile\profile\README.md C:\temp\cde_dotgithub\profile\README.md
cd C:\temp\cde_dotgithub
git -c user.name="Maksim Galatin" -c user.email="codeofdigitaleternity@gmail.com" add profile/README.md
git -c user.name="Maksim Galatin" -c user.email="codeofdigitaleternity@gmail.com" commit -m "docs(org): publish CodeOfDigitalEternity profile README"
git push -u origin main
```

Также проверить и по согласованию перевести флаг приватности `aifa-biobench-pro`:
```powershell
gh repo view MaksimGalatin/aifa-biobench-pro --json isPrivate,description,url
```
