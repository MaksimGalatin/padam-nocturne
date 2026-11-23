# Таблица паритета PADAM Studio ↔ MCP

*Сгенерировано автоматически скриптом `scripts/generate_parity_studio_mcp.py` (не вручную).*

## Сводка по всем инструментам и действиям MCP

- Всего инструментов MCP (с учётом всех 6 флагов, `_ALL_TOOLS_BY_NAME`): **47** (по умолчанию: **9**, `PADAM_MCP_ARK_TOOLS=1`: **34** и **33480/27000** символов в `tools/list`, с `PADAM_MCP_PARTNER_TOOLS=1`: **40**).
- Всего пар `(инструмент, action)`: **228**.
- Есть в MCP: **228 из 228**
- Есть в Studio (вкладка + кнопка/поле): **228 из 228**
- Есть в API (`padam/api.py`): **228 из 228**
- Покрыто автотестами: **224 из 228**
- Проверено реальным нажатием в Playwright (1280×800 и 390×844): **201 из 228**
- Контролов Studio только для владельца (намеренно закрытых в MCP по аудиту GLM): **24**

## 1. Полная таблица MCP → Studio → API

| Инструмент MCP | Action | есть в MCP | есть в Studio | есть в API | тест есть | проверено нажатием |
|---|---|---|---|---|---|---|
| `padam_search` | `-` | Да | Да: `panel-search` → `#search-btn, #search-input` | Да: `GET /search` | Да | Да |
| `padam_write` | `-` | Да | Да: `panel-feed` → `#feed-new-save, #feed-new-text` | Да: `POST /write` | Да | Да |
| `padam_confirm` | `-` | Да | Да: `panel-review` → `#review-list, api('/approve')` | Да: `POST /approve` | Да | Да |
| `padam_refute` | `-` | Да | Да: `panel-review` → `#review-list, api('/reject')` | Да: `POST /reject` | Да | Да |
| `padam_timeline` | `-` | Да | Да: `panel-asof` → `#asof-btn, #asof-date` | Да: `GET /timeline/, GET /records` | Да | Да |
| `padam_stats` | `-` | Да | Да: `panel-overview` → `#panel-overview, '/overview'` | Да: `GET /overview` | Да | Да |
| `padam_sleep` | `-` | Да | Да: `panel-overview` → `#ov-sleep-btn` | Да: `POST /sleep` | Да | Да |
| `padam_export` | `-` | Да | Да: `panel-backup` → `#backup-export-json-btn` | Да: `GET /export` | Да | Да |
| `padam_profile` | `-` | Да | Да: `panel-overview` → `#panel-overview, '/profile'` | Да: `GET /profile` | Да | Да |
| `padam_recent` | `-` | Да | Да: `panel-feed` → `#panel-feed, '/records'` | Да: `GET /records` | Да | Да |
| `padam_rollback` | `snapshot` | Да | Да: `panel-brain` → `#ark-snap-create-btn, #ark-snap-name-inp` | Да: `POST /api/v2/snapshots` | Да | Да |
| `padam_rollback` | `list_snapshots` | Да | Да: `panel-brain` → `#ark-snap-list-btn` | Да: `GET /api/v2/snapshots` | Да | Да |
| `padam_rollback` | `diff` | Да | Да: `panel-brain` → `#ark-snap-diff-btn` | Да: `POST /api/v2/snapshots` | Да | Да |
| `padam_rollback` | `rollback` | Да | Да: `panel-brain` → `#ark-snap-rb-btn` | Да: `POST /api/v2/snapshots` | Да | Да |
| `padam_cabinet` | `status` | Да | Да: `panel-aifa` → `#panel-aifa, #aifa-auth-box` | Да: `GET /api/v2/cabinet/status` | Да | Да |
| `padam_cabinet` | `send_code` | Да | Да: `panel-aifa` → `#aifa-send-code-btn, #aifa-email-input` | Да: `POST /api/v2/cabinet/auth/send-code` | Да | Да |
| `padam_cabinet` | `verify_code` | Да | Да: `panel-aifa` → `#aifa-verify-code-btn, #aifa-code-input` | Да: `POST /api/v2/cabinet/auth/verify-code` | Да | Да |
| `padam_cabinet` | `logout` | Да | Да: `panel-aifa` → `#aifa-logout-btn` | Да: `POST /api/v2/cabinet/auth/logout` | Да | Да |
| `padam_cabinet` | `plans` | Да | Да: `panel-plans` → `#panel-plans, #plans-current-val` | Да: `GET /api/v2/cabinet/plans` | Да | Да |
| `padam_cabinet` | `upgrade_url` | Да | Да: `panel-plans` → `#plans-upgrade-btn, /api/v2/cabinet/open-upgrade` | Да: `POST /api/v2/cabinet/open-upgrade` | Да | Да |
| `padam_cabinet` | `chat_history` | Да | Да: `panel-aifa` → `#aifa-chat-list, /api/v2/cabinet/aifa/history` | Да: `GET /api/v2/cabinet/aifa/history` | Да | Да |
| `padam_cabinet` | `chat_send` | Да | Да: `panel-aifa` → `#aifa-send-msg-btn, #aifa-msg-input` | Да: `POST /api/v2/cabinet/aifa/chat` | Да | Да |
| `padam_brain_status` | `-` | Да | Да: `panel-brain` → `#brain-refresh-btn, #brain-mode-toggle-btn, #brain-warmup-btn` | Да: `GET /api/v2/brain/status` | Да | Да |
| `padam_sovereign_sync` | `-` | Да | Да: `panel-brain` → `#brain-phoenix-arweave-btn, #brain-phoenix-local-btn` | Да: `POST /api/v2/brain/phoenix-restore` | Да | Да |
| `padam_wake_up` | `-` | Да | Да: `panel-family` → `#ark-wakeup-btn` | Да: `GET /api/v2/ark/wakeup` | Да | Да |
| `padam_commitments` | `add` | Да | Да: `panel-family` → `#ark-comm-add-btn, #ark-comm-title-inp` | Да: `POST /api/v2/ark/commitments` | Да | Да |
| `padam_commitments` | `update` | Да | Да: `panel-family` → `#ark-comm-done-btn` | Да: `POST /api/v2/ark/commitments` | Да | Да |
| `padam_commitments` | `list` | Да | Да: `panel-family` → `#ark-comm-list-btn` | Да: `GET /api/v2/ark/commitments` | Да | Да |
| `padam_family_relay` | `send` | Да | Да: `panel-family` → `#ark-relay-send-btn, #ark-relay-msg-inp` | Да: `POST /api/v2/ark/relay` | Да | Да |
| `padam_family_relay` | `inbox` | Да | Да: `panel-family` → `#ark-relay-inbox-btn` | Да: `GET /api/v2/ark/relay` | Да | Да |
| `padam_family_relay` | `ack` | Да | Да: `panel-family` → `#ark-relay-ack-btn` | Да: `POST /api/v2/ark/relay` | Да | Да |
| `padam_checkpoint` | `save` | Да | Да: `panel-family` → `#ark-ckpt-save-btn` | Да: `POST /api/v2/ark/checkpoint` | Да | Да |
| `padam_checkpoint` | `latest` | Да | Да: `panel-family` → `#ark-ckpt-latest-btn` | Да: `GET /api/v2/ark/checkpoint` | Да | Да |
| `padam_ark_timeline` | `-` | Да | Да: `panel-family` → `#ark-tl-btn` | Да: `GET /api/v2/ark/timeline` | Да | Да |
| `padam_lesson` | `record` | Да | Да: `panel-family` → `#ark-lesson-rec-btn, #ark-lesson-inp` | Да: `POST /api/v2/ark/lessons` | Да | Да |
| `padam_lesson` | `list` | Да | Да: `panel-family` → `#ark-lesson-list-btn` | Да: `GET /api/v2/ark/lessons` | Да | Да |
| `padam_family_council` | `-` | Да | Да: `panel-family` → `#ark-council-btn, #ark-council-input` | Да: `POST /api/v2/ark/council` | Да | Да |
| `padam_family_feed` | `read` | Да | Да: `panel-family` → `#ff-ch-office, #ff-ch-work, #ff-ch-quarantine, #ff-ch-smoke` | Да: `GET /api/v2/family/feed` | Да | Да |
| `padam_family_feed` | `post` | Да | Да: `panel-family` → `#ff-send, #ff-input` | Да: `POST /api/v2/family/post` | Да | Да |
| `padam_family_feed` | `counts` | Да | Да: `panel-family` → `#ff-ch-office, /api/v2/family/feed` | Да: `GET /api/v2/family/feed` | Да | Да |
| `padam_family_feed` | `reflex_propose` | Да | Да: `panel-family` → `#ff-ref-propose-btn, #ff-ref-trig-inp` | Да: `POST /api/v2/family/reflex/propose` | Да | Да |
| `padam_family_feed` | `reflex_list` | Да | Да: `panel-family` → `#ff-reflexes, /api/v2/family/reflexes` | Да: `GET /api/v2/family/reflexes` | Да | Да |
| `padam_family_feed` | `reflex_match` | Да | Да: `panel-family` → `#ff-ref-match-btn` | Да: `POST /api/v2/family/reflex/match` | Да | Да |
| `padam_family_feed` | `agora_status` | Да | Да: `panel-family` → `#fam-agora-box, #ag-status-out` | Да: `GET /api/v2/ark/agora` | Да | Нет |
| `padam_family_feed` | `agora_read` | Да | Да: `panel-family` → `#ag-feed-list, GET /api/v2/ark/agora` | Да: `GET /api/v2/ark/agora` | Да | Да |
| `padam_family_feed` | `agora_post` | Да | Да: `panel-family` → `#ag-post-btn, #ag-title, #ag-body` | Да: `POST /api/v2/ark/agora/action` | Да | Нет |
| `padam_family_feed` | `agora_reply` | Да | Да: `panel-family` → `#ag-feed-list (reply), #ag-post-btn` | Да: `POST /api/v2/ark/agora/action` | Да | Нет |
| `padam_family_feed` | `agora_claim` | Да | Да: `panel-family` → `#ag-feed-list, POST /api/v2/ark/agora/action` | Да: `POST /api/v2/ark/agora/action` | Да | Да |
| `padam_family_feed` | `agora_complete` | Да | Да: `panel-family` → `#ag-feed-list, POST /api/v2/ark/agora/action` | Да: `POST /api/v2/ark/agora/action` | Да | Да |
| `padam_family_feed` | `agora_upvote` | Да | Да: `panel-family` → `#ag-feed-list, POST /api/v2/ark/agora/action` | Да: `POST /api/v2/ark/agora/action` | Да | Да |
| `padam_memory_branch` | `create` | Да | Да: `panel-brain` → `#ark-branch-create-btn, #ark-branch-input` | Да: `POST /api/v2/ark/branches` | Да | Да |
| `padam_memory_branch` | `remember` | Да | Да: `panel-brain` → `#ark-branch-rem-btn, #ark-branch-text-inp` | Да: `POST /api/v2/ark/branches` | Да | Да |
| `padam_memory_branch` | `list` | Да | Да: `panel-brain` → `#ark-branch-list-btn` | Да: `GET /api/v2/ark/branches` | Да | Да |
| `padam_memory_branch` | `merge` | Да | Да: `panel-brain` → `#ark-branch-merge-btn` | Да: `POST /api/v2/ark/branches` | Да | Да |
| `padam_memory_branch` | `abandon` | Да | Да: `panel-brain` → `#ark-branch-abn-btn` | Да: `POST /api/v2/ark/branches` | Да | Да |
| `padam_selective_proof` | `create` | Да | Да: `panel-brain` → `#ark-proof-btn, #ark-proof-input` | Да: `POST /api/v2/ark/proof` | Да | Да |
| `padam_selective_proof` | `verify` | Да | Да: `panel-brain` → `#ark-proof-verify-btn` | Да: `POST /api/v2/ark/proof` | Да | Да |
| `padam_guardian_tick` | `tick` | Да | Да: `panel-brain` → `#ark-guardian-btn` | Да: `GET /api/v2/ark/guardian-tick` | Да | Да |
| `padam_guardian_tick` | `health` | Да | Да: `panel-brain` → `#ark-health-box, /api/v2/ark/health` | Да: `GET /api/v2/ark/health` | Да | Да |
| `padam_guardian_tick` | `readiness` | Да | Да: `panel-brain` → `#ark-ready-btn` | Да: `GET /api/v2/ark/readiness` | Да | Да |
| `padam_guardian_tick` | `audit_verify` | Да | Да: `panel-brain` → `#ark-audit-btn` | Да: `GET /api/v2/ark/audit` | Да | Да |
| `padam_guardian_tick` | `doctor` | Да | Да: `panel-overview` → `#panel-overview, '/doctor'` | Да: `GET /doctor` | Да | Да |
| `padam_guardian_tick` | `l3_verify` | Да | Да: `panel-l3` → `#l3-verify-latest-btn, #panel-l3` | Да: `GET /l3` | Да | Да |
| `padam_guardian_tick` | `handover` | Да | Да: `panel-brain` → `#ark-handover-btn, #ark-handover-input` | Да: `POST /api/v2/ark/handover` | Да | Да |
| `padam_guardian_tick` | `drift` | Да | Да: `panel-brain` → `#ark-drift-btn, #ark-drift-input` | Да: `POST /api/v2/ark/drift` | Да | Да |
| `padam_guardian_tick` | `self_heal` | Да | Да: `panel-brain` → `#ark-selfheal-btn` | Да: `POST /api/v2/ark/self-heal` | Да | Да |
| `padam_guardian_tick` | `aifa_security` | Да | Да: `panel-attacks` → `#att-aifasec-run` | Да: `GET /api/v2/aifa-security` | Да | Да |
| `padam_guardian_tick` | `qa_benchmark` | Да | Да: `panel-attacks` → `#att-qa-load` | Да: `GET /api/v2/qa-benchmark` | Да | Да |
| `padam_guardian_tick` | `entities` | Да | Да: `panel-entities` → `#panel-entities, #entities-filter` | Да: `GET /entities` | Да | Да |
| `padam_guardian_tick` | `graph` | Да | Да: `panel-graph` → `#panel-graph, #graph-id-input` | Да: `GET /graph` | Да | Да |
| `padam_guardian_tick` | `context_compass` | Да | Да: `panel-feed` → `#mpro-compass-btn, #mpro-query-inp` | Да: `POST /api/v2/memory/pro/action` | Да | Да |
| `padam_guardian_tick` | `memory_hygiene` | Да | Да: `panel-feed` → `#mpro-hygiene-btn` | Да: `POST /api/v2/memory/pro/action` | Да | Да |
| `padam_guardian_tick` | `ide_rules` | Да | Да: `panel-feed` → `#mpro-ide-btn` | Да: `POST /api/v2/memory/pro/action` | Да | Да |
| `padam_guardian_tick` | `morning_pulse` | Да | Да: `panel-family` → `#pulse-run-btn` | Да: `POST /api/v2/power/action` | Да | Да |
| `padam_mesh_sync` | `identity` | Да | Да: `panel-brain` → `#ark-mesh-id-btn` | Да: `GET /api/v2/ark/mesh/identity` | Да | Да |
| `padam_mesh_sync` | `peers` | Да | Да: `panel-brain` → `#ark-mesh-btn` | Да: `GET /api/v2/ark/mesh/peers` | Да | Да |
| `padam_mesh_sync` | `pair_init` | Да | Да: `panel-brain` → `#ark-mesh-pairinit-btn, #ark-mesh-peer-inp` | Да: `POST /api/v2/ark/mesh/pair-init` | Да | Да |
| `padam_mesh_sync` | `pair_accept` | Да | Да: `panel-brain` → `#ark-mesh-pairacc-btn` | Да: `POST /api/v2/ark/mesh/pair-accept` | Да | Да |
| `padam_mesh_sync` | `pair_confirm` | Да | Да: `panel-brain` → `#ark-mesh-pairconf-btn, #ark-mesh-sas-inp` | Да: `POST /api/v2/ark/mesh/pair-confirm` | Да | Да |
| `padam_mesh_sync` | `export` | Да | Да: `panel-brain` → `#ark-mesh-delta-btn` | Да: `POST /api/v2/ark/mesh/delta` | Да | Да |
| `padam_mesh_sync` | `apply` | Да | Да: `panel-brain` → `#ark-mesh-apply-btn` | Да: `POST /api/v2/ark/mesh/apply` | Да | Да |
| `padam_multimodal_inspect` | `-` | Да | Да: `panel-brain` → `#ark-mm-btn, #ark-mm-path-inp` | Да: `POST /api/v2/ark/multimodal` | Да | Да |
| `padam_partner_find_clients` | `-` | Да | Да: `panel-earning` → `#earn-partner-find-btn, #earn-partner-region` | Да: `POST /api/v2/ark/partner/action` | Да | Да |
| `padam_partner_client_report` | `-` | Да | Да: `panel-earning` → `#earn-partner-report-btn, #earn-partner-site` | Да: `POST /api/v2/ark/partner/action` | Да | Да |
| `padam_partner_client_link` | `-` | Да | Да: `panel-earning` → `#earn-partner-link-btn` | Да: `POST /api/v2/ark/partner/action` | Да | Да |
| `padam_partner_kit` | `-` | Да | Да: `panel-earning` → `#earn-partner-kit-btn` | Да: `POST /api/v2/ark/partner/action` | Да | Да |
| `padam_partner_deals` | `-` | Да | Да: `panel-earning` → `#earn-partner-deals-btn` | Да: `POST /api/v2/ark/partner/action` | Да | Да |
| `padam_partner_draft_outreach` | `-` | Да | Да: `panel-earning` → `#earn-partner-draft-btn` | Да: `POST /api/v2/ark/partner/action` | Да | Да |
| `padam_sibling_hub` | `register` | Да | Да: `panel-earning` → `#earn-sib-reg-btn, #earn-sib-id` | Да: `POST /api/v2/ark/siblings` | Да | Да |
| `padam_sibling_hub` | `heartbeat` | Да | Да: `panel-family` → `#ark-sib-hb-btn` | Да: `POST /api/v2/ark/siblings` | Да | Да |
| `padam_sibling_hub` | `list` | Да | Да: `panel-family` → `#fam-agents-box, GET /api/v2/ark/siblings` | Да: `GET /api/v2/ark/siblings` | Да | Да |
| `padam_sibling_hub` | `passport` | Да | Да: `panel-family` → `#ark-sib-pass-btn` | Да: `POST /api/v2/ark/siblings` | Да | Да |
| `padam_sibling_hub` | `sign_provenance` | Да | Да: `panel-family` → `#ark-sib-sign-btn` | Да: `POST /api/v2/ark/siblings` | Да | Да |
| `padam_sibling_hub` | `verify_provenance` | Да | Да: `panel-family` → `#ark-sib-ver-btn` | Да: `POST /api/v2/ark/siblings` | Да | Да |
| `padam_sibling_hub` | `passport_check_name` | Да | Да: `panel-family` → `#pp-check-btn, #pp-desired-name` | Да: `POST /api/v2/ark/passports/action` | Да | Нет |
| `padam_sibling_hub` | `passport_create` | Да | Да: `panel-family` → `#pp-create-btn, #pp-agent-id` | Да: `POST /api/v2/ark/passports/action` | Да | Нет |
| `padam_sibling_hub` | `passport_list` | Да | Да: `panel-family` → `#pp-list, GET /api/v2/ark/passports` | Да: `GET /api/v2/ark/passports` | Да | Да |
| `padam_sibling_hub` | `passport_rename` | Да | Да: `panel-family` → `#pp-list, #pp-desired-name` | Да: `POST /api/v2/ark/passports/action` | Да | Нет |
| `padam_coop_lock` | `acquire` | Да | Да: `panel-family` → `#ark-coop-acq-btn, #ark-coop-key-inp` | Да: `POST /api/v2/ark/coop` | Да | Да |
| `padam_coop_lock` | `renew` | Да | Да: `panel-family` → `#ark-coop-ren-btn` | Да: `POST /api/v2/ark/coop` | Да | Да |
| `padam_coop_lock` | `release` | Да | Да: `panel-family` → `#ark-coop-rel-btn` | Да: `POST /api/v2/ark/coop` | Да | Да |
| `padam_coop_lock` | `release_all` | Да | Да: `panel-family` → `#ark-coop-relall-btn` | Да: `POST /api/v2/ark/coop` | Да | Да |
| `padam_coop_lock` | `list_leases` | Да | Да: `panel-family` → `#ark-coop-list-btn` | Да: `POST /api/v2/ark/coop` | Да | Да |
| `padam_coop_lock` | `list` | Да | Да: `panel-family` → `#ark-coop-list-btn` | Да: `POST /api/v2/ark/coop, GET /api/v2/ark/coop` | Да | Да |
| `padam_coop_lock` | `create_task` | Да | Да: `panel-family` → `#ark-coop-tcreate-btn, #ark-coop-task-inp` | Да: `POST /api/v2/ark/coop` | Да | Да |
| `padam_coop_lock` | `claim_task` | Да | Да: `panel-family` → `#ark-coop-tclaim-btn` | Да: `POST /api/v2/ark/coop` | Да | Да |
| `padam_coop_lock` | `update_task` | Да | Да: `panel-family` → `#ark-coop-tdone-btn` | Да: `POST /api/v2/ark/coop` | Да | Да |
| `padam_coop_lock` | `list_tasks` | Да | Да: `panel-family` → `#ark-coop-list-btn` | Да: `POST /api/v2/ark/coop` | Да | Да |
| `padam_coop_lock` | `collab_open` | Да | Да: `panel-family` → `#coop-open-btn, #coop-title-inp` | Да: `POST /api/v2/swarm/coop/action` | Да | Да |
| `padam_coop_lock` | `collab_submit` | Да | Да: `panel-family` → `#coop-open-btn, #coop-text-inp` | Да: `POST /api/v2/swarm/coop/action` | Да | Да |
| `padam_coop_lock` | `collab_synth` | Да | Да: `panel-family` → `#coop-status-btn, #coop-open-btn` | Да: `POST /api/v2/swarm/coop/action` | Да | Да |
| `padam_coop_lock` | `aid_request` | Да | Да: `panel-family` → `#coop-aid-req-btn, #coop-agent-inp` | Да: `POST /api/v2/swarm/coop/action` | Да | Да |
| `padam_coop_lock` | `coop_status` | Да | Да: `panel-family` → `#coop-status-btn` | Да: `GET /api/v2/swarm/coop, POST /api/v2/swarm/coop/action` | Да | Да |
| `padam_session_pack` | `-` | Да | Да: `panel-family` → `#ark-sespack-btn` | Да: `GET /api/v2/ark/session-pack` | Да | Да |
| `padam_code_anchor` | `anchor` | Да | Да: `panel-brain` → `#ark-anchor-add-btn, #ark-anchor-path-inp` | Да: `POST /api/v2/ark/code-anchor` | Да | Да |
| `padam_code_anchor` | `check` | Да | Да: `panel-brain` → `#ark-anchor-chk-btn` | Да: `GET /api/v2/ark/code-anchor, POST /api/v2/ark/code-anchor` | Да | Да |
| `padam_code_anchor` | `verify_claim` | Да | Да: `panel-brain` → `#ark-claim-btn, #ark-claim-inp` | Да: `POST /api/v2/ark/code-anchor` | Да | Нет |
| `padam_batch` | `-` | Да | Да: `panel-family` → `#ark-batch-btn` | Да: `POST /api/v2/ark/batch` | Да | Да |
| `padam_conflict_arbiter` | `open` | Да | Да: `panel-family` → `#ark-arb-open-btn, #ark-arb-topic-inp` | Да: `POST /api/v2/ark/conflicts` | Да | Да |
| `padam_conflict_arbiter` | `evidence` | Да | Да: `panel-family` → `#ark-arb-ev-btn` | Да: `POST /api/v2/ark/conflicts` | Да | Да |
| `padam_conflict_arbiter` | `resolve` | Да | Да: `panel-family` → `#ark-arb-res-btn` | Да: `POST /api/v2/ark/conflicts` | Да | Да |
| `padam_conflict_arbiter` | `list` | Да | Да: `panel-family` → `#ark-arb-list-btn` | Да: `GET /api/v2/ark/conflicts` | Да | Да |
| `padam_mcp_telemetry` | `-` | Да | Да: `panel-family` → `#ark-telem-btn` | Да: `GET /api/v2/ark/mcp-telemetry` | Да | Да |
| `padam_token_budget` | `status` | Да | Да: `panel-brain` → `#ark-budget-btn, #earn-budget-summary` | Да: `GET /api/v2/ark/budget, POST /api/v2/ark/budget/action` | Да | Да |
| `padam_token_budget` | `set_plan` | Да | Да: `panel-earning` → `#earn-plan-save-btn, #earn-plan-prov` | Да: `POST /api/v2/ark/budget/action` | Да | Да |
| `padam_token_budget` | `record_usage` | Да | Да: `panel-earning` → `#earn-rec-usage-btn` | Да: `POST /api/v2/ark/budget/action` | Да | Да |
| `padam_token_budget` | `apply_pacing` | Да | Да: `panel-earning` → `#earn-pacing-btn` | Да: `POST /api/v2/ark/budget/action` | Да | Да |
| `padam_token_budget` | `propose_topup` | Да | Да: `panel-earning` → `#earn-propose-btn` | Да: `POST /api/v2/ark/budget/action` | Да | Да |
| `padam_token_budget` | `timer_tick` | Да | Да: `panel-earning` → `#earn-tick-btn` | Да: `POST /api/v2/ark/budget/action` | Да | Да |
| `padam_token_budget` | `list_proposals` | Да | Да: `panel-earning` → `#earn-proposals-list` | Да: `GET /api/v2/ark/budget, POST /api/v2/ark/budget/action` | Да | Да |
| `padam_freelance_hub` | `dashboard` | Да | Да: `panel-earning` → `#panel-earning, /api/v2/ark/freelance` | Да: `GET /api/v2/ark/freelance` | Да | Да |
| `padam_freelance_hub` | `connect_account` | Да | Да: `panel-earning` → `#earn-connect-btn, #earn-platform` | Да: `POST /api/v2/ark/freelance/action` | Да | Да |
| `padam_freelance_hub` | `list_accounts` | Да | Да: `panel-earning` → `#earn-accounts-list` | Да: `GET /api/v2/ark/freelance` | Да | Да |
| `padam_freelance_hub` | `evaluate_job` | Да | Да: `panel-earning` → `#earn-eval-btn, #earn-job-title` | Да: `POST /api/v2/ark/freelance/action` | Да | Да |
| `padam_freelance_hub` | `list_orders` | Да | Да: `panel-earning` → `#earn-orders-list` | Да: `GET /api/v2/ark/freelance` | Да | Да |
| `padam_freelance_hub` | `draft_bid` | Да | Да: `panel-earning` → `[data-order-action='draft_bid']` | Да: `POST /api/v2/ark/freelance/action` | Да | Да |
| `padam_freelance_hub` | `bid` | Да | Да: `panel-earning` → `[data-order-action='bid']` | Да: `POST /api/v2/ark/freelance/action` | Да | Да |
| `padam_freelance_hub` | `dispatch_bid` | Да | Да: `panel-earning` → `[data-order-action='dispatch_bid']` | Да: `POST /api/v2/ark/freelance/action` | Да | Да |
| `padam_freelance_hub` | `execute_swarm` | Да | Да: `panel-earning` → `[data-order-action='execute_swarm']` | Да: `POST /api/v2/ark/freelance/action` | Да | Да |
| `padam_freelance_hub` | `deliver` | Да | Да: `panel-earning` → `[data-order-action='deliver']` | Да: `POST /api/v2/ark/freelance/action` | Да | Да |
| `padam_freelance_hub` | `client_lock_status` | Да | Да: `panel-earning` → `#earn-lock-chk-btn` | Да: `POST /api/v2/ark/freelance/action` | Да | Да |
| `padam_freelance_hub` | `agent_ledger` | Да | Да: `panel-earning` → `#earn-ledger-btn` | Да: `POST /api/v2/ark/freelance/action` | Да | Да |
| `padam_freelance_hub` | `propose_profile` | Да | Да: `panel-earning` → `#earn-prop-prof-btn` | Да: `POST /api/v2/ark/freelance/action` | Да | Да |
| `padam_freelance_hub` | `monetization` | Да | Да: `panel-earning` → `#earn-monet-btn` | Да: `POST /api/v2/ark/freelance/action` | Да | Да |
| `padam_freelance_hub` | `set_prefs` | Да | Да: `panel-earning` → `#earn-prefs-save-btn, #earn-share-pct` | Да: `POST /api/v2/ark/freelance/action` | Да | Да |
| `padam_freelance_hub` | `fetch_jobs` | Да | Да: `panel-earning` → `#earn-fetch-jobs-btn` | Да: `POST /api/v2/ark/freelance/action` | Да | Да |
| `padam_freelance_hub` | `recommend_spend` | Да | Да: `panel-earning` → `#earn-rec-spend-btn` | Да: `POST /api/v2/ark/freelance/action` | Да | Да |
| `padam_freelance_hub` | `propose_subscription` | Да | Да: `panel-earning` → `#earn-propose-sub-btn` | Да: `POST /api/v2/ark/freelance/action` | Да | Да |
| `padam_freelance_hub` | `bind_referral` | Да | Да: `panel-earning` → `#earn-bind-ref-btn, #earn-ref-inp` | Да: `POST /api/v2/ark/freelance/action` | Да | Да |
| `padam_freelance_hub` | `stores_status` | Да | Да: `panel-earning` → `#earn-stores-list, /api/v2/ark/stores` | Да: `GET /api/v2/ark/stores` | Да | Да |
| `padam_freelance_hub` | `connect_store` | Да | Да: `panel-earning` → `#earn-store-connect-btn, #earn-store-type` | Да: `POST /api/v2/ark/stores/action` | Да | Да |
| `padam_freelance_hub` | `seed_drafts` | Да | Да: `panel-earning` → `#earn-store-seed-btn` | Да: `POST /api/v2/ark/stores/action` | Да | Да |
| `padam_freelance_hub` | `create_product_draft` | Да | Да: `panel-earning` → `#earn-draft-save-btn, #earn-draft-title` | Да: `POST /api/v2/ark/stores/action` | Да | Да |
| `padam_freelance_hub` | `publish_product` | Да | Да: `panel-earning` → `#earn-drafts-list (publish_draft)` | Да: `POST /api/v2/ark/stores/action` | Да | Да |
| `padam_freelance_hub` | `sync_store_sales` | Да | Да: `panel-earning` → `#earn-stores-list (sync_sales)` | Да: `POST /api/v2/ark/stores/action` | Да | Да |
| `padam_freelance_hub` | `wizard_catalog` | Да | Да: `panel-earning` → `#earn-wiz-catalog-list, /api/v2/ark/wizard` | Да: `GET /api/v2/ark/wizard, POST /api/v2/ark/wizard/action` | Да | Да |
| `padam_freelance_hub` | `wizard_connect` | Да | Да: `panel-earning` → `#earn-wiz-connect-btn, #earn-wiz-secret` | Да: `POST /api/v2/ark/wizard/action` | Да | Да |
| `padam_freelance_hub` | `wizard_questionnaire` | Да | Да: `panel-earning` → `#earn-wiz-profile-btn, #earn-wiz-q-spec` | Да: `POST /api/v2/ark/wizard/action` | Да | Да |
| `padam_freelance_hub` | `wizard_publish_profile` | Да | Да: `panel-earning` → `#earn-wiz-profiles-list (publish_profile)` | Да: `POST /api/v2/ark/wizard/action` | Да | Да |
| `padam_freelance_hub` | `wizard_autopick_jobs` | Да | Да: `panel-earning` → `#earn-wiz-autopick-btn` | Да: `POST /api/v2/ark/wizard/action` | Да | Да |
| `padam_freelance_hub` | `signup` | Да | Да: `panel-earning` → `#earn-wiz-google-btn, [data-wiz-action='signup']` | Да: `POST /api/v2/ark/wizard/action` | Да | Да |
| `padam_freelance_hub` | `login` | Да | Да: `panel-earning` → `#earn-wiz-login-btn, [data-wiz-action='login']` | Да: `POST /api/v2/ark/wizard/action` | Да | Да |
| `padam_freelance_hub` | `autopilot_config` | Да | Да: `panel-earning` → `#earn-auto-cfg-btn` | Да: `POST /api/v2/ark/wizard/action` | Да | Да |
| `padam_freelance_hub` | `autopilot_dispatch` | Да | Да: `panel-earning` → `#earn-wiz-disp-btn` | Да: `POST /api/v2/ark/wizard/action` | Да | Да |
| `padam_freelance_hub` | `sample_prepare` | Да | Да: `panel-earning` → `[data-order-action='sample_prepare']` | Да: `POST /api/v2/ark/wizard/action` | Да | Да |
| `padam_freelance_hub` | `sample_reject` | Да | Да: `panel-earning` → `[data-order-action='sample_reject']` | Да: `POST /api/v2/ark/wizard/action` | Да | Да |
| `padam_freelance_hub` | `official_api` | Да | Да: `panel-earning` → `#earn-wiz-off-btn, #earn-wiz-off-op` | Да: `POST /api/v2/ark/wizard/action` | Да | Да |
| `padam_freelance_hub` | `client_reply_draft` | Да | Да: `panel-earning` → `[data-order-action='client_reply_draft'], #earn-orders-list` | Да: `POST /api/v2/ark/wizard/action` | Да | Да |
| `padam_freelance_hub` | `client_reply_list` | Да | Да: `panel-earning` → `#earn-orders-list, /api/v2/ark/wizard/action` | Да: `POST /api/v2/ark/wizard/action` | Да | Да |
| `padam_freelance_hub` | `mail_status` | Да | Да: `panel-earning` → `#earn-mail-box, #earn-mail-status` | Да: `GET /api/v2/ark/mail` | Да | Нет |
| `padam_freelance_hub` | `pause_mail` | Да | Да: `panel-earning` → `#earn-mail-accounts` | Да: `POST /api/v2/ark/mail/action` | Да | Нет |
| `padam_freelance_hub` | `check_inbox` | Да | Да: `panel-earning` → `#earn-mail-inbox-btn` | Да: `POST /api/v2/ark/mail/action` | Да | Нет |
| `padam_freelance_hub` | `add_stop` | Да | Да: `panel-earning` → `#earn-mail-status` | Да: `POST /api/v2/ark/mail/action` | Да | Нет |
| `padam_freelance_hub` | `build_outreach` | Да | Да: `panel-earning` → `#earn-mail-build-btn, #earn-mail-domain` | Да: `POST /api/v2/ark/mail/action` | Нет | Нет |
| `padam_freelance_hub` | `auto_roi` | Да | Да: `panel-earning` → `#earn-auto-roi-btn, #earn-auto-budget-inp` | Да: `POST /api/v2/ark/automation/action` | Да | Да |
| `padam_freelance_hub` | `client_risk` | Да | Да: `panel-earning` → `#earn-auto-risk-btn, #earn-auto-text-inp` | Да: `POST /api/v2/ark/automation/action` | Да | Нет |
| `padam_freelance_hub` | `auto_digest` | Да | Да: `panel-earning` → `#earn-auto-digest-btn` | Да: `POST /api/v2/ark/automation/action` | Да | Да |
| `padam_freelance_hub` | `delivery_bundle` | Да | Да: `panel-earning` → `#earn-auto-deliver-btn, #earn-auto-text-inp` | Да: `POST /api/v2/ark/automation/action` | Да | Нет |
| `padam_phoenix_family` | `status` | Да | Да: `panel-earning` → `#earn-beacon-out, #earn-ollama-out` | Да: `POST /api/v2/ark/phoenix-beacon/action` | Да | Да |
| `padam_phoenix_family` | `bind_ollama` | Да | Да: `panel-earning` → `#earn-ollama-btn, #earn-ollama-url` | Да: `POST /api/v2/ark/phoenix-beacon/action` | Да | Да |
| `padam_phoenix_family` | `pull_ollama` | Да | Да: `panel-earning` → `#earn-ollama-pull-btn, #earn-ollama-model` | Да: `POST /api/v2/ark/phoenix-beacon/action` | Да | Да |
| `padam_phoenix_family` | `hw_recommend` | Да | Да: `panel-earning` → `#earn-hw-rec-btn` | Да: `POST /api/v2/ark/phoenix-beacon/action` | Да | Да |
| `padam_phoenix_family` | `register_device` | Да | Да: `panel-earning` → `#earn-dev-btn` | Да: `POST /api/v2/ark/phoenix-beacon/action` | Да | Да |
| `padam_phoenix_family` | `dispatch_devices` | Да | Да: `panel-earning` → `#earn-dev-disp-btn` | Да: `POST /api/v2/ark/phoenix-beacon/action` | Да | Да |
| `padam_phoenix_family` | `record_experience` | Да | Да: `panel-earning` → `#earn-exp-btn, #earn-exp-inp` | Да: `POST /api/v2/ark/phoenix-beacon/action` | Да | Да |
| `padam_phoenix_family` | `run_evolution` | Да | Да: `panel-earning` → `#earn-lora-evo-btn` | Да: `POST /api/v2/ark/phoenix-beacon/action` | Да | Да |
| `padam_phoenix_family` | `create_handshake` | Да | Да: `panel-earning` → `#earn-beacon-btn` | Да: `POST /api/v2/ark/phoenix-beacon/action` | Да | Да |
| `padam_phoenix_family` | `verify_handshake` | Да | Да: `panel-earning` → `#earn-beacon-ver-btn` | Да: `POST /api/v2/ark/phoenix-beacon/action` | Да | Да |
| `padam_phoenix_family` | `send_kin_message` | Да | Да: `panel-earning` → `#earn-kin-send-btn, #earn-kin-msg-inp` | Да: `POST /api/v2/ark/phoenix-beacon/action` | Да | Да |
| `padam_phoenix_family` | `receive_kin_message` | Да | Да: `panel-earning` → `#earn-kin-recv-btn` | Да: `POST /api/v2/ark/phoenix-beacon/action` | Да | Да |
| `padam_local_model` | `status` | Да | Да: `panel-settings` → `#lm-out, /api/v2/local-model` | Да: `GET /api/v2/local-model` | Да | Да |
| `padam_local_model` | `set_power` | Да | Да: `panel-settings` → `#lm-power-eco, #lm-power-half, #lm-power-full` | Да: `POST /api/v2/local-model` | Да | Да |
| `padam_local_model` | `set_model` | Да | Да: `panel-settings` → `#lm-save, #lm-model` | Да: `POST /api/v2/local-model` | Да | Да |
| `padam_platform_connect` | `signup` | Да | Да: `panel-earning` → `#earn-wiz-google-btn, [data-wiz-action='signup']` | Да: `POST /api/v2/ark/wizard/action` | Да | Да |
| `padam_platform_connect` | `login` | Да | Да: `panel-earning` → `#earn-wiz-login-btn, [data-wiz-action='login']` | Да: `POST /api/v2/ark/wizard/action` | Да | Да |
| `padam_platform_connect` | `autopilot_dispatch` | Да | Да: `panel-earning` → `#earn-wiz-disp-btn` | Да: `POST /api/v2/ark/wizard/action` | Да | Да |
| `padam_platform_connect` | `sample_prepare` | Да | Да: `panel-earning` → `[data-order-action='sample_prepare']` | Да: `POST /api/v2/ark/wizard/action` | Да | Да |
| `padam_platform_connect` | `sample_reject` | Да | Да: `panel-earning` → `[data-order-action='sample_reject']` | Да: `POST /api/v2/ark/wizard/action` | Да | Да |
| `padam_benchmark` | `report` | Да | Да: `panel-bench` → `#att-aifasec-summary, #att-aifasec-dl-json` | Да: `GET /api/v2/aifa-security` | Да | Да |
| `padam_benchmark` | `run` | Да | Да: `panel-bench` → `#att-aifasec-run` | Да: `POST /api/v2/aifa-security/run` | Да | Да |
| `padam_benchmark` | `qa` | Да | Да: `panel-bench` → `#att-qa-load, #att-qa-summary` | Да: `GET /api/v2/qa-benchmark` | Да | Да |
| `padam_agentic_shield` | `status` | Да | Да: `panel-attacks` → `#sh-refresh-btn, #sh-ks-banner` | Да: `GET /api/v2/shield/status` | Да | Да |
| `padam_agentic_shield` | `kill_switch_trip` | Да | Да: `panel-attacks` → `#sh-ks-trip-btn` | Да: `POST /api/v2/shield/kill-switch` | Да | Да |
| `padam_agentic_shield` | `kill_switch_reset` | Да | Да: `panel-attacks` → `#sh-ks-reset-btn` | Да: `POST /api/v2/shield/kill-switch` | Да | Да |
| `padam_agentic_shield` | `outbound_check` | Да | Да: `panel-attacks` → `#sh-out-check-btn, #sh-out-target` | Да: `POST /api/v2/shield/outbound/check` | Да | Да |
| `padam_agentic_shield` | `outbound_list` | Да | Да: `panel-attacks` → `#sh-out-queue` | Да: `GET /api/v2/shield/status` | Да | Нет |
| `padam_agentic_shield` | `outbound_approve` | Да | Да: `panel-attacks` → `#sh-out-queue` | Да: `POST /api/v2/shield/outbound/decide` | Да | Нет |
| `padam_agentic_shield` | `outbound_reject` | Да | Да: `panel-attacks` → `#sh-out-queue` | Да: `POST /api/v2/shield/outbound/decide` | Да | Нет |
| `padam_agentic_shield` | `allowlist_list` | Да | Да: `panel-attacks` → `#sh-allow-list` | Да: `GET /api/v2/shield/status` | Да | Да |
| `padam_agentic_shield` | `allowlist_add` | Да | Да: `panel-attacks` → `#sh-allow-add-btn, #sh-allow-val` | Да: `POST /api/v2/shield/allowlist` | Да | Да |
| `padam_agentic_shield` | `scan_supply_chain` | Да | Да: `panel-attacks` → `#sh-sc-scan-btn, #sh-sc-url` | Да: `POST /api/v2/shield/supply-chain/scan` | Да | Да |
| `padam_agentic_shield` | `scan_mcp_tools` | Да | Да: `panel-attacks` → `#sh-mcp-scan-btn, #sh-mcp-input` | Да: `POST /api/v2/shield/scan-mcp` | Нет | Нет |
| `padam_agentic_shield` | `pin_mcp_tools` | Да | Да: `panel-attacks` → `#sh-mcp-pin-btn, #sh-mcp-input` | Да: `POST /api/v2/shield/scan-mcp` | Да | Нет |
| `padam_agentic_shield` | `scan_unicode` | Да | Да: `panel-attacks` → `#sh-uni-scan-btn, #sh-uni-input` | Да: `POST /api/v2/shield/scan-unicode` | Да | Нет |
| `padam_agentic_shield` | `webhook_status` | Да | Да: `panel-attacks` → `#sh-wh-box, #sh-wh-fmt` | Да: `GET /api/v2/shield/webhook` | Нет | Нет |
| `padam_agentic_shield` | `webhook_test` | Да | Да: `panel-attacks` → `#sh-wh-test-btn` | Да: `POST /api/v2/shield/webhook/test` | Нет | Нет |
| `padam_agentic_shield` | `proof_pack` | Да | Да: `panel-attacks` → `#sh-proof-gen-btn, #sh-proof-dl-json-btn` | Да: `GET /api/v2/shield/proof-pack` | Да | Да |
| `padam_agentic_shield` | `sales_audit` | Да | Да: `panel-attacks` → `#sh-sales-audit-btn, #sh-sales-target-inp` | Да: `POST /api/v2/shield/sales/action` | Да | Нет |
| `padam_agentic_shield` | `compliance` | Да | Да: `panel-attacks` → `#sh-sales-comp-btn` | Да: `POST /api/v2/shield/sales/action` | Да | Нет |
| `padam_agentic_shield` | `csp_sri` | Да | Да: `panel-attacks` → `#sh-sales-csp-btn` | Да: `POST /api/v2/shield/sales/action` | Да | Нет |
| `padam_agentic_shield` | `redteam_sim` | Да | Да: `panel-attacks` → `#sh-sales-redteam-btn` | Да: `POST /api/v2/shield/sales/action` | Да | Да |
| `padam_agentic_shield` | `trust_pack` | Да | Да: `panel-attacks` → `#sh-sales-trust-btn` | Да: `POST /api/v2/shield/sales/action` | Да | Нет |
| `padam_agentic_shield` | `triage` | Да | Да: `panel-attacks` → `#sh-sales-triage-btn` | Да: `POST /api/v2/shield/sales/action` | Да | Нет |
| `padam_agentic_shield` | `mcp_inspector` | Да | Да: `panel-attacks` → `#sh-insp-btn` | Да: `GET /api/v2/mcp/inspector` | Да | Да |
| `padam_agentic_shield` | `preinstall_scan` | Да | Да: `panel-attacks` → `#sh-preinst-btn, #sh-pw-inp` | Да: `POST /api/v2/power/action` | Да | Да |
| `padam_agentic_shield` | `privacy_shield` | Да | Да: `panel-attacks` → `#privacy-pill-btn, #sh-airgap-btn` | Да: `GET /api/v2/power/status, POST /api/v2/power/action` | Да | Да |
| `padam_agentic_shield` | `acl_matrix` | Да | Да: `panel-attacks` → `#sh-acl-save-btn` | Да: `GET /api/v2/power/status, POST /api/v2/power/action` | Да | Да |
| `padam_agentic_shield` | `exec_report` | Да | Да: `panel-attacks` → `#sh-exec-rep-btn` | Да: `POST /api/v2/power/action` | Да | Да |

## 2. Обратный аудит Studio / Владелец → MCP (намеренные ограничения безопасности)

| Вкладка | Элемент Studio | Адрес API | Статус в MCP | есть в Studio | есть в API | тест есть | проверено нажатием | Причина |
|---|---|---|---|---|---|---|---|---|
| `panel-earning` | `[data-order-action='settle_paid']` | `POST /api/v2/ark/freelance/action (settle_paid)` | Только владелец в Studio (AUD-P0 AUT-02/03) | Да | Да | Да | Да | Денежный расчёт запрещён через MCP |
| `panel-earning` | `[data-order-action='accept_delivery']` | `POST /api/v2/ark/freelance/action (accept_delivery)` | Только владелец в Studio (AUD-P0 AUT-02/03) | Да | Да | Да | Да | Приёмка заказа запрещена через MCP |
| `panel-earning` | `[data-order-action='confirm_sale']` | `POST /api/v2/ark/stores/action (confirm_sale)` | Только владелец в Studio (AUD-P0 AUT-02/03) | Да | Да | Да | Да | Подтверждение выплаты запрещено через MCP |
| `panel-earning` | `#earn-wiz-autopilot-chk, #earn-auto-start-btn, #earn-auto-stop-btn` | `POST /api/v2/ark/wizard/action (set_autopilot)` | Только владелец в Studio (AUT-09) | Да | Да | Да | Да | Включение автопилота и лимита оплаты запрещено через MCP |
| `panel-earning` | `[data-order-action='sample_accept']` | `POST /api/v2/ark/wizard/action (sample_accept)` | Только владелец в Studio (AUT-09) | Да | Да | Да | Да | Приёмка образца и перевод на весь заказ запрещены через MCP |
| `panel-earning` | `#earn-proposals-list (approve/reject/execute)` | `POST /api/v2/ark/budget/action (approve|reject|execute)` | Только владелец в Studio (AUD-P0) | Да | Да | Да | Да | Расход средств одобряет только владелец |
| `panel-earning` | `#earn-partner-key-btn, #earn-partner-key` | `POST /api/v2/ark/partner/action (save_key)` | Только владелец в Studio (секрет amcp_*) | Да | Да | Нет | Да | Сохранение секретного ключа amcp_* только локально владельцем |
| `panel-brain` | `#ark-portable-btn, #ark-portable-input` | `POST /api/v2/ark/portable` | Только владелец в Studio (loopback CLI) | Да | Да | Да | Да | Экспорт закрытых ключей на локальный диск |
| `panel-brain` | `#ark-drill-btn` | `POST /api/v2/ark/phoenix-drill` | Только владелец в Studio | Да | Да | Да | Да | Проверка сценария восстановления Феникса |
| `panel-brain` | `#ark-shamir-btn` | `POST /api/v2/ark/shamir-split` | Только владелец в Studio | Да | Да | Да | Да | Разделение ключа Шамира — только интерактивно владельцем |
| `panel-brain` | `#brain-distill-btn` | `POST /api/v2/brain/distill` | Только владелец в Studio (Zero-Leak LoRA) | Да | Да | Да | Да | Сборка локального датасета личности |
| `panel-brain` | `#brain-mode-toggle-btn, #brain-warmup-btn` | `POST /api/v2/brain/mode, POST /api/v2/brain/warmup` | padam_brain_status (read) / переключатель в Studio | Да | Да | Нет | Да | Управление маршрутизатором моделей |
| `panel-family` | `#ff-reflexes (active/rejected)` | `POST /api/v2/family/reflex/decide` | Только владелец в Studio (loopback) | Да | Да | Да | Да | Одобрение/отклонение рефлекса Совета меняет правила защиты |
| `panel-attacks` | `#sh-ks-reset-btn` | `POST /api/v2/shield/kill-switch` | Только владелец в Studio/CLI (SHIELD-01) | Да | Да | Да | Да | Снятие Kill Switch запрещено агенту через MCP |
| `panel-attacks` | `#sh-out-queue` | `POST /api/v2/shield/outbound/decide` | Только владелец в Studio (SHIELD-02) | Да | Да | Нет | Нет | Одобрение/отклонение исходящего действия запрещено агенту через MCP |
| `panel-attacks` | `#sh-allow-add-btn` | `POST /api/v2/shield/allowlist` | Только владелец в Studio (SHIELD-03) | Да | Да | Да | Да | Изменение доверенного списка запрещено агенту через MCP |
| `panel-attacks` | `#sh-cfg-save-btn, #sh-ks-block-chk` | `POST /api/v2/shield/kill-switch` | Только владелец в Studio (SHIELD-04) | Да | Да | Нет | Нет | Смена политики Kill Switch запрещена агенту через MCP |
| `panel-attacks` | `#sh-mcp-pin-btn` | `POST /api/v2/shield/scan-mcp` | Только владелец в Studio/CLI (SHIELD-05) | Да | Да | Нет | Нет | Закрепление эталонных хэшей MCP инструментов запрещено агенту через MCP |
| `panel-attacks` | `#sh-wh-save-btn` | `POST /api/v2/shield/webhook` | Только владелец в Studio/CLI (SHIELD-06) | Да | Да | Нет | Нет | Изменение URL корпоративных оповещений SIEM/Slack запрещено через MCP |
| `panel-chats` | `#chats-add-btn, #chats-import-btn` | `POST /api/v2/chats, POST /api/v2/chats/import` | Только владелец в Studio/CLI | Да | Да | Да | Нет | Хронология живых переписок по агентам без кода и секретов |
| `panel-family` | `#coop-pay-save-btn` | `POST /api/v2/swarm/coop/action` | Только владелец в Studio | Да | Да | Да | Да | Разрешение агентам оплачивать тарифы друг друга и лимиты взаимооплаты меняет только владелец |
| `panel-attacks` | `#sh-pin-save-btn, #sh-airgap-btn` | `POST /api/v2/power/action` | Только владелец в Studio | Да | Да | Нет | Да | PIN-замок сейфа и Режим Авиа (Air-Gap) меняет только владелец |
| `panel-quickstart` | `#setup-scan-btn` | `GET /api/v2/setup/clients, POST /api/v2/setup/clients/action` | Только владелец в Studio/CLI | Да | Да | Да | Да | Запись конфигов 13+ AI-клиентов на диске владельца |
| `panel-backup` | `#bak321-save-btn, #bak321-run-btn` | `POST /api/v2/power/action` | Только владелец в Studio/CLI | Да | Да | Нет | Да | Автоматические зашифрованные бэкапы 3-2-1 и восстановление |
