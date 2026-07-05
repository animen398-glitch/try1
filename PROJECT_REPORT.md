# Advanced Site Analyzer — Отчёт о состоянии проекта

> Снимок на 2026-06-13, обновлён 2026-06-23 (эпик ASM 2.0 F1–F6 + пост-эпик +
> Advanced Intelligence Framework EPIC 8–16 + EPIC NEXT business-risk слой).
> Update 2026-06-28: KEV/EPSS Threat Intelligence Feed (CISA KEV + FIRST EPSS
> per-CVE enrichment → priority via threat_tier; cache in CVEStore, derive-on-read
> annotation, opt-in collection phase, report/web/CSV surfaces) closed locally on
> top of Workbench v2; full pytest 2101 passed, ruff clean, GUI self-check 29
> tabs. The priority/risk formula was not changed.
> Update 2026-06-28 (KEV/EPSS follow-ups, epic fully closed): KEV→SLA tightening
> (exploitability shortens the remediation window; floor-only) wired into the
> report, Alert Center, Timeline, GUI and web; NEW_KEV timeline event + KEV alert
> rule; KEV/EPSS exploitability badge in the findings detail; opt-in EPSS
> daily-CSV bulk ingestion. Current scale: **full pytest 2127 passed**, ruff
> clean, 1 existing Starlette/httpx warning. Priority/risk formula still unchanged.
> Update 2026-06-28 (Mission Center M1): new strategic layer started — a pure,
> offline, deterministic mission core contract (`core/pentest_mission.py` +
> `schemas/asa_pentest_mission.schema.json`) over the existing Audit Runs /
> FindingsStore / Scope / ROE, with no second store and client-safe guardrails
> reused from `audit_scope`/`audit_templates`/`action_policy`. Persistence/GUI/web
> deferred to M2+. Current scale: **full pytest 2162 passed**, ruff clean,
> 1 existing Starlette/httpx warning.
> Update 2026-06-28 (Mission Center M2): mission persistence + project bundle —
> `core/mission_store.py` (`MissionStore`, single-table, no event log; mirrors
> `AuditRunStore`), an events-less `PROJECT_EXPORT` generalization in
> `utils/sqlite_store.py`, and `missions.json` in the `core/project_io` bundle
> (`FORMAT_VERSION` unchanged, backward-compatible). No second findings/asset/
> timeline source; GUI/web/timeline deferred to M3+. Current scale: **full pytest
> 2177 passed**, ruff clean, 1 existing Starlette/httpx warning.
> Update 2026-06-29 (Mission Center M3): thin read/parity surfaces over the
> persisted missions — a `gui/tab_missions.py` Missions tab (view + status-advance
> + add-links), web read-parity (`/missions`, `/missions/{id}`), and derive-on-read
> mission events in `core/timeline.py` (`build_events(..., missions=)`). No new
> store/state; reuses `pentest_mission`/`MissionStore`. Current scale: **full pytest
> 2200 passed**, ruff clean, self-check 30 tabs, 1 existing Starlette/httpx warning.
> Update 2026-06-29 (Mission Center M4): run a mission as an Audit Run. The audit
> orchestration is extracted from the GUI into `core/audit_runner.py` (shared seam),
> and `core/mission_runner.py` runs a ready mission (ready→running→completed/failed,
> auto-links the run) with a GUI "Run mission" button + `POST /missions/{id}/run`.
> No second store. Current scale: **full pytest 2209 passed**, ruff clean,
> self-check 30 tabs, 1 existing Starlette/httpx warning.
> Update 2026-06-29 (Mission Center M5): the mission report — `core/mission_report.py`
> assembles an evidence-first view (envelope + linked audit runs' findings, reusing
> `core/audit_report`, + an appendix of explicitly linked findings) with pure
> JSON/MD/HTML renderers, surfaced as GUI export buttons + `GET /missions/{id}/report[.md]`.
> A view, no second store. Current scale: **full pytest 2216 passed**, ruff clean,
> self-check 30 tabs, 1 existing Starlette/httpx warning.
> Update 2026-06-29 (Mission Center M6): mission creation from the surfaces — a
> "Create mission" panel on the Missions tab + web `POST /missions`, both reusing
> `pentest_mission.create_mission` + `validate_mission` (client-safe gate) before
> `MissionStore.save_mission`. No new core. Current scale: **full pytest 2220
> passed**, ruff clean, self-check 30 tabs, 1 existing Starlette/httpx warning.
> Update 2026-06-29 (Mission Center M7): a portfolio overview — `core/mission_overview.py`
> aggregates missions (counts by status + each mission's last-run outcome via
> `core/audit_report`) as a derive-on-read view, surfaced as a Missions card on the
> Overview tab + `GET /missions/overview`. No new state. Current scale: **full pytest
> 2227 passed**, ruff clean, self-check 30 tabs, 1 existing Starlette/httpx warning.
> Update 2026-06-29 (Mission Center M8): timeline run events — `core/timeline.build_events`
> gains `mission_runs`, emitting mission_run_started / mission_run_completed|failed
> events (section 'missions') for each executed mission's linked audit run;
> `build_timeline` resolves the runs so build_events stays a pure shaper. No surface
> changes (the 'missions' section renders generically since M3). Current scale: **full
> pytest 2229 passed**, ruff clean, self-check 30 tabs, 1 existing Starlette/httpx warning.
> Update 2026-06-29 (Mission Center M9): recurring scheduling — `core/mission_schedule.py`
> re-runs a mission on a cadence (reusing monitor's compute_next_run/is_due) by building
> its audit run + linking it WITHOUT touching the one-shot status machine; schedule state
> is a new `missions.schedule` column (MissionStore v2, separate from the payload), with
> GUI controls + `POST /missions/{id}/schedule` and `POST /missions/run-due`. Current scale:
> **full pytest 2240 passed**, ruff clean, self-check 30 tabs, 1 existing Starlette/httpx warning.
> Update 2026-06-29 (Mission Center M10): scheduling auto-tick — due missions now run
> automatically on the monitor tick, wired at the driver level via a generic
> `MonitorScheduler.extra_tick` (the monitor engine stays decoupled), surfaced through the
> existing event bridge / `monitor.format_event` in both the in-app scheduler and
> `monitor_cli run/watch`. Opt-in. Current scale: **full pytest 2245 passed**, ruff clean,
> self-check 30 tabs, 1 existing Starlette/httpx warning.
> Update 2026-06-29 (Mission Center M11): link integrity (closes M1 D4) — `core/mission_links.py`
> adds opt-in `link_audit_run_checked`/`link_finding_checked` (validate existence before the
> pure linker) + `resolve_links` (present vs stale partition); the Missions tab links are now
> checked and the detail flags stale links. `pentest_mission` stays pure. Current scale: **full
> pytest 2251 passed**, ruff clean, self-check 30 tabs, 1 existing Starlette/httpx warning.
> Update 2026-06-29 (Mission Center M12): the demo workspace (`demo_seed.py`) now seeds 3
> missions on the first project (ready+scheduled, executed with a linked run+finding, one with
> a stale link), so the whole M1-M11 Mission Center is visible end-to-end in the demo. Current
> scale: **full pytest 2252 passed**, ruff clean, self-check 30 tabs, 1 existing Starlette/httpx warning.
> Update 2026-06-29 (Mission Center M13): mission CSV export — `report_export.missions_csv`
> exports the mission portfolio (overview rows) via the shared `_rows_to_csv`, surfaced as an
> "Export CSV" button on the Missions tab + `GET /missions.csv`. Closes the planned M1-M13 arc.
> Current scale: **full pytest 2256 passed**, ruff clean, self-check 30 tabs, 1 existing Starlette/httpx warning.
> Update 2026-06-29 (Mission Center M14): stale-link cleanup — `mission_links.prune_stale_links`
> rebuilds a mission keeping only present run/finding links (pure; `pentest_mission` untouched),
> surfaced as a "Remove stale" button + `POST /missions/{id}/links/prune`. Closes the M1-M14 arc.
> Current scale: **full pytest 2261 passed**, ruff clean, self-check 30 tabs, 1 existing Starlette/httpx warning.
> Update 2026-06-29 (Mission Center M15): mission run trend — `mission_overview.mission_run_trend`
> derives a per-mission run history (client-facing count per linked audit run, time-ordered),
> shown as a "Run history" list in the Missions detail + `GET /missions/{id}/runs`. Closes the
> M1-M15 arc (Mission Center feature-complete). Current scale: **full pytest 2266 passed**, ruff
> clean, self-check 30 tabs, 1 existing Starlette/httpx warning.
> Update 2026-06-30 (Safe Pentest Tool Layer — pure stack): a self-contained, offline contract
> for wiring external recon/audit tools to a mission WITHOUT running them — `core/tool_adapter.py`
> (capability registry + ROE-gated `evaluate_tool_allowed_for_mission` + `asa_tool_run` schema) →
> `core/tool_parsers.py` (per-tool parsers over already-captured evidence; all 8 registry tools) →
> `core/tool_pipeline.py` (`assemble_tool_run`: gate→parse→map) → `core/tool_ingest.py` (bridge to
> canonical Finding/Asset DTOs) → `core/tool_report.py` (JSON/MD/HTML renderer). No store writes, no
> network, no new deps; the tool is never executed.
> Update 2026-06-30 (Tool Layer — store-writing): `core/tool_ingest_store.ingest_tool_run` (gated,
> idempotent persist of a completed run into the existing FindingsStore/AssetStore) + the capstone
> `core/tool_runner.run_tool_for_mission` (composes `assemble_tool_run` + `ingest_tool_run`, mirrors
> `mission_runner.run_mission`). Crosses the no-store boundary; the pure stack stays unchanged
> beneath it. Current scale: **full pytest 2310 passed**, ruff clean, self-check 30 tabs.
> Update 2026-06-30 (Tool Layer — surfaces): the orchestrator is wired into the GUI Missions tab
> ("Run tool", evidence-driven) + web `POST /missions/{id}/tools/run`; tool runs surface in the
> timeline as a derive-on-read `tool_run` event (scan-id convention centralized in
> `tool_runner.tool_scan_id`/`parse_tool_scan_id`, replacing the duplicated inline string); and
> `report_export.tool_runs_csv` exports them (Timeline tab "Export tool runs" + `GET /tool-runs.csv`).
> No second store — tool runs are derived from the ingested items' synthetic scan id. Current scale:
> **full pytest 2334 passed**, ruff clean, self-check 30 tabs, 1 existing Starlette/httpx warning.
> Update 2026-06-30 (Web Console Auth & Safe Bind): closed the #1 stability/safety gap — the LAN
> console gained mutating endpoints (mission run, tool-run → store ingestion) while still binding
> `0.0.0.0` with no auth. `resolve_web_console` defaults the bind to `127.0.0.1` (LAN = explicit opt-in
> via `web_console.allow_lan`); one app-wide `require_token` dependency gates every endpoint except the
> static `/` shell (Bearer or `?token=`, constant-time); loopback+no-token stays open (single-user),
> a LAN bind with no token auto-generates one (`secrets.token_urlsafe`). Token from `web_console.token`
> / `ASA_WEB_TOKEN`; dashboard JS attaches it. No new deps. Current scale: **full pytest 2342 passed**,
> ruff clean, self-check 30 tabs, 1 existing Starlette/httpx warning.
> Update 2026-06-30 (Scan Retention & Backup): two ops-maturity gaps. **Retention** (`core/retention.py`)
> prunes old scan *artifact* dirs beyond a keep-last/keep-days policy while keeping the `metadata.json`
> index + `history/` snapshots (risk trend intact, findings never orphaned); `retention` block in
> settings, off by default; auto-prune after a Full Collection + an Overview "Prune old scans" button.
> **Backup** (`core/backup.py`) snapshots the whole data root (SQLite via the online-backup API, WAL-safe)
> + the Projects workspace into one timestamped `.zip`; `restore_backup` is zip-slip guarded and
> non-clobbering by default; Overview "Backup all…" / "Restore…" buttons. Stdlib only. Current scale:
> **full pytest 2361 passed**, ruff clean, self-check 30 tabs, 1 existing Starlette/httpx warning.
> Update 2026-06-30 (GUI table pagination): the heavy tables loaded every row into the widget at once,
> freezing the UI on a large estate. `gui/ui_components.TablePaginator` renders a large (already
> queried/filtered/sorted) row list into a `QTableWidget` one page at a time via a render callback,
> with a First/◀/▶/Last + page-size control strip; `record_at` maps a table row back to the full-list
> record so selection/detail keep working. Applied to the three highest-volume tables — Findings, Assets,
> Timeline — each keeping its full list for selection + CSV export. UI windowing only; the data layer is
> untouched. Current scale: **full pytest 2368 passed**, ruff clean, self-check 30 tabs, 1 existing
> Starlette/httpx warning.
> Update 2026-06-30 (Interactive attack-path graph): the cloud classifier, attack-path engine and
> attack-surface tab ALREADY existed (`core/cloud_classifier.py`, `intelligence.build_attack_paths` +
> `core/correlation.py`, `gui/tab_attack_paths.py`), so only the missing visual was added — no
> duplication. `gui/attack_graph_view.AttackGraphView` (QGraphicsView) draws one ranked path as a
> deterministic layered Entry→Pivot→Targets node-edge diagram (stdlib Qt, target fan-out capped with a
> "+N more" node, click → node_clicked), wired into the Attack Paths tab below the ranked table over the
> existing `load_attack_paths` data. Current scale: **full pytest 2375 passed**, ruff clean, self-check
> 30 tabs, 1 existing Starlette/httpx warning.
> Update 2026-06-30 (Finding assignment & comments triage): DefectDojo-style triage on top of the
> lifecycle/SLA, event-sourced over `finding_events` (no second store, no migration). `findings_store`
> gains assign/get_assignee/assignees (latest ASSIGNED wins, '' unassigns) + add_comment/comments
> (append-only). Surfaced as a "Триаж" row + detail thread on the Findings tab and web endpoints
> `POST /findings/{id}/assign`, `POST /findings/{id}/comment`, `GET /findings/{id}/triage`. Closes the
> last named gap-analysis item. Current scale: **full pytest 2383 passed**, ruff clean, self-check 30
> tabs, 1 existing Starlette/httpx warning.
> Update 2026-06-30 (Captured-scan → tool-evidence bridge): `core/tool_evidence.py` maps a loaded scan
> `report.json` to the exact evidence shape a `tool_parsers` parser consumes, so a tool run can be driven
> from already-captured data instead of pasted JSON. Pure dict→dict + an additive extractor registry;
> verified extractors source_map_finder (recon.source_maps) and safe_active_prober (subdomains), others
> additive. `available_tools(report)` lists what's bridgeable; a round-trip test proves the output parses
> through `parse_tool_output`. No new data path. Current scale: **full pytest 2389 passed**, ruff clean,
> self-check 30 tabs, 1 existing Starlette/httpx warning.
> Update 2026-06-30 (Tool-evidence surface wiring): `tool_evidence.evidence_from_project_scan` (thin
> loader over ProjectStore/load_scan_report) drives the bridge from a project's scan. The Missions "Run
> tool" panel gains an «Из скана» button that fills the evidence field from the mission's project scan
> (operator reviews/edits, then Run), and web `POST /missions/{id}/tools/run` gains `from_scan` (pull
> evidence from the scan when no evidence supplied). Run flow + the tool-never-executed invariant
> unchanged. Current scale: **full pytest 2394 passed**, ruff clean, self-check 30 tabs, 1 existing
> Starlette/httpx warning.
> Update 2026-06-30 (Tool-evidence header+cookie extractors): two verified extractors added to
> `tool_evidence.EXTRACTORS` — header_audit (from `recon.data.security_headers`) and cookie_audit (from
> the cookies phase). dependency_auditor deliberately not bridged (recon stores only the audit result,
> not raw scripts/html; those findings are already in FindingsStore). Surface auto-fill works for both
> with no changes (it is generic over the registry). Current scale: **full pytest 2400 passed**, ruff
> clean, self-check 30 tabs, 1 existing Starlette/httpx warning.
> Update 2026-07-01 (e2e/GUI tests): the GUI suite tested handlers in isolation; added a deterministic
> headless e2e layer — `tests/gui_test_helpers._SyncRunMixin` runs `_run_async` inline (no QThread) +
> reusable FindingsE2EHost/MissionsE2EHost, and `tests/test_gui_e2e.py` drives genuine button clicks
> (`QAbstractButton.click()`) through the full handler→worker→callback→store/UI chain: Findings
> assign/comment/status, Missions run-tool + «Из скана». Existing hosts/tests untouched. Current scale:
> **full pytest 2406 passed**, ruff clean, self-check 30 tabs, 1 existing Starlette/httpx warning.
> Update 2026-07-01 (more table pagination): applied TablePaginator to the remaining high-volume tables —
> Dashboard endpoints (drops the old [:200] cap), Intelligence, Accuracy; each keeps its full list for
> selection + CSV and maps via record_at. Subdomain left as-is (streaming/in-place-updated table, bounded
> per scan); the other table tabs are bounded-small. Current scale: **full pytest 2409 passed**, ruff
> clean, self-check 30 tabs, 1 existing Starlette/httpx warning.
> Update 2026-07-01 (Engagement & ROE Foundation — backend F1–F4): started the Authorized/Client-Safe
> Pentest Workbench's top-level entity. `core/engagement.py` (pure contract: client+project → scope/ROE/
> authorization + links to missions/audit-runs/findings; lifecycle draft→authorized→active→reporting⇄
> retest→closed→archived), `core/engagement_store.py` (single-table SQLite + project-bundle export/import),
> `core/engagement_links.py` (store-checked links + present/stale resolve/prune), `core/engagement_report.py`
> (evidence-first deliverable reusing audit_report, JSON/MD/HTML). Reuses audit_scope/audit_schema; no new
> attack capabilities. Backend only — GUI/Web surfaces deferred to a separate step. Current scale: **full
> pytest 2453 passed**, ruff clean, self-check 30 tabs, 1 existing Starlette/httpx warning.
> Update 2026-07-01 (Engagement surfaces S1–S4): added all engagement surfaces over the backend —
> timeline events (`timeline.build_events(engagements=)`), web parity (`/engagements` CRUD + advance/link/
> prune/report), `demo_seed` engagement, and a GUI **Engagements** tab (`gui/tab_engagement`, mirrors
> tab_missions: create/advance/link/prune/report), registered in plugin_manager/main_window (now 31 tabs).
> Thin surfaces; no second store. Engagement epic (F1–F4 + S1–S4) complete. Current scale: **full pytest
> 2472 passed**, ruff clean, self-check 31 tabs, 1 existing Starlette/httpx warning.
> Update 2026-07-01 (Engagement follow-ups): closed the deferred items — engagement_retest (re-check linked findings' current status: fixed/open/accepted/missing, web GET /engagements/{id}/retest + GUI export), engagement_overview + report_export.engagements_csv (web /engagements/overview + /engagements.csv + GUI export), and engagement.mission_roe_from_engagement (mission inherits the engagement's scope/ROE). Plus an Engagement portfolio card on the Overview tab. Engagement epic fully closed. Current scale: **full pytest 2484 passed**, ruff clean, self-check 31 tabs, 1 existing Starlette/httpx warning.
> Update 2026-07-01 (mission-under-engagement): create_mission_under_engagement (core/engagement_missions.py) spins up a client-safe mission inheriting the engagement's scope/ROE, persists + links it back — a real consumer for the inheritance helper; web POST /engagements/{id}/missions + a GUI 'Create mission' row. Current scale: **full pytest 2489 passed**, ruff clean, self-check 31 tabs, 1 existing Starlette/httpx warning.
> Update 2026-07-01 (dedup finding-render): the identical finding-table renderers in mission_report + engagement_report were extracted into core/finding_render.py (finding_refs / finding_md_table / finding_html_table; presentation-only, escaped) — no rendered-output change. Current scale: **full pytest 2496 passed**, ruff clean, self-check 31 tabs, 1 existing Starlette/httpx warning (also extracted the shared HTML report-document envelope html_open/html_close across 5 renderers, byte-identical).
> Update 2026-07-01 (Retest Run lifecycle R1–R5): retest is now a first-class persisted "run" — a point-in-time snapshot of an engagement's linked-finding outcomes (fixed/open/accepted/missing), not just a derive-on-read view. R1 pure contract core/retest_run.py (+asa_retest_run schema); R2 RetestRunStore (single-table, events-less; in the project_io bundle as retest_runs.json); R3 retest_runner.run_retest freezes engagement_retest.build_retest into a snapshot (engagement not mutated — link on the run's engagement_id); R4 web (POST /engagements/{id}/retest/run, GET /engagements/{id}/retest-runs, GET /retest-runs/{id}[/report.md]) + GUI "Run retest" + history on the Engagements tab; R5 timeline retest_run events + report_export.retest_runs_csv (+ /retest-runs.csv + Timeline export) + demo_seed snapshot. No second findings store; the retest-row markdown table is shared via engagement_retest.retest_rows_markdown. Current scale: **full pytest 2549 passed**, ruff clean, self-check 31 tabs, 1 existing Starlette/httpx warning.
> Update 2026-07-03 (Authorized Enterprise Recon track E1–E10 + increment-2 depth): the 10-epic roadmap in `DOCS_DEVELOPMENT_PLAYBOOK.md` landed — passive OSINT (Shodan/Censys/InternetDB, zero target traffic), coverage gate, execution profiles, browser-backed accuracy, context-aware wordlist planner, origin-exposure intel, storage-backend seam, worker orchestration, sensitive-data governance, parser hardening. Increment-2 depth this pass: E3-2 scan-time execution-profile IP gate (fail-closed pre-flight), E4-2 browser-accuracy collection phase (delta → report + E2 coverage), E5-2 context-aware path-probe phase (executes the wordlist plan, scope-gated + throttled), E7-2 dialect ops + a real PostgresBackend (SQLite byte-identical). Follow-ups: E5-2 findings-fold — readable sensitive paths (/.git, /.env, /actuator/env, …) become first-class findings (path_prober.exposure_findings; recon surface + auth-gated hits are not promoted); E4-2 web parity — GET /browser-accuracy + a dashboard "Browser Accuracy" button expose the rendered-DOM delta to the LAN console (distinct from /accuracy = detection confidence). All opt-in/off-by-default where they add active traffic. Current scale: **full pytest 2866 passed**, ruff clean, self-check 29 tabs, 1 existing Starlette/httpx warning.
> Update 2026-07-03 (Windows CLI Process Hardening): a reliability pass over external-CLI launching on Windows — no cmd/conhost/PowerShell window ever flashes from the GUI, one cancellable process contract, an architectural guard, and a redacted run journal. All additive; scanner business logic and finding formats untouched; `build.spec` `console=False` preserved. AST guard `tests/test_no_direct_subprocess.py` forbids `subprocess.run/Popen/call/check_call/check_output`, `os.system`, `shell=True` outside the sole seam `utils/subprocess_utils.py`. New `run_capture` (Popen poll-loop: timeout + cancel + process-tree kill), `terminate_process_tree` (`taskkill /T` on Windows, `killpg` on POSIX) and `CancellationToken`; `external_tools.run_command` gains an additive `cancel_event` (default path byte-compatible). `system_logger.journal_tool_run` writes one redacted line per run to the same system.log the System tab shows (reusing `crash_reporter.redact`). The tool runners (nuclei/katana/amass/subfinder/httpx/bbot/lift/scrapy) get `set_cancel_event`; the Scrapy tab gets a Cancel button, and Full Collection + the subdomain scan now thread their cancel Event into the external runners so Stop kills a running child promptly. Current scale: **full pytest 2905 passed**, ruff clean, self-check 29 tabs, 1 existing Starlette/httpx warning; PyInstaller (QT_API=pyside6, console=False) + frozen self-check 29 tabs verified.
> Update 2026-07-04→07-05 (workflow polish + release-checklist start): DEV_PLAN WS1–WS6 closed (media downloading removed → 29 tabs; crash reporter; web-console auth + safe bind + rate-limiting; concurrent DAG scan engine; Slack alert channel; native passive subdomain sources + modern secret patterns; update-check + friendly errors). Then a run of management/workflow features on top of the acceptance/findings layer: Compare Projects (A-vs-B) + CSV/MD export, findings & asset keyword search, bulk risk acceptance, the full **Risk Acceptance arc** (accept-with-expiry → timeline → alert → active-risk exclusion → CSV → *Risk Acceptances* review tab → expired-only filter), Remediation pagination. Release-checklist started: `RELEASE_CHECKLIST.md` + `THIRD_PARTY_NOTICES.md`; qfluentwidgets (GPL-3.0) made optional for a **GPL-free default build** (`gui/_fluent.py` soft-degrade + `build.spec` opt-in `ASA_BUNDLE_FLUENT=1`); CHANGELOG `[Unreleased]` reconciled with the whole post-1.0.0 body of work. Current scale: **full pytest 2999 passed** (254 files), ruff clean, self-check 30 tabs, 1 existing Starlette/httpx warning.
> Это навигабельная «карта проекта»: здоровье, структура, найденные ошибки и с
> чего начинать работу. Подробный пофичный лог — в
> [`PROJECT_STATUS.txt`](PROJECT_STATUS.txt); авторитетный статус — CLAUDE.md §12.

---

## 1. Здоровье (health dashboard)

| Метрика | Значение |
|---|---|
| Тесты | **2999 собрано, зелёные** (254 файла; 0 FAILED/ERROR; offline/headless Qt; 1 Starlette/httpx deprecation-warning; на 2026-07-05 после acceptance-арки + release-checklist старта) |
| Линтер (ruff) | ✅ чисто |
| Компиляция всех модулей | ✅ 0 ошибок |
| `except:` без типа | 0 |
| Маркеры TODO/FIXME/XXX | 0 |
| Своих модулей / тест-файлов | 100+ модулей / 140+ test-файлов |
| CI | GitHub Actions: lint + test (3.11/3.12) + Windows .exe build **+ smoke-run собранного .exe (`--self-check`)** |
| Git | ветка `master`, синхронизирована с `origin/master` (push 2026-06-23, `21e88ac`); удалённые действия — только по явному разовому разрешению |
| Локальный checkpoint | 2026-06-28: `master` ahead 70 local commits; remote git actions were not performed |

Вывод: кодовая база в хорошем состоянии — статика чистая, тесты зелёные.
Весь реализуемый роадмап закрыт (P1–P12 + TIER S/A/B + C1/C2 в безопасных
оффлайн/localhost-вариантах); см. §6. Сверх того закрыт **эпик ASM 2.0**
(F1 Findings → F6 GUI-рестайл), пост-эпик (asn_intel, report_export,
Asset Inventory, CVE Intelligence, углубление detection) и **Advanced
Intelligence Framework (EPIC 8–13)**: единый confidence по всем сущностям
(MODULE 1 Scan Accuracy), Asset Criticality, Priority deepening, Attack Paths,
report/web-поверхности и мониторинг attack-path событий — всё derive-on-read,
display-метрики (риск-вердикт не тронут). Сверх того закрыт **EPIC NEXT**
(business-risk слой 2026-06-22): Business Context Model, business-aware
prioritization, deterministic attack paths, remediation tasks, semantic drift
monitoring, auditor-friendly compliance, Cloud/Container/IaC ingestion. GUI-
хвосты добавлены 2026-06-23: Remediation, IaC Config, бизнес-контекст в
Criticality-вкладке (**project default + per-asset override**). Пофичный статус
в CLAUDE.md §12.

---

## 2. Что это за проект

Десктопный инструмент (Python 3.11+/PySide6 через qtpy) для авторизованной разведки и
анализа веб-сайтов: пассивная разведка, субдомены, перехват API-трафика, обход
paywall, оффлайн-клон фронтенда, анализ дизайна, аудиты
безопасности (cookie, секреты, source-map, уязвимости).

**Точки входа:**
- `main.py` — GUI (PySide6/qfluent через qtpy), self-check: 29 вкладок.
- `main_orchestrator.py` — CLI-пайплайн из 6 фаз (флаги `--dynamic/--paywall/--vulns/--dump-api/--web/--profile/--delay`).
- `remote/web_app.py` — FastAPI LAN-консоль (:5000), 13 job'ов с паритетом GUI (+ отмена job'а, + управление мониторингом #8, + Alert Center #9).
- `monitor_cli.py` — Continuous Monitoring (#8): `enable/disable/status/run/watch` над расписанием проектов.
  (та же логика доступна в GUI — вкладка Collection — и в web-консоли.)

---

## 3. Архитектура и структура

### core/ — движки анализа
| Модуль | Назначение |
|---|---|
| recon_engine | GeoIP + CMS-фингерпринт + tech-fingerprint + dependency-audit + infra + фавиконы + PWA-манифест |
| tech_fingerprint | расширенный оффлайн tech-fingerprint (CDN/server/backend/analytics + версии) |
| infrastructure | ASN/инфра-интеллидженс: цепочка Domain → ASN → IP → Provider → **Cloud → Region** (cloud/region derive-on-read из уже собранных сигналов) |
| cloud_classifier | **нормализация хостинг-облака** (AWS/Cloudflare/Azure/GCP/Fastly/Akamai/…) из provider/ASN-строки + CDN-tech + takeover-CNAME; pure/offline/без deps, сильнейший сигнал (ASN>provider>tech>CNAME), unknown→{} (без догадок); НЕ в risk-score |
| dependency_audit | RetireJS-lite: детект JS-библиотек + версий и флаг известных уязвимых |
| graphql_discovery | probe /graphql* + introspection-проверка (Security Audit) |
| subdomain_scanner | пассив (crt.sh, HackerTarget, AlienVault, Anubis) + brute |
| subdomain_active | HTTP-liveness + детект takeover |
| dynamic_analyzer | перехват XHR/Fetch через Playwright |
| paywall_bypass | 6 стратегий обхода + reader view |
| content_capture | обход и сохранение HTML-страниц + site_map (статус/тип/глубина) |
| frontend_cloner | скачивание ассетов + переписывание ссылок → оффлайн-копия |
| design_analyzer | палитра/типографика + сравнение версий |
| secret_scanner | **единый** детектор секретов (источник правды); к каждой находке прикрепляет `validation` |
| secret_validator | **оффлайн** структурная валидация формата секретов (без сети): vendor-форматы, JWT/Basic-декод, отсев плейсхолдеров |
| source_map_parser | `.js.map` → исходники и утечки |
| security_auditor | оркестратор secret + source-map + GraphQL по странице и её JS; summary со счётом валидного формата |
| cookie_auditor | аудит флагов HttpOnly/Secure/SameSite |
| vuln_scanner / vuln_report | правила уязвимостей + экспорт HTML/JSON/PDF |
| api_key_extractor / api_dumper | поиск ключей / дамп API-ответов |
| project | Project workspace: Projects/<slug>/ (scans/reports/history/metadata.json); `load_scan_report` для diff |
| scan_diff | **оффлайн-diff двух сканов проекта** (страницы/субдомены/секреты/тех/зависимости/заголовки/TLS-сертификат/эндпоинты/findings + дельта риска + GraphQL/source-maps/cookies/DNS/exposure-кластеры/**attack paths**), HTML-отчёт. Единый классификатор `diff_events` → Alert Center (`alerts.ALERT_TYPES`) + Timeline; **EPIC 13**: `new_attack_path`/`attack_path_escalated` (high, alertable) |
| monitor | **Continuous Monitoring (P-роадмап #8)**: расписание (daily/weekly/monthly) в metadata.json; `run_due` гоняет Full Collection + авто-Scan Diff против прошлого скана; чистая логика (`compute_next_run`/`is_due`) и тонкий `MonitorScheduler`-тред отделены от инъектируемого раннера (тесты без сети); опц. триггерит alerts |
| alerts | **Alert Center (#9)**: из авто-diff'а извлекает события (new secret/subdomain/takeover/technology/cert change/risk↑) и шлёт в Telegram/Discord (urllib)/Email (smtplib); строго opt-in, stdlib-only, транспорт инъектируем (тесты без сети); секреты уже замаскированы в diff'е |
| cert_info | TLS-сертификат хоста (stdlib ssl): fetch + summarize (issuer/срок/SAN/SHA-256) для Scan Diff |
| openapi_discovery | **OpenAPI Discovery (#11)**: пробинг типовых путей спеки (swagger.json/openapi.json/…) + чистый парсер OpenAPI 3.x/Swagger 2.0 → карта эндпоинтов; фетч (инъектируемый) отделён от парсинга; питает отчёт, граф (категория APIs) и Scan Diff (секция apis) |
| historical_intel | **Historical Intelligence (#12)**: архивные URL домена из Wayback CDX + чистая классификация (admin/auth/api/config/upload/docs); фетч отделён от классификатора (инъектируемый); питает отчёт, граф (категория Historical) и Scan Diff (секция historical, интересное подмножество) |
| dns_intel | **DNS Intelligence (#13 OSINT)**: A/AAAA/MX/TXT/NS/CAA + email-auth (SPF/DMARC/DKIM) через DNS-over-HTTPS (без dnspython); чистый анализ → findings (нет SPF/DMARC, слабый DMARC, нет CAA), которые сворачиваются в риск-движок; питает отчёт и Scan Diff (секция dns) |
| email_intel | **Email Intelligence (#13 OSINT)**: сбор e-mail адресов из homepage/robots.txt/sitemap.xml (stdlib re); чистая экстракция/классификация (фильтр шума: ассеты, плейсхолдеры, version-строки) → группировка на домене/внешние + по ролям (security/admin/support/sales/…); фетч отделён от экстракции (инъектируемый) → тесты без сети; питает отчёт (карточка) и Scan Diff (секция emails) |
| employee_intel | **Employee Intelligence (#13 OSINT)**: имена сотрудников со страниц team/about/leadership из структурных источников (JSON-LD `Person` + личные `mailto`, role-фильтр через email_intel); по парам имя↔адрес выводит корпоративный формат e-mail ({first}.{last}, {f}{last}, …) и достраивает вероятные адреса (помечены `inferred`, без догадок без on-domain-доказательств); фетч отделён от чистого roster (инъектируемый) → тесты без сети; питает отчёт (карточка) и Scan Diff (секция employees) |
| ct_history | **Certificate Transparency History (#13 OSINT)**: история сертификатов домена из crt.sh (то, что subdomain-сканер выбрасывает — временна́я/issuer-метадата): центры сертификации (CA), окна валидности, первое/последнее появление в логах, недавние (≤90 дн.) и wildcard-сертификаты, активные/истёкшие; сетевой fetch отделён от чистого `analyze` (с инъектируемым `now`) → тесты без сети и детерминированы по времени; информационный (в риск-движок не идёт), питает отчёт (карточка) и Scan Diff (секция ct — новый сертификат по crt.sh id) |
| findings_store / findings_adapter / findings_sla | **Findings Management (ASM F1)**: SQLite `data/findings.db`, стабильный fingerprint + project-scoped id, lifecycle OPEN/IN_PROGRESS/FIXED/IGNORED/FALSE_POSITIVE, события `finding_events`, SLA derive-on-read, GUI/Web triage. Заменяет legacy `findings_status.py`/`findings.json`; inactive findings исключаются из risk. |
| asset_store / asset_adapter | **Asset Inventory**: персистентный реестр активов (domain/subdomain/ip/asn/netblock/endpoint/technology), аналог Findings, но для активов. `asset_adapter` — pure derive из report (identity sha1(type␟norm), endpoint через normalize_location, технология=имя без версии); `asset_store` — SQLite `data/assets.db`, scoped-id ключ, lifecycle ACTIVE⇄GONE→REAPPEARED со scope-guard по фазе-источнику, `projects()`/`project_events()`. Проводка: `_sync_assets`, вкладка «Assets» (read-only), web `GET /assets`, Timeline (asset-события), `assets_csv`. Оффлайн, stdlib+sqlite |
| collection_runner | «Full Collection» — все фазы в один скан проекта Projects/<slug>/scans/<id>/; HTML/JSON/Markdown отчёты, warning lifecycle (`warnings`, `warning_count`, `warning_summary`) в report/metadata/portfolio/history, запись запуска в `operations.db`; опц. фазы: screenshot/nuclei/katana/**subdomains**/LLM |
| site_map | дерево путей сайта по HTTP-статусам + тип/глубина (визуальная карта) |
| executive_summary | **единый риск-движок 0–100** + вердикт/рекомендации над фазами; опц. LLM-нарратив (поле `narrative`) поверх детерминированного вердикта |
| intelligence | **Core + Advanced Intelligence (EPIC 7–11)**: confidence + priority + explanation per finding и обобщение на ВСЕ сущности (derive-on-read, без новых моделей/таблиц). `confidence`/`confidence_for` (корроборация+валидация+специфичность детекта для finding/technology/cve/asset/infrastructure/api/secret — **MODULE 1 Scan Accuracy**), `priority` (severity дисконтирован confidence + exposure/SLA + **asset-criticality бонус, EPIC 10**), `explain` (finding_knowledge). **EPIC 9** `asset_criticality`/`build_asset_criticality` (тип-вес + blast radius + находки + exposure → ранжирование активов). **EPIC 11** `build_attack_paths` (латеральные маршруты entry→pivot→targets по shared-infra). **Asset Exposure (likelihood-ось)** `exposure_score`/`build_exposure`/`load_exposure` (reachability + open findings + blast radius, **без тип-веса** — дополняет Criticality impact). `build_accuracy`/`accuracy_from_report` — единый rollup достоверности скана. Всё **display-метрики** (риск-вердикт не тронут). Переиспользует findings_store/correlation/asset_graph/findings_sla. Поверхности: report['intelligence'/'accuracy'/'asset_criticality'/'attack_paths'/'exposure'], web `/intelligence`+`/criticality`+`/attack-paths`+`/accuracy`+`/exposure`, GUI-вкладки «Priorities»/«Asset Criticality»/«Attack Paths»/«Scan Accuracy»/«Asset Exposure» |
| business_context | **Business Context Model (EPIC NEXT F1)**: user-declared важность актива (criticality + data sensitivity) — единый источник словаря/весов/резолва. Хранение = аддитивный ключ `business_context` в `metadata.json` (default + per-asset overrides по bare fingerprint; БЕЗ новой таблицы), `Project.get/set_business_context`. Augment-слой над `intelligence.asset_criticality` (риск-вердикт не тронут). Поверхности: report-карточка, web, `business_cli.py`, GUI-редактор в Criticality-вкладке (project default **+ per-asset override**, 2026-06-23) |
| remediation / iac_scanner / compliance | **EPIC NEXT** прочее: remediation work-items (event-sourced поверх `finding_events`, GUI-вкладка + CLI), Cloud/Container/IaC misconfig-скан (Dockerfile/Terraform/CFN, категория `iac`, GUI ad-hoc scan + CLI), OWASP Top 10 + CWE + framework-crosswalk (PCI/ISO/NIST/SOC2) compliance-отчёт (Markdown + SARIF-теги) |
| llm_summary | опц. LLM-резюме через **локальный Ollama** (stdlib urllib, graceful, ничего не уходит с машины) |
| report_charts | оффлайн inline-CSS бары для HTML-отчётов (без JS/зависимостей) |
| screenshot | опц. headless-скриншоты (Playwright, lazy, gated); **мульти-страничные** (home/login/admin/dashboard) через select_targets/capture_many |
| attack_surface | граф атак-поверхности (домен → категории); **интерактивный оффлайн** (CSS `:target`/`:hover`, без JS) + статический SVG + surface_score 0–100 |
| external_tools | опц. внешние бинари (nuclei/katana/amass): subprocess + нормализация |
| analyzer_plugins | SDK пользовательских аналитических плагинов (plugins/analyzers/) |
| anti_detect_engine / cloudflare_bypass | сессии с ротацией UA, retry, обход CF |
| scrapy_crawler / _scrapy_spider | deep-crawl в отдельном процессе |
| registry / config / paths / features | DataRegistry, единый конфиг, PathManager, детект опц. фич |

### utils/ — инфраструктура
`http_retry` (retry+backoff+gzip/deflate), `browser_utils` (SessionBuilder),
`sqlite_store`/`operation_registry`/`data_viewer`/`exporter`, `endpoint_index`,
`pattern_analyser`, `scan_cache` (TTL), `rate_limiter`, `system_logger`,
`file_compression`, `site_extractor`,
`task_manager`, `cloudflare_tools`.

### gui/ — PySide6/qfluent через qtpy (mixin-архитектура)
`main_window` — тонкий контейнер (~75 строк); каркас — mixin'ы `task_runner`
(единый раннер QThread), `window_chrome`, `window_helpers`; `workers`,
`plugin_manager` (реестр вкладок + авто-дискавери внешних), `ui_components`,
`dialogs`; модули `tab_*.py` (по вкладке), включая ASM-вкладки Findings/Assets/
**Priorities** (read-only Core Intelligence, EPIC 7 — `tab_intelligence`)/
**Asset Criticality** (EPIC 9 — `tab_criticality`)/**Attack Paths** (EPIC 11 —
`tab_attack_paths`)/**Scan Accuracy** (MODULE 1 — `tab_accuracy`)/Timeline/Overview.
Вкладки регистрируются из `BUILTIN_TABS` (секции nav-рельса), не хардкодятся;
кластер Intelligence (Priorities → Asset Criticality → Attack Paths → Scan Accuracy)
— в секции «Управление» после Findings. **Asset Criticality** несёт редактор
бизнес-контекста (project default **+ per-asset override** выбранного актива,
off-thread запись в `metadata.json` через `business_context`); EPIC NEXT GUI-
хвосты — вкладки **Remediation** и **IaC Config** (2026-06-23).

---

## 4. Что нового (платформа P1–P12)

Сессия закрыла весь реализуемый роадмап «Tools → Platform» + Next-Gen TIER B/C.
Каждая фича: оффлайн-тесты + живой прогон на реальном сайте + лог в
`PROJECT_STATUS.txt`. Без новых зависимостей на всём протяжении.

| # | Фича | Суть |
|---|---|---|
| P2 | Project Workspace | проект владеет таймстамп-сканами (`Projects/<slug>/`) |
| P3 | Unified Risk Engine | единый риск 0–100 + 5 уровней (executive_summary) |
| P4 | Dashboard 2.0 | агрегация из DataRegistry (+ takeovers/source maps) |
| P8 | **Scan Diff** | оффлайн-diff двух сканов проекта → HTML (`reports/diff_*.html`) |
| P9 | **Multi-page Screenshots** | home/login/admin/dashboard (Aquatone-style), галерея в отчёте |
| P10 | **Interactive Attack Graph** | клик/подсветка через чистый CSS (`:target`/`:hover`), без JS |
| P11 | **LLM Exec Summary** | опц. нарратив через локальный Ollama (graceful, ничего не уходит с машины) |
| P12 | **Secret Format Validation** | оффлайн-проверка формата ключей (без сети): отсев плейсхолдеров, vendor/JWT/Basic |

**Багов в этом feature-pass не внесено:** 504 теста зелёные, ruff чист,
оффлайн-контракт отчётов (нет `<script>`/CDN) проверяется тестами.

**Историческая справка (ранние ревью, см. PROJECT_STATUS §6):** закрыты
literal-tilde bug в `SettingsDialog` и 7 логических багов (recon/pwa_manifest,
циклический CSS `@import`, deflate-декод, provenance внешних JS, дубль
secret-regex в Capture, экранирование ResultsDisplay) + 4 «мёртвые» настройки.

**Статические проверки:** чисто (компиляция, ruff, нет bare-except, нет TODO).

---

## 5. Риски и технический долг

| Тема | Статус / заметка |
|---|---|
| Папка `~/` (литеральная) | [УДАЛЕНО] Маленький легаси-артефакт tilde-бага (gitignored). Прим.: ранняя оценка «~51 ГБ» была ошибкой измерения — `Get-ChildItem '~'` раскрылся в `$HOME`; реальная папка была небольшой. Дом. каталог не затронут. |
| Внешние сервисы (ip-api, crt.sh, …) | Обёрнуто в retry+backoff, мягкая деградация. Остаётся сетевая хрупкость. |
| Опц. тяжёлые зависимости | Playwright/fastapi/scrapy — guarded; ставятся вручную, не бандлятся в .exe. |
| Web-консоль в LAN | Отдаёт найденные секреты по сети (by design для LAN-инструмента) — не выставлять наружу. |
| UA-профиль в dynamic/paywall | Paywall теперь honor-ит профиль; Playwright-перехват использует свой UA браузера (ожидаемо). |
| Security Audit вкладка | Нет кнопки Stop/прогресса (ограничена `max_scripts`, не критично). |
| LLM-нарратив (P11) | Строго opt-in, **только localhost-Ollama**; вердикт риска остаётся детерминированным (LLM лишь нарративит), текст запекается в отчёт → оффлайн сохраняется. Облачный LLM осознанно вне скоупа. |
| Secret-валидация (P12) | Только **оффлайн** структурная проверка формата — секреты не покидают машину. ЖИВАЯ сетевая валидация (отправка ключа провайдеру) сознательно НЕ реализована (dual-use/приватность). |

---

## 6. С чего начать (backlog / опции)

**Внутренний трек Platform P1–P12 + TIER S/A/B/C закрыт.** Но против ИСХОДНОГО
роадмапа (`2.txt`, приоритеты в строках 515–533) ещё есть непостроенные фазы —
ранее отчёт ошибочно называл их «исчерпанными». Реальный остаток по приоритету:
- **#8 Continuous Monitoring — [ГОТОВО]** `core/monitor.py` + CLI
  `monitor_cli.py` + GUI (вкладка Collection) + web-консоль: расписание
  daily/weekly/monthly, авто-Scan Diff, оффлайн, без новых зависимостей.
  Единая логика (`monitor.enable/disable/status/run_due`) под тремя тонкими
  поверхностями. Осталось опц.: фоновый scheduler внутри GUI/web-процесса
  (сейчас периодический прогон — через `monitor_cli.py watch`).
- **#9 Alert Center — [ГОТОВО]** `core/alerts.py`: события из авто-diff'а →
  Telegram/Discord/Email (stdlib), строго opt-in, конфиг в settings.json.
  Завязано в мониторинг (`run_due(alert_config=…)`); поверхности: CLI
  (`test-alert` + `run/watch`), GUI (Настройки → вкладка «Уведомления»: каналы +
  типы + тест), web-консоль (карточка Alert Center: статус без токенов + тест).
- **#11 OpenAPI Discovery — [ГОТОВО]** `core/openapi_discovery.py`: пробинг
  типовых путей спеки + парсер OpenAPI 3.x/Swagger 2.0 → карта эндпоинтов.
  Опц. фаза collection (чекбокс «OpenAPI / Swagger»), карточка в отчёте,
  категория APIs в графе, секция apis в Scan Diff. Stdlib, без новых
  зависимостей (YAML-спеки вне скоупа — нужен сторонний парсер).
- **#12 Historical Intelligence — [ГОТОВО]** `core/historical_intel.py`:
  архивные URL из Wayback CDX + классификация (admin/auth/api/config/…). Опц.
  фаза collection (чекбокс «Историч. URL (Wayback)»), карточка в отчёте,
  категория Historical в графе, секция historical в Scan Diff. Stdlib;
  Common Crawl / OTX вне скоупа (тяжелее / ключи), источник расширяем.
- **#13 OSINT-модули — [ГОТОВО]** DNS Intelligence **[ГОТОВО]**
  (`core/dns_intel.py`: A/AAAA/MX/TXT/NS/CAA + SPF/DMARC/DKIM через DoH, findings
  в риск-движок; опц. фаза collection «DNS / Email-auth», карточка, Scan Diff
  секция dns) · Email Intelligence **[ГОТОВО]** (`core/email_intel.py`: сбор
  адресов из homepage/robots/sitemap, группировка на домене/внешние + по ролям;
  фетч отделён от чистой экстракции; опц. фаза collection «Email-разведка»,
  карточка, Scan Diff секция emails) · Employee Intelligence **[ГОТОВО]**
  (`core/employee_intel.py`: имена со страниц team/about из JSON-LD Person +
  личных mailto, вывод корпоративного формата e-mail и достройка вероятных
  адресов; опц. фаза collection «Сотрудники», карточка, Scan Diff секция
  employees) · CT-история **[ГОТОВО]** (`core/ct_history.py`: история
  сертификатов из crt.sh — CA/сроки/первое-последнее появление/недавние+
  wildcard; опц. фаза collection «CT-история», карточка, Scan Diff секция ct).
  **Бандл #13 (DNS + Email + Employee + CT) закрыт.**
- **#14 / ASM F1 Findings Management — [ГОТОВО]** (`core/findings_store.py`,
  `core/findings_adapter.py`, `core/findings_sla.py`): SQLite lifecycle-стор,
  cross-scan dedup, auto-FIX со scope guard, sticky IGNORED/FALSE_POSITIVE,
  GUI-вкладка Findings и web endpoints. Legacy `findings_status.py` /
  `findings.json` удалены и заменены этим стором.

Осознанно вне скоупа (нарушают инварианты по своей природе):
- **C2 «живая» сетевая secret-валидация** (отправка ключа провайдеру) — dual-use/приватность.
- **REJECTED:** тяжёлый JS-AST-парсер, интерактивный граф через CDN-JS, любой облачный AI.

**Точечные улучшения — сделано в этой сессии:**
- [СДЕЛАНО] Security Audit: кнопка Stop + live-прогресс в статус-строке (`3e7dcba`).
- [СДЕЛАНО] Модель локального Ollama настраивается из GUI (Настройки → Сеть, `2eb9075`).
- [СДЕЛАНО] Web-консоль: job **Scan Diff** (паритет с GUI P8, `f4d0905`).
- [СДЕЛАНО] Dashboard «Очистить»: вопрос решён (`9f9c803`) — «Очистить вид»
  (безопасно) + отдельная «Очистить БД…» с диалогом подтверждения и реальным
  удалением из registry.db (`DataRegistry.clear()`).
- [ПОКРЫТО РАНЕЕ] Happy-path сетевых модулей: recon (`test_recon_engine`) и
  subdomain (`test_subdomain_cache`) уже тестируются на моках.
- [СДЕЛАНО] Scan Diff: секция **субдоменов** разблокирована — в collection
  добавлена опц. subdomain-фаза (passive + takeover), которая питает Scan Diff,
  риск-движок (takeover-сигнал) и граф (категория Subdomains).
- [СДЕЛАНО] Scan Diff: секция **сертификатов** разблокирована — опц. TLS-cert-
  фаза (`core/cert_info.py`, stdlib ssl) пишет issuer/срок/SAN/отпечаток;
  Scan Diff показывает смену сертификата (renewal/issuer/SAN) между сканами.

- [СДЕЛАНО] Харднинг: CI smoke-запускает собранный .exe (`main.py --self-check`
  строит окно headless и выходит 0) — ловит PyInstaller-регрессии (потерянный
  hidden-import / data-файл), которые юнит-тесты на исходниках не видят.

- [СДЕЛАНО] Web-консоль: **отмена выполняющегося job'а** — эндпоинт `POST /cancel`
  кооперативно сигналит активному движку (CollectionRunner/SubdomainScanner через
  `cancel()`, SecurityAuditor через cancel-Event, адаптируемый `_EventCanceller`);
  раннер регистрирует cancellable и сбрасывает его в `finally`. В UI — кнопка
  Cancel, активная только во время выполнения (состояние ведётся по реальному
  жизненному циклу job'а через SSE, без таймаут-хака).

**Осталось (маргинально):**
- Web-консоль: job экспорта Vuln-отчёта (избыточен — collection уже даёт полный отчёт).
- Security Audit: вынести `max_scripts`/таймауты в настройки; конфиг таймаутов dynamic-анализа (низкий спрос).

---

## EPIC EXT-OSINT — baseline РЕАЛИЗОВАН (2026-06-21)

> Раздел обновлён: модули ниже **существуют и доведены до рабочего baseline**
> (F1–F4 в `ROADMAP_ASM_2.0.md` помечены `[ВЫПОЛНЕНО 2026-06-21]`). Это НЕ
> «запланировано/не написано». Остаток — точечные расширения baseline; новый
> business-risk слой вынесен в **EPIC NEXT** (`ROADMAP_ASM_2.0.md`, статус
> ПЛАНИРОВАНИЕ).

- `core/bbot_adapter.py` **[РЕАЛИЗОВАН]** — внешний опциональный BBOT-адаптер через
  subprocess + JSON/NDJSON (BBOT под AGPL-3.0 — код НЕ копируется, не
  обязательная зависимость, не бандлится в `.exe`). Вывод нормализуется в
  AssetStore/FindingsStore. Детект — `features.has_bbot()` **[РЕАЛИЗОВАН]**.
- `core/document_intelligence.py` **[РЕАЛИЗОВАН]** — ядро document intelligence
  (offline-first контракт «документ → структурированные поля → DTO»).
- `core/document_providers/lift_adapter.py` **[РЕАЛИЗОВАН]** — опциональный провайдер
  (datalab-to/lift) через subprocess; тяжёлые `torch`/`vLLM`/HF-модели не
  импортируются/не бандлятся, мягкая деградация при отсутствии.
- `core/osint_catalog.py` **[РЕАЛИЗОВАН]** — offline derive-on-read каталог AI-OSINT
  воркфлоу (идеи из Awesome-AI-OSINT) поверх существующих движков.

Расширение baseline (или NEXT-слой) — строго по цепочке Epic → Feature → Task,
по одной задаче, после утверждения плана конкретной фичи. README обновляется
только по факту.

---

*Сгенерировано в ходе ревью. Детали и история изменений — `PROJECT_STATUS.txt`.*
> Update 2026-06-20: Epic 14 - Scope & Evidence Foundation is CLOSED.
> Completed: Scope Guard v1, Evidence Manifest v1, Evidence Integrity Hook,
> Finding Evidence Persistence v1, Scope CLI / Project Scope Management,
> Evidence Refs Coverage Expansion, Report / Export Traceability, Scope Guard
> Coverage Audit, Evidence Integrity Integration With Monitor/Export, and
> roadmap/status cleanup. Final verification: ruff clean; full pytest 1460
> passed with 1 existing Starlette/httpx warning.
> Update 2026-06-23: EPIC NEXT (business-risk слой, F0–F7) CLOSED 2026-06-22;
> GUI-хвосты добавлены 2026-06-23 — Remediation, IaC Config, и per-asset business
> context override в Criticality-вкладке (хранение прежнее: metadata.json →
> business_context → assets; risk-вердикт не тронут). Final verification: ruff
> clean; full pytest **1794 passed** с 1 существующим Starlette/httpx warning.
> Update 2026-06-28: Client-Safe Pentest Workbench closed locally: audit
> workflow/schema/validation/quality gates, safe ROE-gated checks, Audit Runs GUI,
> persistent audit_runs/audit_events, deterministic JSON/MD/HTML reports,
> timeline audit-run events, independent evidence verification, granular finding
> audit events, and project bundle portability for audit-run history. Backend
> release-hardening merge `fb862990` also verified. Final local checkpoint:
> `ruff check .` clean; full pytest **2020 passed** with 1 existing
> Starlette/httpx warning; `python main.py --self-check` = 29 tabs; PyInstaller
> build with `QT_API=pyside6` and frozen `dist/SiteAnalyzer.exe --self-check`
> passed. Remote git actions were not performed.
