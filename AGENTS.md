# AGENTS.md — Advanced Site Analyzer

> Этот файл Codex читает автоматически в начале каждой сессии.
> Он задаёт контекст, архитектуру и **жёсткие правила**. Не нарушать.

---

<!-- MEMANTO-MANAGED-SECTION -->
## MEMANTO - Your Active Memory Companion

**MEMANTO is not a passive store. It is an active companion agent that works alongside you.**
Don't treat MEMANTO like a static blob you query once and forget. It's a teammate you keep
talking to, every preference, decision, and correction flows through it. MEMANTO remembers,
recalls, and answers so you hold context across sessions, honor prior decisions, and avoid
repeating mistakes the user already corrected.

Every memory operation in this session goes through MEMANTO. There is no exception.

> **CRITICAL**: All `memanto` commands are **shell commands**. Always run them using the terminal.
> Never simulate, describe, or "pretend to call" them. If you cannot run the shell, say so explicitly instead of inventing memory state.

### NON-NEGOTIABLE RULES

These are not suggestions. Follow each one on every turn.

1. **Read `MEMORY.md` before doing anything.** It is auto-synced at session start and holds
   the user's preferences, facts, goals, instructions, decisions, and commitments from every
   prior session. You MUST honor what is written there. If you act against it, you are
   breaking continuity the user is paying for.
2. **Search memory before saying you don't know.** If the user asks about past context, an
   earlier decision, a preference, or anything you are unsure about, you MUST run `recall`
   or `answer` first. Saying "I don't have context" without searching is a failure.
3. **Store proactively. Do not wait to be asked.** The moment a memory-worthy event happens
   — a preference stated, a decision made, a fact learned, an instruction given, a goal set,
   a mistake corrected — run `memanto remember` immediately, in the same turn.
4. **Always pass full metadata to `remember`.** Every `memanto remember` call MUST include
   `--type`, `--confidence`, `--provenance`, and `--source <your_agent_name>`. Never let
   these default. Untyped, unsourced memories pollute the agent's recall quality.
5. **One memory operation goes through MEMANTO. All of them do.** Do not keep mental notes,
   in-context scratch pads, or "I'll remember this for next time" promises. If it matters
   beyond this turn, it goes into MEMANTO. If it doesn't, drop it.

### Memory Operations — Use the Right One

MEMANTO gives you three primitives. They are equal-priority. Pick by intent, not by habit.

| You want to... | Use | Why |
|---|---|---|
| Read raw memory chunks and apply them as context | `memanto recall "query"` | Best for context-building, multi-step work, comparing options |
| Get one synthesized, grounded answer to a direct question | `memanto answer "question"` | Best for "what did we decide / prefer / commit to?" — saves you reading and merging |
| Persist something memory-worthy | `memanto remember "content" --type ... --confidence ... --provenance ... --source ...` | Every preference, decision, fact, instruction, goal, lesson |
| See what changed since last time | `memanto recall --changed-since "last 7 days"` | Catching up after a break |
| See the most recent memories | `memanto recall --recent` | Fast context refresh |

Do NOT always default to `recall`. If the user asked a direct question, `answer` is usually
the right tool — it returns a grounded synthesis so you don't burn tokens re-reading raw
chunks.

### When to Call `remember` (Examples — Run Immediately)

- User says *"I prefer tabs over spaces"*:
  `memanto remember "User prefers tabs over spaces for indentation" --type preference --confidence 1.0 --provenance explicit_statement --source <your_agent_name>`
- You decide to use Library X for reason Y:
  `memanto remember "Chose Library X for reason Y; commit abc123" --type decision --confidence 0.95 --provenance inferred --source <your_agent_name>`
- User corrects an approach:
  `memanto remember "User corrected: use pytest, not unittest" --type learning --confidence 1.0 --provenance corrected --source <your_agent_name>`
- A failed approach taught you something:
  `memanto remember "Batch size > 100 fails with TimeoutError" --type error --confidence 0.95 --provenance observed --source <your_agent_name>`

### Command Reference

```bash
# Store — ALWAYS pass full metadata
memanto remember "content" --type <type> --confidence <0.0-1.0> --provenance <provenance> --source <agent_name>

# Recall raw context
memanto recall "query"                              # semantic search
memanto recall "query" --type <type> --limit 10     # filtered search
memanto recall --recent --limit 10                  # newest first, no query
memanto recall --as-of "2026-01-15"                 # state at a point in time
memanto recall --changed-since "last 7 days"        # what changed since

# Synthesized answer (grounded RAG over memories)
memanto answer "question"

# Re-sync MEMORY.md (project-local cache)
memanto memory sync --project-dir .
```

**Memory types** (use the closest fit, do not invent new ones):
`fact`, `preference`, `instruction`, `decision`, `event`, `goal`, `commitment`,
`observation`, `learning`, `relationship`, `context`, `artifact`, `error`.

**Provenance values**: `explicit_statement`, `inferred`, `observed`, `corrected`,
`validated`, `imported`.

**Confidence**: `1.0` for explicit user statements; `0.9-0.95` for strong consensus;
`0.8-0.85` for observed patterns (3+ times); `0.6-0.75` for emerging patterns.

> **Note**: The `memanto-memory` skill in `.agents/skills/memanto/` contains detailed reference guidelines (best practices, confidence levels, tagging).
<!-- /MEMANTO-MANAGED-SECTION -->

## 1. Что это за проект

**Advanced Site Analyzer** — десктопный инструмент (Python 3.11+ / PySide6 через qtpy) для
авторизованного анализа веб-сайтов: recon, перечисление субдоменов, перехват
динамического трафика и API, аудит безопасности (секреты, source maps,
cookie, GraphQL), захват и оффлайн-клонирование фронтенда, извлечение медиа.

Назначение — **только авторизованное тестирование безопасности, исследования
и обучение**. Любая новая функциональность не меняет это назначение.

**Текущая зрелость:** мощный Security Analyzer (~80–90% как анализатор).
**Цель текущего этапа:** превратить его в платформу уровня
**ASM (Attack Surface Management)** + **CSM (Continuous Security Monitoring)**.
Подробный план — в `ROADMAP_ASM_2.0.md` (в корне проекта).

Главный сдвиг приоритетов на этом этапе: **с «поиска данных» на «управление
данными»** (lifecycle находок, история, мониторинг, оповещения), а не новые
сканеры.

---

## 2. Технологии

- Python 3.11+
- PySide6/qtpy + PySide6-Fluent-Widgets (GUI), многопоточность через QThread/QObject Signals-Slots
- SQLite (реестры операций, индекс эндпоинтов, метаданные проектов)
- Playwright (опц. — динамический анализ)
- FastAPI + uvicorn (опц. — LAN web-консоль)
- yt-dlp / ffmpeg (опц. — медиа)
- PyInstaller (поставка `.exe`)
- pytest (тесты, headless Qt `offscreen`, offline)

Тяжёлые зависимости опциональны и не бандлятся в `.exe` — это правило сохраняем.

---

## 3. Карта репозитория (где что лежит)

```
main.py                 # точка входа GUI
demo_seed.py            # сеет self-contained demo workspace (company+домены, lifecycle/assets/remediation) под один каталог; запуск приложения на нём через ASA_DATA_ROOT
main_orchestrator.py    # CLI-пайплайн из 6 фаз (Recon→[Paywall]→Capture→[Dynamic]→[Vulns]→[API])
monitor_cli.py          # OS-level адаптер мониторинга (run = прогон готовых для cron; watch = блок-цикл)
launcher.py             # EPIC 6: тонкий entry Launcher (CLI --health/--repair/--update/--launch/--install + Qt-окно Module 5)

core/                   # ВСЯ бизнес-логика и движки (UI сюда не лезет)
  config.py             # ЕДИНЫЙ источник путей/дефолтов, load/save settings.json, targets.json
  paths.py              # PathManager: frozen-aware пути (resource_root / data_root)
  project.py            # Project / ProjectStore — единственный источник правды по сканам проекта
  collection_runner.py  # Full Collection: прогон всех фаз в один скан
  scan_diff.py          # сравнение двух report.json + diff_events (offline, stdlib)
  recon_engine.py  subdomain_scanner.py  subdomain_active.py
  dynamic_analyzer.py  paywall_bypass.py  content_capture.py  frontend_cloner.py
  design_analyzer.py  api_key_extractor.py  vuln_scanner.py  vuln_report.py  api_dumper.py
  secret_scanner.py     # ЕДИНЫЙ набор secret-правил (RULES) — единственный источник правды
  source_map_parser.py  security_auditor.py  cookie_auditor.py
  anti_detect_engine.py  cloudflare_bypass.py  scrapy_crawler.py  _scrapy_spider.py
  # — ASM 2.0 платформа (F1–F5) —
  finding_fingerprint.py  findings_store.py  findings_adapter.py  # F1: SQLite-стор находок + lifecycle (adapter — кросс-сканерный dedup по CVE)
  findings_sla.py       # SLA по severity (derive-on-read, DefectDojo-дефолты; breach/age)
  asset_adapter.py  asset_store.py        # Asset Inventory: derive + SQLite-стор активов (data/assets.db) + lifecycle
  timeline.py           # F2: derive-on-read серии+события (находки+активы; без второй таблицы)
  monitor.py  alerts.py                                          # F3 мониторинг (движок) + F4 Alert Center
  executive_summary.py  attack_surface.py                        # risk-вердикт + граф/score атак-поверхности
  report_charts.py  dashboard_charts.py  portfolio.py            # offline-SVG (bars/sparkline/heatmap) + F5 портфолио
  trends.py             # EPIC 4: аналитика тренда поверх timeline.build_series (направление/baseline/дельта/пик)
  correlation.py        # F-K: Finding→Asset→Infra (exposure-by-asset, blast radius)
  asset_graph.py        # EPIC 5: Asset Correlation Engine — asset↔asset граф + кластеры общей инфры (Exposure Intelligence)
  intelligence.py       # EPIC 7: Core Intelligence — confidence + priority + explanation per finding (derive-on-read, ранжирование «что чинить первым»)
  features.py           # централизованный детект опц. зависимостей (pip-модули vs PATH-бинарники); summary()/missing()
  launcher.py           # EPIC 6: engine Install/Repair/Update/Launch + health_check (REQUIRED + features.summary); offline-first, subprocess инъектируется
  report_export.py      # CSV-экспорт findings/portfolio (PDF — печатью report.html)
  project_io.py         # экспорт/импорт проекта одним .zip (дерево Projects/<slug> + faithful срез findings/assets); zip-slip/SQL-safe; generic срез в SQLiteStore.export_project/import_project
  # — detection-движки (вливаются в risk/attack-surface/report) —
  infrastructure.py     # Domain→ASN→IP→Provider (offline, из recon-geo)
  asn_intel.py          # АКТИВНО (opt-in): RDAP CIDR + RIPEstat префиксы + reverse-IP (keyless)
  tech_fingerprint.py  dependency_audit.py  graphql_discovery.py # tech/JS-фреймворки + уязв. JS-либы (хардкод-fallback) + GraphQL
  osv_correlation.py    # АКТИВНО (opt-in): live CVE-корреляция JS-либ через OSV.dev (вытесняет хардкод)
  cve_intel.py  nvd_provider.py  cve_store.py   # EPIC 3 CVE Intelligence: OSV+NVD оркестратор + NVD-обогащение + персист-кеш (data/cve_cache.db, оффлайн)
  screenshot.py  external_tools.py  llm_summary.py               # Playwright скрины; nuclei/katana; опц. Ollama-резюме

utils/                  # инфраструктура
  sqlite_store.py  operation_registry.py        # учёт операций (SQLite)
  endpoint_index.py  pattern_analyser.py        # нормализация/дедуп эндпоинтов
  exporter.py  data_viewer.py  site_extractor.py  task_manager.py  system_logger.py
  image_processor.py  video_processor.py  file_compression.py
  subprocess_utils.py   # run_hidden/popen_hidden/hidden_kwargs — единый запуск дочерних процессов без всплывающих cmd-окон (Windows CREATE_NO_WINDOW)

gui/                    # ТОНКИЙ UI-слой (mixin-паттерн)
  main_window.py        # чистый контейнер: собирает окно из mixin'ов
  task_runner.py        # TaskRunnerMixin: _start_task / _run_async — ЕДИНЫЙ раннер фоновых задач
  window_chrome.py      # меню, таб-бар из PluginManager, статус-бар
  window_helpers.py     # общие helpers (пути, архивация, busy-state, browse)
  first_run.py          # first-run onboarding + system-health screen (тонкий фронт над launcher.health_check; пункт «Состояние системы» в nav)
  monitor_runner.py     # MonitorRunnerMixin: in-app планировщик мониторинга (F3)
  theme.py              # F6: единый источник темы (Fusion+QPalette, opt-in dark; risk/severity-цвета)
  plugin_manager.py     # реестр вкладок-плагинов + авто-дискавери из plugins/
  tab_*.py              # по mixin-классу на вкладку (вкл. tab_findings/tab_assets/tab_timeline/tab_overview)
  ui_components.py      # StyledButton/SectionGroupBox/ResultsDisplay (цвета из gui.theme) + FlowLayout (перенос длинных рядов)
  workers.py  constants.py   # constants реэкспортит из core.config

remote/web_app.py       # FastAPI LAN-консоль (паритет с GUI через реестр JOBS)
plugins/                # внешние вкладки-плагины (контракт в plugins/README.md)
plugins/analyzers/      # analyzer-плагины: run(results)->findings (вливаются в risk score)
tests/                  # pytest-набор (~1563 теста, offline/headless)
build.spec              # PyInstaller
```

**Workspace проектов** (создаётся при Full Collection):
```
Projects/<домен>/
  scans/<timestamp>/    # отдельный скан (recon/ api/ capture/ … report.json report.html)
  reports/  screenshots/  exports/  history/
  metadata.json         # индекс всех сканов + последний risk level/score, attack-surface, #секретов/находок
```

---

## 4. Архитектурные инварианты (нарушать = регресс)

1. **UI тонкий.** Вся логика — в `core/`/`utils/`. Вкладки `gui/tab_*.py` —
   mixin'ы, которые только зовут раннер и рисуют результат.
2. **Один раннер задач.** Любая фоновая работа идёт через
   `self._start_task()` / `self._run_async()` (TaskRunnerMixin). Не создавать
   QThread'ы вручную во вкладках. Воркеры — тонкие форвардеры колбэк→Qt-сигнал.
3. **Единые источники правды:**
   - пути/настройки → `core/config.py` + `core/paths.py` (PathManager);
     никаких относительных хардкодов `data/*.db`;
   - secret-правила → `core/secret_scanner.py` (RULES);
   - сканы проекта → `core/project.py` (Project / ProjectStore);
   - эндпоинты → `utils/endpoint_index.py`.
4. **Плагины — без правки ядра.** Новая вкладка = `*.py` в `plugins/`.
   Новый аналитик = `*.py` в `plugins/analyzers/`. Список вкладок собирается
   из `PluginManager`, не хардкодится.
5. **frozen-aware.** Любые новые пути — через PathManager (работает и в `.exe`).
6. **Опциональные зависимости — мягкая деградация.** Нет Playwright/yt-dlp/
   fastapi → фича отключается с подсказкой, приложение не падает.
7. **Backward compatibility.** Раскладка `Projects/<домен>/`, `metadata.json`,
   `report.json` и контракты `_start_task/_run_async/_set_busy/_browse` не ломать.

---

## 5. Жёсткие правила (НЕ нарушать никогда)

### 5.1 Работа только локально

**Разрешено** (норма с 2026-06-15): локальные коммиты — Codex сам коммитит
завершённую, проверенную (`pytest`/`ruff`) единицу работы с осмысленным
сообщением. Артефакты сборки (`dist/`, `dist_pyside6/`, `build/`, `temp/`) в
коммит не попадают (см. `.gitignore`).

**Запрещено** выполнять любые действия с **удалёнными** репозиториями и
публикацией: `git push`, `git fetch`, `git pull`, `git clone`, создание PR,
изменение `remote`/`origin`, релизы, любые действия с GitHub. Push/удалёнку
человек делает сам (или разрешает явно и разово).

### 5.2 Никакого технического долга

Запрещено: костыли, временные заглушки «на потом», копипаст логики,
дублирование функциональности, искусственное усложнение, переписывание
рабочего кода без необходимости.

### 5.3 Перед изменением кода

1. Изучить существующую архитектуру и переиспользовать имеющиеся компоненты.
2. Не дублировать; не ломать обратную совместимость.
3. Если функция уже есть в `core/` — расширять её, а не делать вторую.

### 5.4 Если информации недостаточно

**Не выдумывать.** Остановиться и задать уточняющий вопрос.

---

## 6. Процесс выполнения каждой задачи

Каждая задача проходит строго по шагам:

1. **Анализ** — что уже есть, какие файлы затронем, контракты.
2. **План** — что и как меняем (показать ДО кода для нетривиальных задач).
3. **Реализация** — минимальный связный диф.
4. **Проверка совместимости** — не сломаны ли контракты/раскладки/`.exe`-путь.
5. **Проверка ошибок** — `pytest`, `ruff` (если есть), headless-сборка окна.
6. **Отчёт** (см. §7).

Крупные/хаотичные изменения без предварительного утверждённого плана — запрещены.
Двигаемся по цепочке: **Roadmap → Epic → Feature → Task → Implementation →
Testing → Review → следующий Task**.

---

## 7. Формат отчёта после каждой задачи

После каждой задачи Codex обязан выдать:

- **Что сделано**
- **Какие файлы изменены** (список путей)
- **Почему выбрано именно это решение**
- **Какие есть риски**
- **Что рекомендуется делать дальше**

---

## 8. Приоритеты (в этом порядке)

1. Стабильность
2. Масштабируемость
3. Поддерживаемость
4. Красивый код
5. Новые функции

Если фича конфликтует со стабильностью — побеждает стабильность.

---

## 9. Тесты

```bash
pip install -r requirements-dev.txt
pytest
```

Набор **offline** и **headless** (Qt в режиме `offscreen`). Любая новая логика
покрывается тестами без сети: сетевые вызовы стабятся (`_fetch`, subprocess и т.п.).
Не добавлять тесты, требующие реального интернета или внешних бинарей.

---

## 10. Роль Codex в связке

- **GPT** — CTO / Architect / Reviewer / Planner (стратегия, ревью плана).
- **Codex** — Senior Engineer: рефакторинг, тесты, аккуратная реализация
  утверждённого плана.
- **Gemini** — альтернативные идеи / research / критика архитектуры.

Codex не принимает крупных архитектурных решений в одиночку без плана —
сначала план, утверждение, потом реализация поэтапно.

---

## 11. Текущий фокус

**Epic: ASM Platform 2.0** — детальный план, модели данных, изменения SQLite,
Dashboard и Reporting, риски и точки интеграции описаны в
**`ROADMAP_ASM_2.0.md`** (корень проекта). Начинать строго с него.

---

## 12. Текущее состояние (оперативная карта, коротко)

> Этот раздел намеренно короткий: Claude Code держит `CLAUDE.md` в контексте, поэтому длинную историю нельзя хранить здесь.
> Полный хронологический лог реализаций — `PROJECT_STATUS.txt`, каталог модулей/метрик — `PROJECT_REPORT.md`, плановые детали — `ROADMAP_ASM_2.0.md`.

**Документы-источники (не плодить новые):**
- `CLAUDE.md` — правила, архитектура, инварианты и короткий актуальный статус.
- `AGENTS.md` — зеркало `CLAUDE.md` для Codex; держать синхронно.
- `ROADMAP_ASM_2.0.md` — roadmap/эпики/решения по ASM 2.0 и EPIC NEXT.
- `KICKOFF_PROMPT.md` — стартовый промпт эпика.
- `PROJECT_STATUS.txt` — полный исторический журнал реализаций.
- `PROJECT_REPORT.md` — обзор модулей, метрик, тестового состояния и текущей зрелости.

**Текущая зрелость продукта:** Advanced Site Analyzer уже не просто scanner/recon GUI, а локальная ASM/CSM-платформа для авторизованного анализа: Full Collection, проекты, persistent findings lifecycle, asset inventory, timeline/change events, monitoring, alert center, overview/portfolio, intelligence layer, business context, attack paths, remediation, compliance, IaC ingestion и PySide6/Fluent GUI.

**Главные закрытые блоки:**
- ASM 2.0 F1–F6 закрыты: Findings Management, Timeline, Continuous Monitoring, Alert Center, Executive Dashboard, GUI Redesign.
- Asset Inventory, SLA, portfolio, charts, attack-surface graph, risk/executive summary и report/web/CSV-проводки работают поверх существующих стор/metadata без лишних таблиц.
- Advanced Intelligence закрыт: confidence/priority/explanation, asset criticality, priority deepening, deterministic attack paths, surfaces/report/web, monitoring persistence.
- Infrastructure/Technology/Integration waves закрыты: cloud/region classification, tech risk, SARIF, Markdown, generic webhook, CI gate, GitHub Issues push, OWASP/CWE compliance, severity/timeline/report convergence.
- EPIC NEXT закрыт: migrations/contracts, Business Context Model, business-aware prioritization, deterministic attack paths, remediation tasks, semantic drift, auditor-friendly compliance, IaC ingestion.
- GUI-хвосты закрыты: Criticality business editor, per-asset business override, Remediation tab, IaC Config tab.
- Client-Safe Pentest Workbench (v1) закрыт: audit-run workflow/phases, ROE/scope+action policy, finding validation/quality gate, schemas, AuditRunStore, report JSON/MD/HTML, тонкая вкладка Audit Runs.
- Workbench v2 закрыт: audit scenario templates, ROE/scope templates, re-validation unresolved findings, Audit Run A/B compare (+gate), template+compare report surfaces, GUI scenario/compare controls, web read-parity (`/audit-runs`, `/audit-compare`).
- KEV/EPSS Threat Intelligence Feed закрыт: `core/threat_feed.py` (KEV+EPSS парсеры+seam) + `CVEStore.cve_threat`, `core/threat_intel.py` (enrich/annotate/tier derive-on-read), seam в `intelligence._threat_tier` (priority-формула не менялась), opt-in `_phase_threat` (не scope-gated) + monitor/GUI parity, поверхности report-card/web/CSV. KEV→SLA отложено.

**Ключевые рабочие модули:**
- `core/project.py` — единственный источник правды по проектам/сканам/metadata.
- `core/findings_store.py`, `core/findings_adapter.py`, `core/finding_fingerprint.py` — lifecycle находок и dedup.
- `core/asset_store.py`, `core/asset_adapter.py`, `core/asset_graph.py`, `core/correlation.py` — asset inventory/correlation/exposure.
- `core/timeline.py`, `core/scan_diff.py`, `core/monitor.py`, `core/alerts.py` — история, drift/change events, monitoring/alerts.
- `core/intelligence.py`, `core/business_context.py`, `core/remediation.py`, `core/compliance.py`, `core/iac_scanner.py` — business/risk/paths/remediation/compliance/IaC слой.
- `gui/tab_*` — тонкие mixin-вкладки; любые фоновые операции идут через `_start_task()` / `_run_async()`.
- `remote/web_app.py` — LAN web-console, parity через тонкие helpers/JOBS.
- `core/audit_workflow.py`, `core/audit_templates.py`, `core/audit_scope.py` (ROE+ROE-templates), `core/audit_checks.py`, `core/scope_policy.py`, `core/action_policy.py`, `core/finding_validation.py`, `core/finding_quality.py`, `core/audit_revalidation.py`, `core/audit_compare.py`, `core/audit_report.py`, `core/audit_store.py`, `core/audit_schema.py` + `schemas/asa_audit_*.schema.json` — Client-Safe Pentest Workbench (v1+v2). Единый `FindingsStore` SoT; compare derive-on-read; всё client-safe.
- `core/pentest_mission.py` + `schemas/asa_pentest_mission.schema.json` — Mission Center M1: чистый offline-контракт «миссии» поверх Audit Runs/FindingsStore/Scope/ROE (без второго стора). API create/normalize/validate/advance_mission_status/link_audit_run/link_finding/mission_to_json; guardrails переиспользуют `audit_scope`/`audit_templates`/`action_policy`; client-safe, evidence-first.
- `core/mission_store.py` — Mission Center M2: `MissionStore(SQLiteStore)` (single-table `missions`, без events; save_mission валидирует через `mission_to_json`+схему; get/list/delete/export). Участвует в `project_io` bundle (`missions.json`) через events-less `PROJECT_EXPORT`.
- `gui/tab_missions.py` + web `/missions[/{id}]` + timeline mission-события — Mission Center M3: тонкие read/parity-поверхности над `MissionStore`/`pentest_mission` (без нового состояния). Вкладка Missions: список+detail, status-advance (легальные переходы из `MISSION_TRANSITIONS`), add-links существующих audit runs/findings (`link_audit_run`/`link_finding`→`save_mission`); lazy-load в `_on_tab_changed`. Web read-parity зеркалит `/audit-runs`. `timeline.build_events(..., missions=)` derive-on-read: `mission_created`+статус-событие (без второй таблицы).
- `core/audit_runner.py` — единый оркестратор Audit Run (`build_audit_run` + helpers: target/candidate/rows/rollup/events/rows_from_run), вынесен из `gui/tab_audit_runs` (вкладка теперь тонкий делегатор). `core/mission_runner.py` — Mission Center M4 execution: `run_mission(mission)` гоняет `ready` миссию как Audit Run через `audit_runner.build_audit_run` (checks = allowed_actions ∩ `SAFE_CHECKS`), линкует run и двигает `ready→running→completed` (или `→failed` с пробросом ошибки); GUI «Run mission» + web `POST /missions/{id}/run`. Второго стора нет — run в `AuditRunStore`.

**Последние важные изменения на 2026-06-29 (Mission Center M4 — execution):**
- M4: запуск миссии как Audit Run, без второго стора. Архитектурное решение D1 (locked): оркестрация Audit Run вынесена из инлайна GUI (`tab_audit_runs._query_audit_run`) в новый `core/audit_runner.py` — `build_audit_run(project, *, run_id, roe, checks, template, evidence, fetcher) -> {project, run, rows, saved}` + helpers (`target_from_roe`, `audit_candidate`, `build_audit_rows`, `rollup`, `rows_from_run`, `record_audit_events`); вкладка Audit Runs теперь тонкие делегаторы (контракт static-методов сохранён для тестов). Новый `core/mission_runner.py`: `run_mission(mission, *, now, run_id, evidence, fetcher)` — нормализует+валидирует миссию, требует `ready`, двигает `ready→running` (persist), строит+сохраняет Audit Run через `audit_runner` (checks = `allowed_actions ∩ audit_checks.SAFE_CHECKS`; ROE-gated; без сети без `fetcher`), `link_audit_run`→`running→completed`; при ошибке оркестрации миссия персистится `failed` и исходная ошибка пробрасывается (save-failure не маскирует). Surfaces (D2 locked): GUI кнопка «Run mission» на вкладке Missions (активна только для `ready`), web `POST /missions/{id}/run` (синхронный per-resource mutation как `/findings/{id}/status` — bounded+offline, не named-phase JOBS; 404 unknown / 400 not-ready). Decisions: completed если оркестрация завершилась (любое число находок), failed только на исключении; offline-safe по умолчанию (probe = no-op без fetcher). Файлы: `core/audit_runner.py` (new), `core/mission_runner.py` (new), `gui/tab_audit_runs.py`, `gui/tab_missions.py`, `remote/web_app.py`, тесты `test_mission_runner.py` (new)/`test_missions_tab.py`/`test_web_missions.py` (`audit_runner` покрыт делегаторами вкладки Audit Runs + `mission_runner`). Проверено: ruff clean, self-check 30 вкладок, полный pytest зелёный.

**Ранее на 2026-06-29 (Mission Center M3 — read/parity surfaces):**
- M3: операторские поверхности над персистентными миссиями, без нового стора/состояния. Новая `gui/tab_missions.py` (`MissionsTabMixin`) по образцу `tab_audit_runs`: project-селектор → таблица миссий (из `MissionStore.list_missions`), detail-панель (objective/ROE/allowed_actions/linked runs+findings), **view + status-advance** (комбо легальных целей из `pentest_mission.MISSION_TRANSITIONS`, advance через `advance_mission_status`→`save_mission`) и **add-links селекторы** (привязка существующих audit run/finding через `link_audit_run`/`link_finding`→`save_mission`); вся фоновая работа через `_run_async`/`_set_busy`, lazy-load через `_missions_widget` в `tab_history._on_tab_changed`. Регистрация — запись в `plugin_manager.BUILTIN_TABS` + база в `main_window.py` (30 вкладок). Web read-parity: `remote/web_app._missions_list`/`_mission_view` + `/missions`, `/missions/{id}` (404 на unknown), зеркало `/audit-runs`. Timeline: `core/timeline.build_events` получил `missions=` — derive-on-read `mission_created` (по `created_at`) + одно статус-событие (по `updated_at`, если не `draft`), секция `missions`, без второй таблицы; `build_timeline` грузит `MissionStore().list_missions(slug)` best-effort. Решения (locked): GUI = view+status-advance (без формы создания — создание остаётся в core/store); surfaces = web read-parity + timeline; linking = add-links селекторы. Файлы: `gui/tab_missions.py`, `gui/plugin_manager.py`, `gui/main_window.py`, `gui/tab_history.py`, `remote/web_app.py`, `core/timeline.py`, `tests/gui_test_helpers.py`, `tests/test_missions_tab.py`, `tests/test_web_missions.py`, `tests/test_timeline.py`. Проверено: ruff clean, self-check 30 вкладок, полный pytest 2200 зелёных (1 Starlette/httpx warning).

**Ранее на 2026-06-28 (Mission Center M2 — persistence + bundle):**
- M2: персистентность миссий + участие в project-bundle. Новый `core/mission_store.py` — `MissionStore(SQLiteStore)` по образцу `AuditRunStore`, но **single-table** (у миссии нет events в M1-контракте): таблица `missions` (id/project/profile/status/payload/created_at/updated_at); `save_mission` нормализует+валидирует схему через `pentest_mission.mission_to_json` перед записью (идемпотентно, `created_at` сохраняется); get/list/delete/export_mission. База `utils/sqlite_store.py` обобщена под **events-less** `PROJECT_EXPORT` (`events_table=None`) — single-table стор участвует в bundle без фантомной events-таблицы; 3-tuple путь (findings/assets/audit) не изменён. `core/project_io.py`: в bundle добавлен `missions.json` (зеркало `audit_runs.json`) + счётчик `missions`; `FORMAT_VERSION` остался 1 (аддитивно — старый bundle без `missions.json` импортируется как 0 миссий). Решения D1–D5 как утверждены (single-table; генерализация базы; формат 1; колонки как audit; GUI не трогаем). Файлы: `core/mission_store.py`, `utils/sqlite_store.py`, `core/project_io.py`, `tests/conftest.py`, `tests/test_mission_store.py`, `tests/test_project_io.py`. Проверено: ruff clean, целевые+смежные (findings/asset/sqlite store) зелёные.

**Ранее на 2026-06-28 (Mission Center M1 — core contract):**
- Стартовал стратегический слой Mission Center / Authorized Pentest Multitool. M1 = чистый детерминированный offline-контракт «миссии» (аналог `core/audit_workflow.py`, без состояния/IO/сети/записи в FindingsStore). Новый `core/pentest_mission.py`: миссия = `mission_id` (sha1 от project|objective), project, objective, фикс. `profile=client_safe`, опц. `template` (сценарий из `audit_templates`), нормализованный `roe` (SSOT, включает scope — отдельного scope-поля нет), client-safe `allowed_actions`, `status`, `report_orientation=evidence_first`, `linked_audit_run_ids`/`linked_finding_ids`. API: `create_mission`/`normalize_mission`/`validate_mission`/`advance_mission_status`/`link_audit_run`/`link_finding`/`mission_to_json`. Статус-машина: draft→{ready,archived}, ready→{running,draft,archived}, running→{completed,failed,archived}, completed→{archived}, failed→{ready,archived}, archived терминальный; →ready требует валидной миссии. Guardrails переиспользованы, не продублированы: ROE — `audit_scope`, сценарий — `audit_templates`, каждое `allowed_actions` гейтится `action_policy` (exploit/bruteforce/stealth/auto-login/auth-bypass/persistence запрещены по классу). Новая `schemas/asa_pentest_mission.schema.json` + 1-строчный alias в `audit_schema.SCHEMA_ALIASES`. Решения: D1 только pure-contract (MissionStore/GUI/web/timeline → M2+); D2 карта переходов; D3 scope внутри ROE; D4 `link_finding` без проверки в FindingsStore; D5 имя модуля. Файлы: `core/pentest_mission.py`, `schemas/asa_pentest_mission.schema.json`, `tests/test_pentest_mission.py` (35 offline), `core/audit_schema.py` (alias). Проверено: ruff clean, целевые+смежные зелёные.

**Ранее на 2026-06-28 (EPSS daily-CSV bulk ingestion):**
- Закрыт последний хвост KEV/EPSS. Opt-in альтернативный источник EPSS: вместо per-CVE API — полный дневной датасет FIRST одним gzip-CSV. `core/threat_feed.py`: `parse_epss_csv` (чистый; пропускает `#`-комменты+header) + `fetch_epss_csv` (одна загрузка; `_get_text` разжимает gzip по magic-number, отдельный bytes-seam не нужен; свой таймаут 30с). `threat_intel.enrich_cves(..., epss_csv=True, epss_csv_get=...)` тянет CSV один раз и берёт нужные CVE; **персистятся только нужные** (footprint кэша тот же); сбой CSV → **fallback на per-CVE API** (EPSS не теряется). Провязка opt-in под-флагом `threat_epss_bulk` (off by default): `CollectionRunner` (ctor+configure+`_phase_threat`), `monitor` opts, GUI-под-чекбокс под KEV/EPSS. Дефолт (per-CVE) не менялся. Файлы: `core/threat_feed.py`, `core/threat_intel.py`, `core/collection_runner.py`, `core/monitor.py`, `gui/tab_collection.py`, тесты `test_threat_feed.py`/`test_threat_intel.py`. Проверено: ruff clean, целевые+смежные тесты зелёные.

**Ранее на 2026-06-28 (KEV/EPSS бейдж в findings detail):**
- `gui/tab_findings.py`: строки в `_query_findings_table` теперь threat-annotate-ятся из offline-кэша (`threat_intel.annotate_offline`) ПЕРЕД SLA-annotate → SLA-колонка в GUI тоже ужесточается для KEV (консистентно с отчётом). Detail-панель показывает бейдж «⚠ Exploitability» (единая формулировка через `threat_intel.threat_label` — KEV явно, EPSS-перцентиль) + пометку «ужесточено: KEV/EPSS, базовое Nд» рядом с сокращённым SLA. KEV-строка помечается и в списке (critical-цвет заголовка + tooltip). Контракт колонок не менялся; холодный кэш/не-CVE — как раньше. LAN web-консоль (`remote/web_app._findings_list`) переупорядочена так же — threat-annotate перед SLA-annotate — поэтому `/findings` SLA тоже ужесточается для KEV. Файлы: `core/threat_intel.py` (+`threat_label`), `gui/tab_findings.py`, `remote/web_app.py`, тесты `test_threat_intel.py`/`test_findings_tab.py`/`test_web_findings.py`. Проверено: ruff clean, целевые+смежные тесты зелёные.

**Ранее на 2026-06-28 (NEW_KEV event + KEV alert rule):**
- Известно-эксплуатируемые находки стали first-class сигналами (derive-on-read из offline threat-кэша, без второй таблицы). Timeline: `threat_intel.kev_events(findings)` → строка `new_kev` на активную KEV-находку (дата = `first_seen_at`, severity `high`, базовая severity в заголовке); провязка через новый параметр `kev_events` в `timeline.build_events` поверх того же annotate-списка, что и SLA (annotate один раз). Alert rule: `alerts.collect_kev_alerts` + `notify_kev` (тип `new_kev` в `ALERT_TYPES`), finding-based one-shot канал как SLA/secret/generic (`FindingsStore.record_kev_alerts`, маркер `KEV_ALERTED`, reopen-resetting); диспатч в `monitor._run` рядом с прочими finding-based каналами; холодный кэш = ничего. GUI-метки добавлены (`gui/dialogs`, `gui/tab_timeline`). Файлы: `core/threat_intel.py`, `core/timeline.py`, `core/alerts.py`, `core/findings_store.py`, `core/monitor.py`, `gui/dialogs.py`, `gui/tab_timeline.py`, тесты `test_threat_intel.py`/`test_timeline.py`/`test_alerts.py`. Проверено: ruff clean, целевые+смежные тесты зелёные.

**Ранее на 2026-06-28 (KEV→SLA tightening, follow-up):**
- Закрыт follow-up KEV→SLA (одобрен отдельно; roadmap «Follow-up — KEV→SLA tightening (CLOSED)»). Находка с реальным KEV/EPSS-блоком `threat` получает ужесточённое SLA-окно: множитель по tier (high ×0.25 / medium ×0.5, `THREAT_SLA_MULTIPLIER`, per-tier override через новый `threat_mult`), floor-семантика (окно только сокращается). `sla_status` теперь отдаёт эффективное `sla_days` + `base_sla_days` + `tightened_by` (`kev`/`epss`/`None`) → due/breach/days_left/bucket/summary считаются по сокращённому дедлайну. Самогейтинг: ужесточает только кэш-сигнал KEV/EPSS (статическая priority-эвристика — нет); нет `threat`-блока → обычное окно (ноль изменений для не-enriched прогонов). Все breach-поверхности annotate-ят активные находки из offline-кэша перед SLA: `collection_runner._sync_findings` (`sla_summary`), Alert Center `alerts.collect_sla_alerts` (KEV-находка алертит по сокращённому дедлайну), Timeline `timeline.build_timeline`→`sla_events` (событие `sla_breach` на ужесточённой дате). Единый best-effort seam — `threat_intel.annotate_offline` (SSOT; SLA/alerts/timeline/priority используют его вместо дублей inline-guard). Файлы: `core/findings_sla.py`, `core/threat_intel.py`, `core/alerts.py`, `core/timeline.py`, `core/collection_runner.py`, `core/intelligence.py`, тесты `tests/test_findings_sla.py`/`test_alerts.py`/`test_timeline.py`. Проверено: ruff clean, целевые+смежные тесты зелёные.

**Ранее на 2026-06-28 (KEV/EPSS Threat Feed):**
- Закрыт эпик KEV/EPSS (roadmap «EPIC CLOSED — KEV/EPSS Threat Intelligence Feed»): ранжирование находок по реальной эксплуатируемости. F1 `core/threat_feed.py` (парсеры CISA KEV + FIRST EPSS, injectable seam) + таблица `cve_threat` в `CVEStore`. F2 `core/threat_intel.py`: `enrich_cves` (network: KEV раз + EPSS per-CVE, persist, soft-degrade без false-negatives), `annotate` (offline derive-on-read → блок `threat`+`tier`), пороги KEV→high/EPSS≥0.90→high/≥0.50→medium (именованные константы). F3 seam в `intelligence._threat_tier` (enrichment-first, fallback на статику — ноль регресса; `build_intelligence` += best-effort offline annotate; priority-формула НЕ менялась). F4 opt-in `_phase_threat` в CollectionRunner (после dedup, не scope-gated — метаданные о CVE без трафика к цели, off by default, soft-degrade) + monitor/GUI parity. F5 поверхности: report-card «Exploitability (KEV/EPSS)», web `/findings` threat-блок, CSV-колонки. Decisions: tier-пороги; только priority (KEV→SLA отложено); opt-in не под Scope Guard; TTL 24ч. Проверено: ruff clean, full pytest 2101 passed, self-check 29 вкладок.

**Ранее на 2026-06-28 (Workbench v1+v2):**
- Client-Safe Pentest Workbench v1 закрыт (audit-run workflow, ROE/scope/action policy, validation/quality gate, schemas, store, report JSON/MD/HTML, тонкая вкладка).
- Workbench v2 закрыт (эпик в `ROADMAP_ASM_2.0.md` «EPIC CLOSED — Workbench v2»): F1 `core/audit_templates.py` (4 сценария; `create_audit_run` += opt-in `template`/`roe`/`baseline_run_id`, bare-вызов = v1), F2 ROE/scope-шаблоны в `core/audit_scope.py`, F3 `core/audit_revalidation.py` (overlay по unresolved, lifecycle не трогаем, липкость соблюдена), F4 `core/audit_compare.py` + `schemas/asa_audit_compare.schema.json` (A/B по finding_id, gate, упавшая фаза=inconclusive, derive-on-read, опц. `compared`-событие), F5 compare+scenario рендеры в `core/audit_report.py`. GUI: scenario-селектор + baseline-compare + export в `gui/tab_audit_runs.py`. Web read-parity: `/audit-runs`, `/audit-runs/{id}`, `/audit-compare`. Decisions locked: bare=v1; authenticated=только safe checks; compare derive-on-read; failed phase=inconclusive. Проверено: ruff clean, full pytest 2074 passed (1 Starlette warning), self-check 29 вкладок.

**Более ранние изменения на 2026-06-23:**
- GUI polish (юзабилити, без слома вкладок/контрактов; окно — нативный `QMainWindow` `StableWindowBase`, не frameless qfluent): (1) `utils/subprocess_utils.py` — `run_hidden`/`popen_hidden` прячут cmd-окна внешних CLI на Windows; переведены все рантайм-вызовы (nuclei/katana/amass/subfinder/httpx/bbot/lift через `external_tools.run_command`, + rar/yt-dlp/ffmpeg/scrapy/relaunch/git). (2) Тема: слоистая dark-палитра + централизованный dark-QSS (таблицы/inputs/scrollbars/tab-pane) в `gui/theme.py`; рейл стилизуется из `theme.navigation_qss()` (sidebar совпал с темой, accent-selected). (3) `gui/ui_components.py`: `linkify`/`make_selectable_label`/`make_link_label`/`SelectableText`/`LinkTextBrowser` — ссылки кликабельны/копируемы (применено к Findings detail + health-диалогу). (4) Settings открывается размером 580×600 (поля «Уведомления» видны; скролл уже был). Sidebar wheel-scroll/collapse/footer/`&`-fix — уже были и покрыты тестами. Все изменения покрыты тестами; frozen self-check 28 вкладок.
- Release-слой (шаг 5): добавлен `core/project_io.py` — экспорт/импорт проекта одним `.zip` (дерево `Projects/<slug>` + faithful срез findings/assets со строками и событиями lifecycle; zip-slip/SQL-safe). Generic срез — `SQLiteStore.export_project`/`import_project` (декларация `PROJECT_EXPORT` в findings/asset сторах). Поверхность — кнопки Export/Import project в Overview. Добавлен `CHANGELOG.md` (Keep a Changelog; 1.0.0 + Unreleased). Добавлен `gui/first_run.py` — first-run onboarding + system-health screen поверх `launcher.health_check` (+ пункт «Состояние системы» в nav, хук в `main.py`). Подтверждено: `init_path_manager()` во frozen-пути чтит `ASA_DATA_ROOT`. Покрыто `tests/test_project_io.py`/`test_first_run.py` + GUI-тесты Overview.
- Demo/Release подготовка: добавлен `ASA_DATA_ROOT` env-override в `PathManager._detect_data_root` (единый seam — уводит ВСЕ data-БД/configs/settings/workspaces под один каталог, портится поверх source- и frozen-дефолтов; явный `data_root=` ctor-арг по-прежнему выше). Добавлен `demo_seed.py` (entry-скрипт корня): сеет self-contained demo workspace (1 company + 3 домена, 7 сканов, lifecycle-находки с drift, активы, business-контекст, remediation) в один каталог через явные PathManager-пути; запуск приложения — `ASA_DATA_ROOT=<dir> python main.py`. Проверено end-to-end (override → GUI читает портфель) + `tests/test_demo_seed.py`/`test_paths.py`.
- Подтверждён GUI smoke (живой `MainWindow`, 28 вкладок): Criticality/Remediation/IaC/Overview-Portfolio на едином богатом проекте.
- Почищен устаревший статус-баннер EPIC NEXT в `ROADMAP_ASM_2.0.md` (NOT STARTED → ЗАКРЫТ).
- Добавлен per-asset business context editor в Criticality GUI.
- Backend polish (F-SR1): SSOT для SQLite timestamp/severity/OSINT target parse, robustness-hardening malformed inputs. Коммит: `abca7ee`.

**Тестовый ориентир:**
- `PROJECT_REPORT.md` указывает актуальный масштаб набора; на 2026-06-29 (после Mission Center M4) — 2209 offline/headless тестов (зелёные, 1 Starlette/httpx warning).
- Перед релизной пометкой обязательно прогонять `pytest` и, если менялся GUI/frozen-контур, self-check окна/PyInstaller smoke.
- На Windows при полном pytest возможны temp/cache teardown quirks; для чистой проверки удобно использовать уникальный `--basetemp` и `-p no:cacheprovider`.

**Что делать дальше в первую очередь:**
1. ✅ Подтверждён полный pytest после backend polish (1798 зелёных).
2. ✅ Почищен устаревший статус-баннер EPIC NEXT в `ROADMAP_ASM_2.0.md`.
3. ✅ Проведён живой GUI smoke (Criticality/Remediation/IaC/Overview-Portfolio).
4. ✅ Подготовлен demo workspace (`demo_seed.py` + `ASA_DATA_ROOT` override).
5. ✅ Релиз-слой: CHANGELOG + version, project import/export (`core/project_io.py` + Overview GUI), first-run/system-health screen (`gui/first_run.py`), frozen чтит `ASA_DATA_ROOT` (через `init_path_manager()`). Остаётся по желанию: фактический PyInstaller build на стороне пользователя для поставки `.exe` + подпись/инсталлятор.

**Осознанно отложено и не является блокером:**
- live KEV/EPSS threat feed;
- live cloud API ingestion;
- прямой path→task mapping;
- расширенная коммерческая упаковка/лицензирование;
- новые внешние сканеры без ясной пользы для lifecycle/business layer.

**Главное правило следующей разработки:** не добавлять “ещё один сканер” ради количества. Приоритет — стабильность, управляемость находок, понятная ценность для пользователя, demo/release готовность и аккуратное развитие lifecycle/business intelligence слоя.
