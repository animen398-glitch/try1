# CLAUDE.md — Advanced Site Analyzer

> Этот файл Claude Code читает автоматически в начале каждой сессии.
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

> **CRITICAL**: All `memanto` commands are **shell commands**. Always run them using the Bash tool.
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

> **Note**: The `memanto-memory` skill contains reference guidelines only (best practices, confidence levels, tagging). It is NOT executable — always use Bash for memanto commands.
<!-- /MEMANTO-MANAGED-SECTION -->

## 1. Что это за проект

**Advanced Site Analyzer** — десктопный инструмент (Python 3.11+ / PySide6 через qtpy) для
авторизованного анализа веб-сайтов: recon, перечисление субдоменов, перехват
динамического трафика и API, аудит безопасности (секреты, source maps,
cookie, GraphQL), захват и оффлайн-клонирование фронтенда.

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
  file_compression.py
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
6. **Опциональные зависимости — мягкая деградация.** Нет Playwright/
   fastapi/scrapy → фича отключается с подсказкой, приложение не падает.
7. **Backward compatibility.** Раскладка `Projects/<домен>/`, `metadata.json`,
   `report.json` и контракты `_start_task/_run_async/_set_busy/_browse` не ломать.

---

## 5. Жёсткие правила (НЕ нарушать никогда)

### 5.1 Работа только локально

**Разрешено** (норма с 2026-06-15): локальные коммиты — Claude сам коммитит
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

После каждой задачи Claude обязан выдать:

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

## 10. Роль Claude Code в связке

- **GPT** — CTO / Architect / Reviewer / Planner (стратегия, ревью плана).
- **Claude Code** — Senior Engineer: рефакторинг, тесты, аккуратная реализация
  утверждённого плана.
- **Gemini** — альтернативные идеи / research / критика архитектуры.

Claude Code не принимает крупных архитектурных решений в одиночку без плана —
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
- `core/mission_report.py` — Mission Center M5 report: `build_mission_report(mission)` собирает evidence-first view (envelope + linked audit runs через `audit_report.client_findings/review_findings` + appendix явно-связанных findings из `FindingsStore`; stale-линки помечаются, не фейкаются) + pure `render_json/markdown/html`. GUI export (JSON/MD/HTML) на вкладке Missions + web `GET /missions/{id}/report[.md]`. View, не стор.
- Mission Center M6 creation: создание миссии из GUI (панель «Create mission» на вкладке Missions — project/objective/scenario/ROE/allowed_actions-чекбоксы из `SAFE_CHECKS`) и web `POST /missions`; оба зовут `pentest_mission.create_mission`+`validate_mission` (client-safe гейт перед `MissionStore.save_mission`). Нового ядра нет — переиспользован контракт M1.
- `core/mission_overview.py` — Mission Center M7 portfolio overview: `build_mission_overview(*, mission_store, audit_store, project)` derive-on-read (counts by status + per-mission last-run outcome + client-facing totals через `audit_report.client_findings`; view, не стор). GUI карточка «Миссии (Mission Center)» на вкладке Overview + web `GET /missions/overview`.
- Mission Center M8 timeline run-events: `timeline.build_events(..., mission_runs=)` — на каждый linked Audit Run миссии событие `mission_run_started` (по `created_at` run'а) + терминальное `mission_run_completed`/`mission_run_failed` (по `updated_at`), секция `missions`. `build_timeline` резолвит linked runs против уже загруженных audit_runs (build_events остаётся чистым шейпером). GUI/web не трогались — секция `missions` рендерится generically с M3.
- `core/mission_schedule.py` — Mission Center M9 recurring scheduling: `run_due_missions`/`set_mission_schedule`/`disable_mission_schedule`/`run_mission_audit` поверх `monitor`-кадансов (`compute_next_run`/`is_due`); тик исполняет audit run миссии и линкует его БЕЗ продвижения one-shot статус-машины (recurring-friendly). Расписание — в новой колонке `schedule` таблицы `missions` (MissionStore v2, отдельно от canonical payload). GUI Enable/Disable/«Run due now» + web `POST /missions/{id}/schedule`, `POST /missions/run-due`. M10: авто-тик — `run_due_missions(on_event=)` подключён к monitor-тику через generic `MonitorScheduler.extra_tick` (in-app `MonitorRunnerMixin._tick_due_missions` + `monitor_cli run/watch`); `monitor.format_event` рендерит `mission_run`.
- `core/mission_links.py` — Mission Center M11 link integrity (закрывает M1 D4): `link_audit_run_checked`/`link_finding_checked` (проверяют существование в AuditRunStore/FindingsStore перед чистым линком) + `resolve_links` (present vs stale-партиция). Контракт `pentest_mission.link_*` остаётся ЧИСТЫМ — проверка только в этом opt-in слое. GUI add-links теперь checked + detail помечает stale-линки.
- `demo_seed.py` — Mission Center M12: demo workspace теперь сеет 3 миссии на первом проекте (ready+scheduled weekly; executed с linked run+finding; одна со stale-линком) → весь M1–M11 lifecycle виден в Missions-вкладке/Overview-карточке; `seed()` summary += `missions`.
- Mission Center M13 CSV export: `report_export.missions_csv(overview)` (колонки mission_id/project/objective/status/last-run/client-facing/updated; принимает overview-dict или bare-list) поверх `mission_overview` rows. GUI «Export CSV» на вкладке Missions + web `GET /missions.csv`.
- Mission Center M14 stale-link cleanup: `mission_links.prune_stale_links(mission, *, stores)` → новая миссия только с present-линками (+ `removed_runs/removed_findings`); чистый rebuild через `normalize_mission`, input не мутируется. GUI «Remove stale» (активна при stale-линках) + web `POST /missions/{id}/links/prune`.
- Mission Center M15 run trend: `mission_overview.mission_run_trend(mission, *, audit_store)` → `[{run_id, at, status, client_facing}]` (derive-on-read по linked runs, `audit_report.client_findings`). GUI: «Run history» в detail вкладки Missions + web `GET /missions/{id}/runs`. Закрывает дугу M1–M15.
- `core/tool_adapter.py` — Tool Adapter Contract Foundation: чистый/offline contract-слой для будущего подключения внешних recon/audit-tools к миссии БЕЗ запуска, без сети, без store-writes. DTO `ToolCapability`(+registry)/`ToolRunRequest`/`ToolRunResult`/`ToolFinding`/`ToolAsset`; `build_tool_request`/`evaluate_tool_allowed_for_mission`/`map_tool_result_to_findings`/`tool_result_to_json`. Gate переиспользует `scope_policy.evaluate_scope_policy` (→ `action_policy`+`scope_guard`), передавая ROE как scope; target из `roe.allowed_domains`. Schema `asa_tool_run` (+alias в `audit_schema`).
- `core/tool_parsers.py` — Per-Tool Offline Parsers (слой над M3): `parse_tool_output(tool, evidence)` превращает уже-захваченный evidence в generic `{findings, assets}` для `map_tool_result_to_findings`; БЕЗ запуска tools/сети/store-writes. Покрыты ВСЕ 8 registry-tools: header/cookie/source-map (reuse `core.audit_checks`), `safe_active_prober` (asset/enumeration), `dependency_auditor` (reuse `dependency_audit.audit`), `iac_config_auditor` (reuse `iac_scanner.scan_path`, локальный файл-ридинг), `graphql_introspector`/`tls_audit` (малая pure-детекция по captured evidence). Реестр `PARSERS` (additive); unknown/empty/unparsed tool → `ValueError`.
- `core/tool_pipeline.py` — Offline Tool-Evidence Pipeline (капстоун tool-слоя): `assemble_tool_run(mission, tool, evidence, *, target)` композитит M3-gate (`evaluate_tool_allowed_for_mission`) + parser (`parse_tool_output`) + mapper (`map_tool_result_to_findings`) в один store-free `ToolRunResult`. Статусы: `blocked` (политика/ROE запретили — evidence НЕ парсится), `skipped` (allowed, но нет парсера), `completed`. Без запуска tools/сети/store-writes; evidence — захваченный вход, не fetched.
- `core/tool_ingest.py` — Tool→Canonical Finding/Asset Bridge: `tool_result_to_findings(result)`/`tool_result_to_assets(result)` — чистый конвертер `ToolRunResult` → канонические `findings_adapter.Finding`/`asset_adapter.Asset` DTO (reuse `from_raw`: tool-finding получает fingerprint-identity/category/severity как у сканера; category из action; string-refs в `detail`). БЕЗ store-writes — ingestion в FindingsStore/AssetStore остаётся отдельным явным шагом.
- `core/tool_report.py` — Tool-Run Report Renderer (презентация tool-стека): `render_json/render_markdown/render_html(result)` поверх canonical payload `ToolRunResult` (`tool_result_to_json`); envelope + findings/assets таблицы; HTML escaped + `markdown-sha` (зеркало `audit_report`/`mission_report`). View, не стор; детерминирован, без сети/store-writes/новых deps.
- `core/tool_ingest_store.py` — Gated Tool-Run Ingestion (ПЕРВЫЙ store-writing шаг tool-слоя): `ingest_tool_run(result, project, scan_id, *, findings_store, asset_store)` персистит findings/assets completed- result через bridge в существующие `FindingsStore.upsert`/`AssetStore.sync` (idempotent). Gated: пишет ТОЛЬКО при `status=="completed"`; blocked/skipped/иное → no-op. Без второго стора, без сети, без запуска tools.
- `core/tool_runner.py` — End-to-End Tool-Run Orchestrator (капстоун tool-слоя) + scan-id SoT: `run_tool_for_mission(mission, tool, evidence, *, scan_id, project=None, target=None, findings_store=None, asset_store=None)` композитит `tool_pipeline.assemble_tool_run` + `tool_ingest_store.ingest_tool_run` в один вызов (зеркало `mission_runner.run_mission` поверх `audit_runner`+persist); `project` дефолтится из миссии; → `{result, ingest:{status,written,findings,assets}}`; blocked/skipped проходят насквозь как no-op. `tool_scan_id(tool, *, now=)`/`parse_tool_scan_id(scan_id)` — единый SoT синтетического scan_id `tool-<tool>-<unix_ts>` (используют GUI/web/timeline). Surfaces: GUI вкладка Missions «Run tool» (evidence-driven, gate по ROE) + web `POST /missions/{id}/tools/run` + timeline derive-on-read `tool_run` (через `timeline._derive_tool_runs`) + CSV `report_export.tool_runs_csv` (Timeline tab + `GET /tool-runs.csv`).
- `core/retest_run.py` + `core/retest_run_store.py` + `core/retest_runner.py` (+`schemas/asa_retest_run.schema.json`) — Retest Run lifecycle: персистентный снимок исходов ретеста engagement'а (fixed/open/accepted/missing) как first-class «прогон» (ранее только derive-on-read view `engagement_retest`). R1 чистый контракт (create/normalize/validate/advance/to_json + render_json/markdown; lifecycle pending→completed|failed; summary всегда деривируется из результатов). R2 `RetestRunStore(SQLiteStore)` single-table events-less (зеркало MissionStore) + участие в `project_io` bundle (`retest_runs.json`, аддитивно). R3 `run_retest` замораживает live `engagement_retest.build_retest` в снимок и персистит (зеркало `mission_runner`; исходы не дублируются; engagement не мутируется — связь на `engagement_id` прогона). Surfaces: web `POST /engagements/{id}/retest/run`, `GET /engagements/{id}/retest-runs`, `GET /retest-runs/{id}[/report.md]`, `/retest-runs.csv`; GUI «Run retest» + история прогонов на вкладке Engagements; timeline `retest_run` события + `report_export.retest_runs_csv`; demo_seed снимок. Общая markdown-таблица retest-строк вынесена в `engagement_retest.retest_rows_markdown` (dedup).

**Последние важные изменения на 2026-07-02 (DEV_PLAN остаток WS6 — update-check + user-facing errors + observability):**
- Закрыт «остаток WS6» (3 полировочных пункта надёжности; все opt-in/аддитивные, best-effort поведение не менялось). **A) Opt-in update-check** — `core/update_check.py` (new, чистый/offline, transport инъектируется): `check_for_update(*, current=APP_VERSION, endpoint=settings, fetch=_fetch)` — одиночный HTTPS GET на настраиваемый endpoint `{"version","url"}`, сравнение с `APP_VERSION` через `parse_version` (numeric-tuple); статусы disabled/update_available/up_to_date/error; НИЧЕГО не качается/ставится, никогда не райзит; `_fetch` HTTPS-only (не-https → ValueError); `update_line` pure. `config.update_check {enabled:False, endpoint:''}` (off by default). `gui/first_run.health_report_text(health, update=None)` добавляет строку обновления только если проверка бежала (дефолт-выкл байт-в-байт как раньше); `show_health_dialog` зовёт best-effort. **B) Понятные GUI-ошибки** — `gui/task_runner.friendly_error_text(raw)` (pure, Qt-free): оборачивает причину + указывает на локальный crash-отчёт, берёт только первую строку; `_run_async` error-path использует её (центральная точка всех async-операций). Сырые traceback в диалоги и раньше не попадали (WS2: воркеры шлют `str(e)`, traceback → crash-репорт) — дожата формулировка. **C) Наблюдаемость swallow'ов** — `core/crash_reporter.note_swallowed(context, exc)` (breadcrumb-обёртка, redacted, never-raises) применён к кураторскому набору тихих `except: pass` (не hot-path): `collection_runner._finish_operation`/`_persist_error_report`, `project.record_scan` history-snapshot; остальные `except: pass` (own-guards/config-fallbacks/cache/validator) осознанно тихие, `note_swallowed` — стандарт для будущих. «Единый источник версии» уже = `config.APP_VERSION`. Тесты: `test_update_check.py` (9), `test_task_runner_errors.py` (3), `test_crash_reporter.py` (+2). Проверено: ruff clean, self-check 29 вкладок, полный pytest зелёный (2577 → 2591, +14). Локальные коммиты, без push. **Итог: DEV_PLAN WS1–WS6 закрыты.**

**Последние важные изменения на 2026-07-02 (DEV_PLAN WS5 инкремент 2 — современные secret-паттерны):**
- Кандидат #2 WS5 (нативный секрет-сканер без внешнего SecretFinder/GPL): к 28 правилам добавлены 4 современных vendor-ключа (оригинальные паттерны по публичной форме префикса; precision-first): **Anthropic** `\bsk-ant-[A-Za-z0-9_-]{20,}\b`, **OpenAI** `\bsk-[A-Za-z0-9_-]{20,}\b`, **GitLab PAT** `\bglpat-[A-Za-z0-9_-]{20,}\b`, **Hugging Face** `\bhf_[A-Za-z0-9]{34,}\b`. В `RULES` Anthropic ПЕРЕД OpenAI (scanner дедупит по matched-value → более специфичный `sk-ant-` побеждает); OpenAI требует дефис, не ловит Stripe `sk_live_` (подчёркивание). Новые типы не в `_GENERIC_SECRET_TYPES` → `is_high_value_secret` даёт high-value автоматически (тир не менялся). `core/secret_validator._VALIDATORS` +4 `_re_exact` (VALID при точной форме, INVALID при коротком). Файлы: `core/secret_scanner.py`, `core/secret_validator.py`, тесты `test_secret_scanner.py` (+3: детект; Anthropic-wins; Stripe-underscore не матчится), `test_secret_validator.py` (+1). Проверено: ruff clean, self-check 29 вкладок, полный pytest зелёный (2573 → 2577, +4). Локальные коммиты, без push. Дальше: остаток WS6.

**Последние важные изменения на 2026-07-02 (DEV_PLAN WS5 инкремент 1 — нативные пассивные источники субдоменов):**
- WS5 = «долгий трек» снятия зависимости от внешних бинарников. Аудит трёх кандидатов плана: **#2 секрет-сканер** уже несёт 28 правил (JWT/AWS/Google/Stripe×4/GitHub+PAT/Slack/Twilio/Mailgun/SendGrid/npm/PayPal/Square/Basic/Bearer/PrivateKey/Generic — плановые vendor/JWT/Basic покрыты); **#3 краулер эндпоинтов** уже нативный (content_capture/site_map/scrapy_crawler → katana опция); **#1 пассивные субдомены** — расширены (наибольшая польза). Инкремент 1: `core/subdomain_scanner.py` — добавлены 2 keyless источника по существующему паттерну (URL-константа + `_fetch_X` classmethod через `urlopen_retry`/`_names_in_domain` + `_passive_X` cache-обёртка (1ч TTL, failure→[]) + фаза в `scan()`): **Cert Spotter** (`api.certspotter.com` issuances → flatten `dns_names` SAN, CT-источник рядом с crt.sh; метка 'certspotter') и **urlscan.io** (search API → page/task `domain`, пассивный URL-corpus; метка 'urlscan'). Keyless-источников 4 → 6 (crt.sh/HackerTarget/AlienVault/Anubis/Cert Spotter/urlscan) → полезное перечисление «из коробки», subfinder/amass остаются опцией. Оба кэшируются + мягко деградируют. Оригинальный код по описанию API (чужие исходники не транслировались). Тесты: `test_subdomain_cache.py` — `_no_dns` глушит новые источники (офлайн); +3 (record+cache с source-метками; парсинг certspotter dns_names + фильтр; парсинг urlscan page/task + фильтр). Проверено: ruff clean, self-check 29 вкладок, полный pytest зелёный (2570 → 2573, +3). Локальные коммиты, без push. Дальше: возможные доп. инкременты WS5 (современные secret-паттерны; ещё keyless-источники), затем остаток WS6.

**Последние важные изменения на 2026-07-02 (DEV_PLAN WS4 — алертинг поверх мониторинга):**
- Аудит (урок WS3 — аудитить core перед «новым») показал: почти весь WS4 уже реализован. Generic webhook — уже есть (`core/alerts.WebhookChannel`, EPIC 16 F3; Slack incoming webhook читает `text` → работал). diff→alert проводка ПОЛНАЯ: `core/monitor.run_project` дёргает `alerts.notify` (диф) + finding-based каналы (sla/secret/finding/kev); проверено, что `scan_diff.diff_events` эмитит КАЖДЫЙ тип из `alerts.ALERT_TYPES` (new_subdomain/takeover/new_attack_path/attack_path_escalated/dns_email_auth_weakened/attack_surface·exposure·criticality_drift/secret/cert/graphql/sourcemap/cookie/dependency/header) — обрывов нет. Дедуп: диф only-new + finding-based one-shot маркеры (reopen-resetting). Секреты не логируются (журнал доставки пишет имена каналов+статус+маскированные заголовки, не токены/URL). Surfaces были: web `/alerts` статус + `/alerts/test` POST, GUI вкладка «Уведомления», CLI `monitor_cli` через `format_event`. Единственный реальный пробел — выделенный **Slack**-канал (item #1): добавлен `SlackChannel(webhook_url)` (name='slack', POSTит `{"text":"*subj*\nbody"}`, успех=200; тот же channel-паттерн, что Telegram/Discord/Webhook — не дублирование) + слот `slack.webhook_url` в `build_channels` + группа «Slack» в `gui/dialogs._build_alerts_tab`/`_collect_alerts_config` + docstring config shape. Тесты: `test_alerts.py` (+3), `test_alerts_gui.py` (+1). Проверено: ruff clean, self-check 29 вкладок, полный pytest зелёный (2566 → 2570, +4). Локальные коммиты, без push. Дальше по DEV_PLAN: WS5 (нативные реализации), затем остаток WS6.

**Последние важные изменения на 2026-07-02 (DEV_PLAN WS3 — конкурентный движок сканирования):**
- По `DEV_PLAN_CLAUDE_CODE.md` WS3 независимые фазы Full Collection теперь исполняются конкурентно, БЕЗ изменения результата. Транспорт — `ThreadPoolExecutor` (не asyncio): весь код синхронный/потоковый (SubdomainScanner уже на пуле, rate_limiter/http_retry блокирующие, GUI гоняет раннер в QThread), поэтому существующие движки планируются без переписывания. Новый `core/scan_engine.py` (чистый/offline): DAG-планировщик — `Task(name, fn, deps)` + `run_dag(tasks, *, max_concurrency, cancel_event, on_error)`; независимые задачи идут параллельно (пул, ограничен `max_concurrency`), зависимая стартует лишь когда все её deps завершены; `max_concurrency<=1` → точный старый последовательный топо-порядок на вызывающем потоке; исключение задачи перехватывается (её зависимые всё равно бегут; результат = исключение/`on_error`), cancel останавливает планирование новых; валидация графа (cycle/unknown/dup → `ValueError`). `core/collection_runner.py`: `_run_impl` переведён на DAG — `_build_phase_tasks` собирает фазы, НЕ мутирующие общие vuln-находки (always-on recon/api/capture/clone/cookies/vulns + opt-in subdomains/certificate/openapi/historical/emails/employees/ct/asn_intel/katana/screenshot; каждая пишет ТОЛЬКО свой `report['phases'][key]`, GIL-атомарно; deps vulns←recon,cookies / clone←capture / asn_intel←recon / screenshot←capture), а фазы, мутирующие общий список находок, гоняются СЕРИЙНО в точном историческом порядке (`_run_active_phases`: secret-fold→security→takeover-fold→dns→osv→bbot→documents→iac) → порядок фолдинга детерминирован; методы `_phase_*` и их фолд-контракты/юнит-тесты НЕ тронуты. `_normalize_report_order` переупорядочивает `report['phases']` + `skipped_active_phases` в фиксированную каноническую последовательность → конкурентный прогон байт-в-байт == последовательный. Неожиданное исключение фазы ре-райзится в каноническом порядке (обёртка `run()` всё так же метит операцию failed + читаемый частичный report). `core/config.py`: `scan_concurrency` default 4 (1 = классический последовательный; per-host rate-limit из scope по-прежнему пейсит сетевые всплески). Решения (locked): ThreadPoolExecutor; on-by-default модест 4; scope = только phase-level DAG в collection_runner (recon_engine внутри пока последовательный — отдельный будущий шаг); фазы сериализуются через `_run_active_phases`, не переписываются (нулевой test-churn фаз + детерминизм). Тесты: `test_scan_engine.py` (14), `test_collection_runner.py` (+2: seq(1)↔concurrent(4) равенство свёрнутых находок/summary/порядка + резолюция `scan_concurrency`). Проверено: ruff clean, self-check 29 вкладок, полный pytest зелёный (2550 → 2566, +16). Локальные коммиты, без push. Дальше по DEV_PLAN: WS4 (алертинг), WS5 (нативные реализации), затем остаток WS6.

**Последние важные изменения на 2026-07-02 (DEV_PLAN WS6 quick items — rate-limiting web-консоли):**
- По `DEV_PLAN_CLAUDE_CODE.md` WS6 (быстрые пункты) закрыт главный пробел надёжности web-консоли: мутирующие эндпоинты не имели rate-limit. Новый серверный `utils/rate_limiter.RequestThrottle` (ОТДЕЛЬНЫЙ класс рядом с client-side `RateLimiter` — другая семантика: non-blocking per-key fixed-window `allow(key)->bool`, а не blocking-spacing; thread-safe; injectable clock; `max<=0`/`window<=0` → disabled; ленивый prune stale-ключей, память ограничена; `.enabled`/`.limit`). `remote/web_app.py`: app-wide зависимость `rate_limit(request)` рядом с `require_token` — throttl'ит только мутирующие методы (POST/PUT/PATCH/DELETE; read-запросы никогда), ключ = токен (`_request_token`) иначе client IP, превышение → HTTP 429; `_THROTTLE`/`_make_throttle()` из настроек, ребилдится в `start_server` (+печать `rate: N/min`). `core/config.py`: `web_console.rate_limit_per_min` (default 60, 0=off) + доккоммент: LAN-bind без TLS → только доверенная сеть; CSRF не проблема (auth = Bearer/`?token=`, не ambient cookie, поэтому cross-site запрос не подхватит креды). `tests/conftest.py`: autouse `_reset_web_throttle` даёт каждому тесту свежий throttle (module-level `_THROTTLE` шарится сессией → иначе накопление POST под ключом TestClient могло дать ложный 429; действует только если web_app импортирован). «Единый источник версии приложения» (тоже quick item) уже удовлетворён существующим `config.APP_VERSION` — изменений не потребовал. Тесты: `test_rate_limiter.py` (+4 RequestThrottle: disabled/limit-per-key/per-key-независимость/window-reset), `test_web_auth.py` (+2: 429 при burst POST, disabled пропускает всё). Проверено: ruff clean, self-check 29 вкладок, полный pytest зелёный (2544 → 2550). Локальные коммиты, без push. Остаток WS6 (update-check opt-in, user-facing error messages, аудит проглатываемых `except`) отложен к «остатку WS6» после WS3–WS5.

**Последние важные изменения на 2026-07-02 (DEV_PLAN WS2 — crash-репортер и наблюдаемость):**
- По `DEV_PLAN_CLAUDE_CODE.md` WS2 добавлен local-first crash-репортер. Новый `core/crash_reporter.py`: `install()` (ставит `sys.excepthook`+`threading.excepthook`+`faulthandler.enable(file=)`+`qInstallMessageHandler`; идемпотентно; хуки НЕ глотают — chain к оригиналу), `breadcrumb()`/`breadcrumbs()` (кольцевой `deque(maxlen=50)`), `_redact()` (вырезает authorization/cookie/token/api_key/password/bearer/JWT + URL-query значения перед записью/показом), `_write_report(kind, detail)` (redacted JSON: time/app_version/os/python/qt/detail/breadcrumbs → `PathManager.get_crash_dir()`), `report_exception()` (для уже-пойманных исключений воркеров), `pending_crashes()`/`mark_seen()` (unseen-отчёты через `.seen`-маркер), `send_report()` (opt-in, HTTPS-only). `core/paths.py`: `get_crash_dir()` (frozen-aware, `<data_root>/data/crashes`). `core/config.py`: `crash_reporting {enabled:True, endpoint:''}` (ничего не шлётся автоматически). `main.py`: `crash_reporter.install()` ДО `QApplication` + breadcrumb «app started» + startup-диалог. `gui/crash_dialog.py` (new): тонкий «Прошлый сеанс завершился аварийно» (Посмотреть/Копировать/Отправить[если endpoint]/Пропустить → `mark_seen`). `gui/workers.py`: `report_exception(e, kind='worker')` во ВСЕХ 7 воркерах (traceback фонового потока больше не теряется; error-сигнал сохранён — контракт цел). Breadcrumbs: смена вкладки (`tab_history._on_tab_changed`), старт Full Collection (`tab_collection._run_collection`). Единый источник версии — существующий `config.APP_VERSION` (нового не заводили). `tests/test_crash_reporter.py` (12): redaction (headers/token/JWT/URL; plain-текст цел), report-JSON со всеми полями, breadcrumbs bounded+redacted, pending/mark_seen, excepthook+threading.excepthook пишут отчёт И зовут оригинал, send-guards (нет endpoint / не-https). Проверено: ruff clean, self-check 29 вкладок, faulthandler-файл создаётся, полный pytest зелёный (2532 → 2544). Локальные коммиты, без push.

**Последние важные изменения на 2026-07-02 (DEV_PLAN WS1 — убрано скачивание видео/фото):**
- По `DEV_PLAN_CLAUDE_CODE.md` WS1 продукт сужен до security/recon + оффлайн-клон сайта: удалено медиа-скачивание (видео/изображения, зависимости yt-dlp/ffmpeg). Удалены `utils/video_processor.py`, `utils/image_processor.py`, `gui/tab_media.py` (вкладки Video Downloader + Image Extractor → регистрация в `plugin_manager`/`main_window`), web-джобы images/video (`_run_images`/`_run_video` + JOBS-записи + импорты + `s.images` в dashboard JS), фаза Images в `collection_runner` (`_phase_images` + вызов + docstring + карта отчёта «Images (Media)» + doc-intel roots; перенумерация этапов 7→6: recon..vulns), фичи `features.has_ytdlp`/`has_ffmpeg` + записи в `OPTIONAL_FEATURES`, `launcher` install-maps (yt-dlp/ffmpeg), dead `window_helpers._save_video_log`, комментарий в `core/__init__`, yt-dlp/ffmpeg в docstring `subprocess_utils`, закомментированные yt-dlp/ffmpeg строки в `requirements.txt`. Оффлайн-клонирование (`frontend_cloner`/`content_capture`/`site_map`, вкладки Clone/Capture) сохранено. Доки (README/PROJECT_REPORT/CLAUDE/AGENTS/PROJECT_STATUS) вычищены от медиа-упоминаний. Тесты: удалён `test_media_processors.py`, `test_web_clone_video.py`→`test_web_clone.py` (video-тест убран, `_strip_heavy`-тест обобщён), video-тесты убраны из `test_optional_feature_gating`, `_phase_images` убран из `test_collection_runner`/`test_contracts`, `has_ytdlp`/`has_ffmpeg` из `test_features`, `ffmpeg`→`nuclei` в `test_first_run`. **Вкладок 31 → 29.** Проверено: ruff clean, self-check 29 вкладок, полный pytest зелёный (2549 → 2532; junit подтверждает 2532 passed/0 fail). Локальные коммиты, без push.

**Последние важные изменения на 2026-07-01 (Retest Run lifecycle — R1–R5):**
- Ретест engagement'а стал first-class персистентным «прогоном» (снимок исходов на момент времени) — ранее только derive-on-read view. Слои как в Mission Center: чистый контракт → стор → runner → тонкие surfaces, БЕЗ второго findings-стора и без новых атак-возможностей. **R1** `core/retest_run.py` (+`schemas/asa_retest_run.schema.json`+alias): create/normalize/validate/advance/to_json + render_json/markdown; lifecycle pending→completed|failed; summary всегда деривируется (инвариант). **R2** `core/retest_run_store.py` — `RetestRunStore(SQLiteStore)` single-table events-less (зеркало MissionStore) + `project_io` bundle `retest_runs.json` (аддитивно, FORMAT_VERSION=1; старый bundle → 0) + conftest-изоляция. **R3** `core/retest_runner.run_retest` — замораживает `engagement_retest.build_retest` в снимок, персистит, pending→completed (или failed с пробросом); исходы переиспользуются, engagement не мутируется (связь на `engagement_id`). **R4** surfaces: web `POST /engagements/{id}/retest/run`, `GET /engagements/{id}/retest-runs`, `GET /retest-runs/{id}`, `GET /retest-runs/{id}/report.md`; GUI «Run retest» + история на вкладке Engagements; общая markdown-таблица вынесена в `engagement_retest.retest_rows_markdown`. **R5** derive-on-read: timeline `retest_run` события (section engagements) + `report_export.retest_runs_csv` + web `/retest-runs.csv` + Timeline «Export retest runs» + demo_seed снимок. Коммиты b24ddb06/da0f1ac/94463b7/f3ec8ff/3c35c93c. Проверено: ruff clean, self-check 31 вкладка, полный pytest зелёный (рост 2496 → 2549). Локальные коммиты, без push.

**Ранее на 2026-07-01 (Review/dedup — общий рендер таблицы находок):**
- Ревью-проход по коду отчётов. Устранена дупликация `mission_report`↔`engagement_report`: идентичные рендеры таблицы находок (`finding_refs`/`finding_md_table` + HTML-`table()`) вынесены в новый чистый `core/finding_render.py` (`finding_refs`/`finding_md_table`/`finding_html_table`; presentation-only, offline, escaped HTML), оба report-модуля теперь импортируют его. Рендер-вывод не изменился (обе report-сюиты зелёные). Файлы: `core/finding_render.py` (new), `core/mission_report.py`, `core/engagement_report.py`, `tests/test_finding_render.py`. Тем же проходом вынесен и общий HTML-конверт отчётов (`html_open`/`html_close` — doctype/head/style + `markdown-sha`-футер), продублированный в 5 рендерерах (`audit_report` ×2, `mission_report`, `engagement_report`, `tool_report`); вывод байт-в-байт тот же (хелперы возвращают ровно вынесенные литералы). Рост 2489 → 2496. Проверено: ruff clean, полный pytest зелёный. (commits a83eaefb, 62b5419c)

**Ранее на 2026-07-01 (Engagement surfaces — S1–S4):**
- Поверх бэкенд-слоя (F1–F4) добавлены ВСЕ surfaces (по полной автономии пользователя). Тонкие, derive-on-read/store-aware, без второго стора и без новых атак-возможностей. **S1** timeline (`2ed2a75a`): `timeline.build_events(engagements=)` → `engagement_created` + статус-событие (section `engagements`); `build_timeline` грузит `EngagementStore().list_engagements(slug)` best-effort. **S2** web (`6301f6f2`): `GET /engagements`, `GET /engagements/{id}`, `POST /engagements` (create, client-safe validated), `POST /engagements/{id}/advance`, `POST /engagements/{id}/link` (mission/audit_run/finding, checked), `POST .../links/prune`, `GET /engagements/{id}/report[.md]`. **S3** demo_seed (`919d1ad7`): `_seed_engagement` — авторизованная engagement mid-flight `reporting`, linked mission+run+finding. **S4** GUI (`b301cc24`): `gui/tab_engagement.EngagementsTabMixin` (зеркало `tab_missions`: project→table→create→advance→link(store-combos,checked)→prune→report JSON/MD/HTML, всё через `_run_async`); зарегистрирован в `plugin_manager.BUILTIN_TABS`+`main_window`, lazy-load в `tab_history`; `EngagementsHost` в gui_test_helpers. **Вкладок теперь 31.** Проверено: ruff clean, целевые+смежные (incl MainWindow-based) зелёные, полный pytest зелёный (рост 2453 → 2472). Локальные коммиты, без push. Engagement-эпик (F1–F4 + S1–S4) закрыт. Follow-ups (commit 2825e836) ЗАКРЫТЫ: retest (`core/engagement_retest.py` — перепроверка статуса связанных находок fixed/open/accepted/missing + web `/engagements/{id}/retest` + GUI export); overview+CSV (`core/engagement_overview.py` + `report_export.engagements_csv` + web `/engagements/overview` & `/engagements.csv` + GUI export); scope/ROE inheritance (`engagement.mission_roe_from_engagement`). Engagement-эпик ПОЛНОСТЬЮ закрыт (F1–F4 + S1–S4 + follow-ups) + Overview-карточка Engagements (38525e3b) + создание миссии под engagement с наследованием ROE (`core/engagement_missions.py` + web POST /engagements/{id}/missions + GUI; commit d8526f43, даёт потребителя E3-helper'у); рост 2472 → 2489.

**Ранее на 2026-07-01 (Engagement & ROE Foundation — backend F1–F4):**
- Стартовал следующий большой этап — Authorized/Client-Safe Pentest Workbench: верхнеуровневая сущность **Pentest Engagement** (клиент/проект/scope/ROE/авторизация ↔ missions/audit_runs/findings). Дуга: Engagement → Authorization/ROE → Missions → Audit Runs → Evidence → Findings → Report → Retest → Close. **Только бэкенд**, без GUI/Web (surfaces отложены до отдельного go). Никаких атакующих возможностей не добавлялось (нет brute force/stealth/exploit-automation/credential-attacks/auth-bypass/persistence/destructive).
- **F1** `core/engagement.py` (commit `44b52784`) — чистый/offline/детерминированный контракт (зеркало `pentest_mission`): `create/normalize/validate/advance_engagement_status` + `link_mission/link_audit_run/link_finding` + `engagement_to_json`; lifecycle draft→authorized→active→reporting⇄retest→closed→archived (archived терминальный). Engagement РАЗДЕЛЯЕТ `scope`/`roe`/`authorization` (в отличие от миссии); reuse `audit_scope.validate_roe` (active/passive) + `audit_schema`; id `eng-`+sha1(client|project)[:16]; →authorized требует accepted authorization; →closed требует ≥1 линка. `schemas/asa_engagement.schema.json`+alias. tests/test_engagement.py (22).
- **F2** `core/engagement_store.py` (commit `42a175f4`) — `EngagementStore(SQLiteStore)` single-table (no events), CRUD+idempotent+schema-validated export; `project_io` bundle += `engagements.json` (аддитивно, FORMAT_VERSION=1); conftest `_isolate_engagements_db`.
- **F3** `core/engagement_links.py` (commit `c32d6702`) — store-aware `link_*_checked` + `resolve_links` (present/stale по mission/run/finding) + `prune_stale_links`; чистый `core.engagement` не тронут.
- **F4** `core/engagement_report.py` (commit `0e8da25b`) — evidence-first deliverable: `build_engagement_report` (envelope + linked missions/runs(reuse `audit_report`)/findings, stale-линки помечаются) + чистые `render_json/markdown/html`. View, не стор.
- Проверено: ruff clean, целевые сьюты зелёные, полный pytest зелёный (рост 2409 → 2453). Локальные коммиты, без push. **Следующее (только по явному go):** GUI Engagement tab / web read-parity / timeline события / demo_seed / retest workflow.

**Ранее на 2026-07-01 (GUI pagination: Dashboard/Intelligence/Accuracy):**
- Применён готовый `TablePaginator` к оставшимся высокообъёмным таблицам (паттерн как Findings/Assets/Timeline): **Dashboard endpoints** (снят старый обрез `[:200]` → пагинируется ПОЛНЫЙ список уникальных эндпоинтов; selection/detail через `record_at`), **Intelligence** (priority-ranked findings), **Accuracy** (per-entity rows) — render-row callback + `paginator.set_rows` + `record_at`; полный список хранится для selection + CSV. **Subdomain** ОСОЗНАННО не тронут: streaming-таблица (`row_found`/`row_updated` добавляют+обновляют строки in-place во время живого скана, трекинг `_subdomain_rows`) — статичный list-paginator не подходит; объём ограничен сканом. Остальные табличные вкладки (exposure/criticality/technology-risk/osint/history/remediation/security/attack-paths) — bounded-small, не пагинируются by design. Файлы: `gui/tab_dashboard.py`, `gui/tab_intelligence.py`, `gui/tab_accuracy.py`, тесты `test_dashboard_detail.py`/`test_intelligence_tab.py`/`test_accuracy_tab.py`, `ROADMAP_ASM_2.0.md`. Коммит `3772364e`. Проверено: ruff clean, целевые+смежные зелёные, полный pytest зелёный (рост 2406 → 2409). Остаётся (отложено): i18n.

**Ранее на 2026-07-01 (e2e / GUI-interaction tests):**
- GUI-набор тестировал хендлеры изолированно (`_run_async` застаблен в no-op) — реальная цепочка клик→handler→worker→callback→store/UI не покрывалась. Добавлен детерминированный headless e2e-слой. Harness (`tests/gui_test_helpers.py`): `_SyncRunMixin` переопределяет `_run_async(work, on_done)` — гоняет воркер INLINE и зовёт callback (контракт `TaskRunnerMixin`, синхронно, без QThread → детерминизм) + переиспользуемые `FindingsE2EHost`/`MissionsE2EHost`. `tests/test_gui_e2e.py`: настоящие активации `QAbstractButton.click()` (уважает enabled-state, бьёт по слоту) над conftest-изолированными сторами — Findings select-row → assign/comment/change-status кликом (ассерт в сторе) + disabled-without-selection wiring; Missions Run-tool кликом (header_audit→finding ingested) + «Из скана» fill-evidence кликом (монкипатч `core.config.load_settings` output_dir→tmp, скан с субдоменами → поле авто-заполнено). Решение (locked): синхронный `_run_async`; `.click()`-активации (надёжно headless); репрезентативный охват (Findings+Missions), остальные вкладки → follow-up на том же harness. Паттерн будущего GUI e2e: subclass host + `_SyncRunMixin` + `.click()`. Существующие хосты/тесты не тронуты. Файлы: `tests/gui_test_helpers.py`, `tests/test_gui_e2e.py`, `ROADMAP_ASM_2.0.md`. Коммит `3eb18aa6`. Проверено: ruff clean, целевые+смежные GUI-сьюты зелёные, полный pytest зелёный (рост 2400 → 2406). Остаются (отложены): i18n, пагинация остальных таблиц.

**Ранее на 2026-06-30 (Tool-Evidence: header + cookie extractors):**
- Расширен `core/tool_evidence.EXTRACTORS` двумя ВЕРИФИЦИРОВАННЫМИ экстракторами (формы отчёта сверены в коде): `header_audit` → `{url, headers}` из `recon.data.security_headers` (гейт по наличию ключа = recon фетчил; `headers_check` флагует недостающие); `cookie_audit` → `{url, cookies}` из cookies-фазы (`CookieAuditor.audit` строки несут name/secure/httponly = ровно shape `cookie_flags_check`). `dependency_auditor` СОЗНАТЕЛЬНО НЕ подключён (решение пользователя): recon хранит только РЕЗУЛЬТАТ аудита (`recon.data.dependencies`), не сырые scripts/html, которые парсер ре-аудитит; находки уже в FindingsStore через vuln-фазу → tool-run избыточен, персист сырого HTML = scope-creep. Реестр: source_map_finder/safe_active_prober/header_audit/cookie_audit (аддитивно). Surface-провязка (GUI «Из скана»/web from_scan) работает для них БЕЗ изменений (generic над реестром). Верифицированные формы: `recon.data` = server_headers/security_headers/technologies/dependencies/cms (НЕ raw scripts/html); `cookies.data.cookies`. Файлы: `core/tool_evidence.py`, `tests/test_tool_evidence.py`, `ROADMAP_ASM_2.0.md`. Коммит `93f0fb5f`. Проверено: ruff clean, целевой+смежные зелёные, полный pytest зелёный (рост 2394 → 2400). Остаются (отложены): i18n, e2e/GUI-тесты, пагинация остальных таблиц.

**Ранее на 2026-06-30 (Tool-Evidence Surface Wiring):**
- Follow-up к мосту: tool-runs заполняют evidence из скана прямо из «Run tool». `core/tool_evidence.evidence_from_project_scan(project, tool, *, base=None, scan_id=None)` — ТОНКИЙ I/O-loader (зеркало `timeline.build_timeline`): резолвит отчёт скана проекта (последний/заданный) через `ProjectStore`/`load_scan_report` → делегирует чистому `evidence_from_report`; `{}` при отсутствии, не падает; base дефолт = settings output_dir. GUI Missions «Run tool»: кнопка «Из скана» (`btn_mission_tool_evidence`) — off-thread `_do_fill_tool_evidence` → `_on_tool_evidence_filled` заполняет `mission_tool_evidence` pretty-JSON'ом из последнего скана проекта миссии (оператор проверяет/правит → Run; ручной поток не тронут). Web `POST /missions/{id}/tools/run` += `from_scan:bool` (+опц. `scan_id`): при `from_scan` и пустом evidence — тянется из скана проекта (`base=_REPORT_BASE`). Решение (locked): GUI fill-button (прозрачно), не auto-чекбокс; loader тонкий; run-flow + инвариант «tool не исполняется» не тронуты; нового пути данных нет. Файлы: `core/tool_evidence.py`, `gui/tab_missions.py`, `remote/web_app.py`, `tests/test_tool_evidence.py`, `tests/test_missions_tab.py`, `tests/test_web_missions.py`, `ROADMAP_ASM_2.0.md`. Коммит `e64618e9`. Проверено: ruff clean, целевые+смежные зелёные (incl from_scan→completed+assets), полный pytest зелёный (рост 2389 → 2394). Остаются (отложены): i18n, e2e/GUI-тесты, пагинация остальных таблиц, больше tool-evidence экстракторов.

**Ранее на 2026-06-30 (Captured-Scan → Tool-Evidence Bridge):**
- Tool-runs принимали evidence вручную (paste JSON) — теперь их можно гонять из данных, уже захваченных сканом. `core/tool_evidence.py` (new): `evidence_from_report(report, tool) -> dict` мапит загруженный `report.json` в ТОЧНУЮ evidence-форму, которую потребляет парсер `core.tool_parsers` для tool'а (готово к `tool_pipeline.assemble_tool_run`/`parse_tool_output`); `{}` если нет экстрактора/данных; не падает. `available_tools(report)` — bridgeable tool'ы. АДДИТИВНЫЙ реестр `EXTRACTORS` (зеркало `tool_parsers.PARSERS`); верифицированные (охват по решению пользователя): `source_map_finder` (из `recon.data.source_maps[].url`) + `safe_active_prober` (из `subdomains.data.results[].subdomain` + `summary.takeover_candidates[].subdomain`, dedup); прочие → manual, добавляются тривиально. ЧИСТЫЙ dict→dict над уже-загруженным отчётом (caller — `project.load_scan_report`); без I/O/сети/стора/запуска tool'а; reuse форм отчёта `collection_runner` (нового пути данных нет). Решение (locked): mapper + аддитивный реестр; только верифицированные формы; surface-провязка (Missions/web auto-evidence) — аддитивный follow-up. Файлы: `core/tool_evidence.py`, `tests/test_tool_evidence.py` (incl round-trip через `parse_tool_output`), `ROADMAP_ASM_2.0.md`. Коммит `7ea4982c`. Проверено: ruff clean, целевой+смежные зелёные, полный pytest зелёный (рост 2383 → 2389). Остаются (отложены): i18n, e2e/GUI-тесты, пагинация остальных таблиц, surface-провязка tool-evidence + больше экстракторов.

**Ранее на 2026-06-30 (Finding Assignment & Comments Triage):**
- Закрыт последний named-пробел из gap-анализа: DefectDojo-триаж поверх lifecycle/SLA. СОБЫТИЙНО над `finding_events` (фича `REMEDIATION` — точный шаблон): БЕЗ второго стора, БЕЗ миграции. `core/findings_store.py`: `EVENT_TYPES += ASSIGNED, COMMENT`; `assign(fid,assignee)`/`get_assignee(fid)` (последний ASSIGNED побеждает, ''=снять)/`assignees(project)` (latest-per-finding карта для списка); `add_comment(fid,text,author='')`/`comments(fid)` (append-only COMMENT, note=json {author,text}). Валидируют существование (KeyError), пишут через `_log_event`; история в `finding_events`, переносится project_io. GUI Findings tab: ряд «Триаж» (исполнитель+Назначить, комментарий+Добавить) через `_run_async`; detail показывает assignee + ленту (сырые COMMENT скрыты из generic-истории), поле префиллится. Web: `POST /findings/{id}/assign` `{assignee}`, `POST /findings/{id}/comment` `{text,author?}`, `GET /findings/{id}/triage`; 404 unknown / 400 пустой — зеркало `/status`. Решение (locked): событийно (без стора/миграции); detail+web без новой колонки таблицы (выбор пользователя). Файлы: `core/findings_store.py`, `gui/tab_findings.py`, `remote/web_app.py`, `tests/test_findings_store.py`, `tests/test_web_findings.py`, `tests/test_findings_tab.py`, `ROADMAP_ASM_2.0.md`. Коммит `05e8f72f`. Проверено: ruff clean, целевые+смежные зелёные, полный pytest зелёный (рост 2375 → 2383). Остаются (отложены): i18n, e2e/GUI-тесты, мост captured-scan→tool evidence, пагинация остальных таблиц.

**Ранее на 2026-06-30 (Interactive Attack-Path Graph):**
- ВАЖНО (урок): пользователь попросил «3 новых модуля под ключ» (cloud_classifier, движок attack paths, GUI attack-surface), но ВСЕ ТРИ уже существовали — `core/cloud_classifier.py` (`classify_cloud(provider,asn_name,asn,technologies,cname)`, уже принимает CNAME+CDN-tech), `intelligence.build_attack_paths`+`core/correlation.py` (entry/pivot/target/score/vector/band, кластеры по IP/подсети/ASN, blast radius), `gui/tab_attack_paths.py` (таблица+detail+async). Отказ дублировать (§5.2/5.3/6/10): аудит → доказательная карта → по решению пользователя добавлена ТОЛЬКО недостающая часть. `gui/attack_graph_view.AttackGraphView(QGraphicsView)` (new): детерминированный ПОСЛОЙНЫЙ граф Вход→Транзит→Цель в `QGraphicsScene` (stdlib Qt, без graph-lib); entry по severity, критичная цель подсвечена, fan-out целей капается `MAX_TARGETS=12` + узел «+N more»; клик → `node_clicked(node_id, role)`; чистая презентация поверх загруженной записи пути, headless-safe, не падает. Вшит в `tab_attack_paths` ПОД таблицей: выбор пути → render, клик-узел → detail, перезагрузка → clear; переиспользует `load_attack_paths`+`_run_async` (нового пути данных нет). Решение (locked): reuse существующих движков, строить только граф; послойная (не force-directed) раскладка под 3-стадийную цепочку; клик кормит существующую detail-панель. Файлы: `gui/attack_graph_view.py`, `gui/tab_attack_paths.py`, `tests/test_attack_graph_view.py`, `tests/test_attack_paths_tab.py`, `ROADMAP_ASM_2.0.md`. Коммит `651c214f`. Проверено: ruff clean, целевые+смежные зелёные, полный pytest зелёный (рост 2368 → 2375). УРОК: всегда аудитить `core/` перед «новыми» модулями — ASM attack-path/cloud/correlation поверхность уже во многом построена.

**Ранее на 2026-06-30 (GUI Table Pagination):**
- Закрыт пробел №3 из найденных: тяжёлые таблицы грузили все строки в виджет разом → фриз UI на крупном портфеле/истории. Решено **UI-windowing** (тормозит именно заполнение `QTableWidget`, не хранение строк; слой данных не тронут). `gui/ui_components.TablePaginator` (new) рисует уже-выбранный/отфильтрованный/отсортированный список в `QTableWidget` ПО СТРАНИЦЕ через колбэк `render_row(table,row,rec)`; полоска управления (First/◀/▶/Last + «стр X/Y · показано a–b из N» + комбо размера 100/200/500/1000); `set_rows(full)` хранит полный список и рисует страницу; `record_at(table_row)`/`index_at` маппят строку таблицы → запись полного списка (selection/detail работают); `on_page_changed` чистит stale-detail. Применено к 3 самым объёмным (gap-анализ): **Findings/Assets/Timeline** — каждый хранит полный список (`_findings_records`/`_assets_records`/`_timeline_events_data`) для selection + CSV (экспорт по полному набору, не по странице), рисует лишь страницу; selection через `paginator.record_at`. Остальные ~17 табличных вкладок — тривиальный follow-up на том же helper. Решение (locked): UI-windowing, не store limit/offset (сорт/фильтр/CSV над полным списком); охват = Findings+Assets+Timeline. Файлы: `gui/ui_components.py`, `gui/tab_findings.py`, `gui/tab_assets.py`, `gui/tab_timeline.py`, `tests/test_ui_pagination.py`, `tests/test_findings_tab.py`, `ROADMAP_ASM_2.0.md`. Коммит `e8d1df4d`. Проверено: ruff clean, целевые+смежные зелёные, полный pytest зелёный (рост 2361 → 2368). Прочие пробелы (отложены): i18n, e2e/GUI-тесты, мост captured-scan→tool evidence, assignment/comments в триаже, пагинация остальных таблиц.

**Ранее на 2026-06-30 (Scan Retention & Backup):**
- Закрыт пробел №2 из найденных (выбран после web-console-auth): неограниченный рост scan-workspace для CSM + отсутствие полного бэкапа. Две фазы, offline, без новых зависимостей. **Phase 1 — Retention** (`core/retention.py`): `plan_retention(project, *, keep_last, keep_days, now=None)` — чистый планировщик (новейший скан всегда жив; keep_last/keep_days; нет политики → keep all; `artifacts_pruned` не перечисляется повторно) + `apply_retention` удаляет ТОЛЬКО `scans/<id>/` и метит запись `artifacts_pruned`; индекс `metadata.json scans[]` + снимок `history/<id>.json` СОХРАНЯЮТСЯ → risk-серия/тренд целы, timeline мягко деградирует, FindingsStore не осиротеет (scan_id — лишь метка); идемпотентно; `policy_from_settings()`/`prune_project()`. Config `retention {enabled, keep_last, keep_days}` в `DEFAULT_SETTINGS` **off by default**. `collection_runner` авто-прореживает после Full Collection при `retention.enabled` (best-effort). GUI Overview «Prune old scans» (с подтверждением). Решение (locked, выбор пользователя): артефакты-только / индекс жив. Коммит `db0aa9e3`. **Phase 2 — Full Backup & Restore** (`core/backup.py`): `create_backup(dest, *, data_root=None, workspace=None)` → таймстемпованный `.zip` всего состояния (data root: SQLite-сторы под `data/` + конфиги под `configs/`; workspace: `Projects/` под `output_dir`). Каждый `*.db` через **online backup** SQLite (WAL-safe, без `-wal`/`-shm` сайдкаров) под `data_root/`, прочие файлы verbatim, workspace под `workspace/` (пропуск если вложен — без двойного захвата); сбой online backup → raw-copy fallback + warning. `backup_info` читает манифест; `restore_backup(..., replace=False)` — zip-slip guard, ПРОПУСКАЕТ существующие файлы кроме `replace=True` (restore никогда молча не затирает). GUI Overview «Backup all…» / «Restore…» (off-thread). Stdlib only. Коммит `dd99e75e`. Файлы: `core/retention.py`, `core/backup.py`, `core/config.py`, `core/collection_runner.py`, `gui/tab_overview.py`, `tests/test_retention.py`, `tests/test_backup.py`, `tests/test_overview_tab.py`, `ROADMAP_ASM_2.0.md`. Проверено: ruff clean, self-check, полный pytest зелёный (рост 2342 → 2361). Прочие пробелы (отложены): пагинация GUI-таблиц, i18n, e2e/GUI-тесты, мост captured-scan→tool evidence, assignment/comments в триаже.

**Ранее на 2026-06-30 (Web Console Auth & Safe Bind):**
- Закрыт пробел №1 по приоритету (стабильность/безопасность инструмента): LAN web-консоль (`remote/web_app.py`) получила мутирующие эндпоинты (mission run, tool-run → ingestion в сторы), но биндила `0.0.0.0` БЕЗ аутентификации. Решение (offline, без новых deps): (1) `resolve_web_console(host=None)` → `(host, token)` из `settings.json` `web_console` + env; дефолтный bind теперь `127.0.0.1` (из LAN недоступно), LAN — явный opt-in (`web_console.allow_lan` → `0.0.0.0` или явный не-loopback host); `start_server` дефолт host сменён `0.0.0.0` → loopback. (2) Одна app-wide зависимость `require_token` (`FastAPI(dependencies=[Depends(...)])`): при активном токене любой запрос вне `_PUBLIC_PATHS={'/'}` (статичная оболочка) обязан прислать `Authorization: Bearer` ИЛИ `?token=` (браузерный EventSource), сравнение `hmac.compare_digest`; иначе 401. (3) loopback+нет-токена → открыто (single-user desktop); LAN+нет-токена → токен авто-генерируется (`secrets.token_urlsafe`) и печатается один раз → консоль никогда не открыта в LAN без auth; источник токена `web_console.token` / `ASA_WEB_TOKEN`. (4) Дашборд: JS-шим подставляет токен (localStorage; prompt при 401) в fetch + SSE. (5) `web_console {host, allow_lan, token}` в `DEFAULT_SETTINGS`. Решения (locked): D1 дефолт loopback / LAN opt-in; D2 Bearer + `?token=`, app-wide dep; D3 loopback open / LAN авто-токен; D4 settings + env; D5 stdlib `secrets`/`hmac`. Совместимость: дефолт изменён намеренно (телефон в Wi-Fi не достучится без `allow_lan`); `main_orchestrator.start_server()` работает (loopback); CORS `*` оставлен. Файлы: `remote/web_app.py`, `core/config.py`, `tests/test_web_auth.py` (8), `ROADMAP_ASM_2.0.md`. Коммит `5c922062`. Проверено: ruff clean, целевые+смежные зелёные, полный pytest зелёный (рост 2334 → 2342). Прочие найденные пробелы (отложены): scan retention/backup, пагинация GUI-таблиц, i18n, e2e/GUI-тесты, мост captured-scan→tool evidence, assignment/comments в триаже.

**Ранее на 2026-06-30 (Tool-Run Orchestrator + surfaces):**
- Закрыт капстоун tool-слоя и все его поверхности. `core/tool_runner.run_tool_for_mission` композитит store-free pipeline (`assemble_tool_run`: gate→parse→map) и gated ingestion (`ingest_tool_run`) в один mission-scoped вызов — зеркало `mission_runner.run_mission`; `project` из миссии; возвращает renderable `ToolRunResult` + ingest-сводку; blocked/skipped не пишут. Формат синтетического scan_id централизован в `tool_runner.tool_scan_id`/`parse_tool_scan_id` (`tool-<tool>-<unix_ts>`, убрал дубль инлайн-строки в GUI+web). Поверхности: (1) GUI вкладка Missions — тонкая панель «Run tool (client-safe, evidence-driven)» (tool-combo из `TOOL_CAPABILITIES` + JSON evidence; `_run_mission_tool` парсит JSON на GUI-треде fail-fast, off-thread зовёт runner; кнопка активна для любой выбранной миссии — gate по ROE, не по статусу); (2) web `POST /missions/{id}/tools/run` (`MissionToolRequest`; 404 unknown / 400 missing tool; blocked/skipped → 200 `written:false`); (3) timeline derive-on-read `tool_run` (БЕЗ второго стора — `_derive_tool_runs` группирует ингестнутые CREATED finding/asset события по tool scan_id; `build_events(..., tool_runs=)` эмитит событие section `tools`; GUI-метка «Прогон инструмента»); (4) CSV — `build_timeline` дополнительно отдаёт структурные `tool_runs` (один путь деривации), `report_export.tool_runs_csv` (When/Tool/Findings/Assets/Scan ID), GUI Timeline «Export tool runs» + `GET /tool-runs.csv`. Решения (locked): только композиция/derive-on-read, без новой детекции/политики, без второго стора, без сети/новых deps, инструмент не исполняется. Коммиты: `d5d0d27b` (orchestrator), `cc2abc0d` (Missions GUI), `44731ae3` (web), `5d8dbf11` (timeline + scan-id SoT), `0ee42888` (CSV). Файлы: `core/tool_runner.py`, `core/timeline.py`, `core/report_export.py`, `gui/tab_missions.py`, `gui/tab_timeline.py`, `remote/web_app.py` + целевые тесты. Проверено: ruff clean, self-check 30 вкладок, полный pytest зелёный (collect-only 2334).

**Ранее на 2026-06-30 (Gated Tool-Run Ingestion):**
- Добавлен ПЕРВЫЙ store-writing слой tool-стека — `core/tool_ingest_store.py`: `ingest_tool_run(result, project, scan_id, *, findings_store=None, asset_store=None)` персистит findings/assets уже-авторизованного completed-`ToolRunResult` через canonical bridge (`tool_ingest`) в существующие `FindingsStore.upsert` (per finding) + `AssetStore.sync`. **Gated:** пишет только при `status=="completed"`; `blocked`/`skipped`/иное → no-op (авторизация решена выше `evaluate_tool_allowed_for_mission`; tool не запускается, сокет не открывается, policy не перепроверяется). **Idempotent:** upsert/sync identity-keyed → повторный ingest не дублирует. Возвращает `{status, written, findings, assets}`. Переиспользует существующие сторы (НЕ второй findings/asset-стор), без сети/новых зависимостей. Решения (locked): reuse FindingsStore/AssetStore + bridge DTO; писать только на `completed`; idempotent; result уже авторизован (без policy-перепроверки); tool по-прежнему не исполняется (evidence захвачен offline выше). Первый слой, пересекающий no-store-границу; чистый tool-стек (contract→parsers→pipeline→bridge→report) под ним не меняется. Файлы: `core/tool_ingest_store.py`, `tests/test_tool_ingest_store.py` (5 тестов). Не тронуты Timeline/CollectionRunner/GUI; второй стор не создан. Проверено: ruff clean, self-check 30 вкладок, полный pytest зелёный.

**Ранее на 2026-06-30 (Tool-Run Report Renderer):**
- Добавлен презентационный слой tool-стека — `core/tool_report.py`: чистые offline-рендеры `render_json`/`render_markdown`/`render_html(result)` поверх canonical schema-payload `ToolRunResult` (`tool_result_to_json`). Markdown несёт envelope (tool/action/mission/target/status + счётчики) + таблицы findings/assets; HTML escaped, заканчивается `markdown-sha`-комментом — зеркалит `core.audit_report`/`mission_report`. View, не storage: читает уже-собранный result, отдаёт строку; детерминирован, без сети/новых зависимостей/store-writes. Решения (locked): только презентация (рендер существующего payload, без детект/policy/новой модели); детерминизм; без store-writes/сети/deps. Файлы: `core/tool_report.py`, `tests/test_tool_report.py` (5 тестов). Не тронуты сторы/Timeline/CollectionRunner/GUI. Проверено: ruff clean, self-check 30 вкладок, полный pytest зелёный.

**Ранее на 2026-06-30 (Tool→Canonical Finding/Asset Bridge):**
- Добавлен мост tool-слоя к finding-модели платформы — `core/tool_ingest.py`: чистый конвертер `ToolRunResult` → канонические DTO. `tool_result_to_findings(result)` мапит findings через `findings_adapter.from_raw` (tool-finding получает ту же fingerprint-identity/категорию/нормализацию severity, что и любой сканер-finding; category из `_ACTION_CATEGORY` по action, дефолт `vuln`; tool string-refs кладутся в `detail`, т.к. это не manifest-артефакты — `Finding.evidence_refs` не засоряется). `tool_result_to_assets(result)` мапит assets в `asset_adapter.Asset` (обнаруживший tool в `attrs['source']`). Чистый/детерминированный: БЕЗ записи в стор, без сети, без новых зависимостей — ingestion в FindingsStore/AssetStore — отдельный явный шаг, НЕ этот слой. blocked/skipped/пустой result → пустые списки. Решения (locked): только конвертер (reuse from_raw + Asset, без новой модели); никаких store-writes; без сети/новых deps. Файлы: `core/tool_ingest.py`, `tests/test_tool_ingest.py` (7 тестов). Не тронуты сторы/Timeline/CollectionRunner/GUI. Проверено: ruff clean, self-check 30 вкладок, полный pytest зелёный.

**Ранее на 2026-06-30 (Offline Tool-Evidence Pipeline):**
- Добавлен композиционный капстоун tool-слоя — `core/tool_pipeline.py`: `assemble_tool_run(mission, tool, evidence, *, target=None) -> ToolRunResult` связывает M3-gate + parser + mapper в один store-free вызов. Порядок: строит M3 `ToolRunRequest` → гейтит через `evaluate_tool_allowed_for_mission` → если запрещено, возвращает `ToolRunResult(status="blocked")` с пустыми findings/assets (evidence НЕ парсится) → если разрешено, но нет парсера, `status="skipped"` → иначе `parse_tool_output` (уже-захваченный evidence) + `map_tool_result_to_findings` → `status="completed"`. Три исхода ложатся на существующий `RESULT_STATUSES` (`blocked`/`skipped`/`completed`). Только композиция — никакой новой детект/policy-логики; evidence — захваченный вход (не fetched, не запуск бинаря, без сети, без store-writes, без новых зависимостей). Файлы: `core/tool_pipeline.py`, `tests/test_tool_pipeline.py` (5 тестов). Не тронуты сторы/Timeline/CollectionRunner/GUI. Проверено: ruff clean, self-check 30 вкладок, полный pytest зелёный.

**Ранее на 2026-06-30 (Per-Tool Offline Parsers):**
- Добавлен следующий безопасный слой над Tool Adapter Contract — `core/tool_parsers.py`: чистые/offline/детерминированные парсеры, превращающие УЖЕ-захваченный evidence (структурированный dict) в generic `{"findings","assets"}`, который потребляет M3-`map_tool_result_to_findings`. БЕЗ запуска инструментов, без сети, без записи в сторы, без новых зависимостей, без exploit/bruteforce/stealth/payload. Парсеры по имени M3-tool: `parse_header_audit`/`parse_cookie_audit`/`parse_source_map_finder` — **детект переиспользован** из `core.audit_checks` (не переписан; парсер гоняет reused-check под пермиссивным in-scope ROE, т.к. scope-гейтинг — задача `evaluate_tool_allowed_for_mission`, а не парсера), `parse_safe_active_prober` — asset/enumeration (urls/hosts/subdomains → нормализованные assets, dedup, без findings). Диспетчер `parse_tool_output(tool, evidence)` + `has_parser(tool)`; реестр `PARSERS` аддитивен; empty/unknown/без-парсера tool → `ValueError`. Решения (locked): вход — captured evidence (не live-run, не сырой stdout бинаря); reuse audit_checks для header/cookie/source-map; фокусный первый набор (3 reuse-backed + 1 asset) с аддитивным реестром. Файлы: `core/tool_parsers.py`, `tests/test_tool_parsers.py` (7 тестов), `ROADMAP_ASM_2.0.md`. Не тронуты сторы/Timeline/CollectionRunner/GUI. Проверено: ruff clean, self-check 30 вкладок, полный pytest зелёный.

**Ранее на 2026-06-30 (Tool Adapter Contract Foundation):**
- Добавлен чистый/offline/детерминированный contract-слой `core/tool_adapter.py` для будущего подключения внешних recon/audit-инструментов (nuclei/nmap/katana/httpx) к pentest-миссии — БЕЗ запуска инструментов, без сети, без записи в FindingsStore/AssetStore/ProjectStore, без изменения risk verdict. API: `ToolCapability`(+`TOOL_CAPABILITIES` реестр client-safe tools), `ToolRunRequest`, `ToolRunResult`, `ToolFinding`, `ToolAsset`, `normalize_tool_name`, `resolve_tool_capability`, `build_tool_request`, `evaluate_tool_allowed_for_mission`, `map_tool_result_to_findings`, `tool_result_to_json`. Контракт детерминированный (canonical sort); unknown/empty tool → `ValueError`; request биндит mission_id/project/target/profile/**ROE** (в try1 ROE — SSOT scope; target выводится из `roe.allowed_domains`, если не задан). Gate НЕ вводит своей политики — мапит tool→action class и делегирует существующему `scope_policy.evaluate_scope_policy` (→ `action_policy`+`scope_guard`), передавая ROE как scope: forbidden-классы блокируются, passive-default блокирует active, active разрешён только при `active_scan_enabled=True`+`passive_only=False` и хосте в scope. Нет exploit/bruteforce/stealth/payload. `map_tool_result_to_findings` нормализует уже-распарсенный вывод в DTO и НЕ пишет в сторы. Новая `schemas/asa_tool_run.schema.json` + alias `asa_tool_run` в `core/audit_schema.SCHEMA_ALIASES`; `tool_result_to_json` отдаёт schema-valid payload. Файлы: `core/tool_adapter.py`, `schemas/asa_tool_run.schema.json`, `core/audit_schema.py`, `tests/test_tool_adapter.py` (9 тестов), `ROADMAP_ASM_2.0.md`. Не тронуты ProjectStore/FindingsStore/AssetStore/Timeline/CollectionRunner/GUI; зависимости не добавлены. Проверено: ruff clean, self-check 30 вкладок, полный pytest зелёный.

**Review/quality pass на 2026-06-29 (Mission Center M1–M15):**
- Ревью-проход по коду Mission Center. Найдена и устранена дупликация M7↔M15: `mission_overview.build_mission_overview` имел собственный `_latest_run` + инлайновый `audit_report.client_findings` для last-run outcome, тогда как M15-`mission_run_trend` уже считает per-run client-facing и отдаёт time-ordered историю. `build_mission_overview` теперь переиспользует `mission_run_trend` (last = `trend[-1]`); `_latest_run` удалён, дубль `client_findings` ушёл — один источник per-run счёта. Поведение сохранено (52 целевых + полный pytest зелёные). Остальное оставлено сознательно: ~3-4 общих строки `checks ∩ SAFE_CHECKS`+build+link в `run_mission`/`run_mission_audit` читаемее инлайн, чем вынос с кросс-модульной зависимостью при разной статус-семантике. Файл: `core/mission_overview.py`.

**Последние важные изменения на 2026-06-29 (Mission Center M15 — run trend):**
- M15: история прогонов миссии (последний grounded пункт дуги). `core/mission_overview.py`: новый `mission_run_trend(mission, *, audit_store=None)` — derive-on-read по `linked_audit_run_ids`, на каждый существующий run строка `{run_id, at(updated/created), status, client_facing}` (счёт через `audit_report.client_findings`), отсортировано по времени; отсутствующие runs пропускаются. GUI вкладка Missions: `_query_missions` аннотирует каждую миссию `_trend` (off-thread, общий audit-store), detail показывает «Run history (client-facing)» с последними 5 прогонами. Web: read-only `GET /missions/{id}/runs` (`_mission_runs`; 404 unknown). Без нового состояния/стора. Файлы: `core/mission_overview.py`, `gui/tab_missions.py`, `remote/web_app.py`, тесты `test_mission_overview.py`/`test_missions_tab.py`/`test_web_missions.py`. Проверено: ruff clean, self-check 30 вкладок, полный pytest зелёный. Mission Center: дуга M1–M15 закрыта.

**Ранее на 2026-06-29 (Mission Center M14 — stale-link cleanup):**
- M14: operator-driven очистка stale-линков (follow-up M11; закрывает плановую дугу Mission Center). `core/mission_links.py`: новый `prune_stale_links(mission, *, audit_store, findings_store)` — поверх `resolve_links` строит НОВУЮ миссию, оставляя только present run/finding линки, через чистый `pentest_mission.normalize_mission` (input не мутируется, пустая/без-stale миссия возвращается как есть); отдаёт `{mission, removed_runs, removed_findings}`. Контракт `pentest_mission` по-прежнему чист (prune живёт в opt-in слое). GUI вкладка Missions: кнопка «Remove stale» в link-ряду, активна только когда у выбранной миссии есть stale-линки (из `_links`); `_do_prune_links` → `save_mission` → рефреш. Web: `POST /missions/{id}/links/prune` (`_mission_prune_links`; 404 unknown / 400 ошибка; пуш-уведомление с числом удалённых). Файлы: `core/mission_links.py`, `gui/tab_missions.py`, `remote/web_app.py`, тесты `test_mission_links.py`/`test_missions_tab.py`/`test_web_missions.py`. Проверено: ruff clean, self-check 30 вкладок, полный pytest зелёный.

**Ранее на 2026-06-29 (Mission Center M13 — CSV export):**
- M13: экспорт портфеля миссий в CSV (паритет с findings/portfolio surfaces). `core/report_export.py`: новый `missions_csv(overview)` через общий `_rows_to_csv` + `_MISSIONS_COLUMNS` (mission_id/project/objective/status/last_run_id/last_run_status/client_facing/updated_at); принимает либо `mission_overview.build_mission_overview()` dict (`{'missions':[...]}`), либо bare-list (как `portfolio_csv`). GUI: кнопка «Export CSV» в ctrl-ряду вкладки Missions (`_export_missions_csv` → `_missions_csv_text(project)` строит overview для текущего проекта и рендерит). Web: `GET /missions.csv` (`_missions_csv`, media-type `text/csv`, зеркало `/findings.sarif`/`/report.md`). Pure-инвариант экспортёров сохранён (строка из уже-загруженных rows, без I/O в `missions_csv`). Файлы: `core/report_export.py`, `gui/tab_missions.py`, `remote/web_app.py`, тесты `test_report_export.py`/`test_missions_tab.py`/`test_web_missions.py`. Проверено: ruff clean, self-check 30 вкладок, полный pytest зелёный.

**Ранее на 2026-06-29 (Mission Center M12 — demo seed):**
- M12: Mission Center показан в demo workspace (release-readiness). `demo_seed.py`: новый `_seed_missions(missions_store, slug, audit_run_id, finding_id)` сеет 3 миссии на самом богатом (первом) проекте — (1) `ready` + `set_mission_schedule(weekly)` (видны контролы расписания/авто-тик), (2) executed: `draft→ready→running→completed` + `link_audit_run` (существующий demo-run) + `link_finding` (реальная находка) → даёт report/overview last-run outcome, (3) legacy со stale-линком (`link_audit_run('audit-demo-removed')`) → демонстрирует M11-флаг. `seed()` создаёт `MissionStore(pm.get_db_path('missions.db'))`, ловит `run_id` из `_seed_audit_run`, зовёт `_seed_missions` один раз (`n_mission`); summary/`main` печать += `missions`. Файлы: `demo_seed.py`, тест `test_demo_seed.py`. Проверено: ruff clean, end-to-end seed (3 миссии), полный pytest зелёный.

**Ранее на 2026-06-29 (Mission Center M11 — link integrity):**
- M11: целостность линков миссии (закрыт отложенный M1 D4), без нарушения чистоты контракта. Чистый `pentest_mission.link_audit_run`/`link_finding` НЕ тронут (по-прежнему линкует без I/O — тест-инвариант `test_pentest_mission_link_stays_pure`). Новый `core/mission_links.py` — store-aware opt-in слой поверхностей: `link_audit_run_checked(mission, run_id, *, audit_store)` / `link_finding_checked(mission, finding_id, *, findings_store)` (валидируют существование → `ValueError` если нет → иначе делегируют чистому линку), `resolve_links(mission, *, audit_store, findings_store)` → `{present_runs, stale_runs, present_findings, stale_findings}` (stale = ссылка на удалённый run/finding; не дропается, только именуется). GUI вкладка Missions: `_do_link_run`/`_do_link_finding` теперь зовут checked-варианты (deleted id между populate и кликом отбивается), `_query_missions` аннотирует каждую миссию `_links` (resolve через общие стор-инстансы), detail показывает «⚠ Stale links». Web/report stale уже покрыт M5 (`build_mission_report` помечает missing) — нового эндпоинта нет. Файлы: `core/mission_links.py` (new), `gui/tab_missions.py`, тесты `test_mission_links.py` (new)/`test_missions_tab.py`. Проверено: ruff clean, self-check 30 вкладок, полный pytest зелёный.

**Ранее на 2026-06-29 (Mission Center M10 — scheduling auto-tick):**
- M10: due-миссии теперь исполняются автоматически на тике монитора (завершён follow-up M9). Связка сделана на уровне ДРАЙВЕРОВ, движок `core/monitor` остаётся развязанным с миссиями: `MonitorScheduler.__init__` получил generic-колбэк `extra_tick(now)` — `tick()` зовёт его после project-sweep (исключение в extra_tick не рушит цикл — уходит в `on_event` как `error`); сам `monitor.py` миссии не импортирует. `mission_schedule.run_due_missions` получил `on_event=` и эмитит событие `{'type':'mission_run','slug':project,'mission_id','run_id','status'}` на каждый прогон; `monitor.format_event` рендерит `mission_run` (shared formatter для web-feed и in-app индикатора). Драйверы инъектируют tick: in-app `gui/monitor_runner.MonitorRunnerMixin._tick_due_missions` (на daemon-треде, emit маршалится в GUI-тред тем же bridge-сигналом) передаётся как `extra_tick`; `monitor_cli`: команда `run` дополнительно гоняет due-миссии (`cmd_run_missions`), `watch` передаёт `extra_tick`, `_print_event` рендерит `mission_run`. Авто-тик опт-ин (как и project-мониторинг: `monitor_autostart`); миссия бежит только при включённом расписании. Файлы: `core/monitor.py`, `core/mission_schedule.py`, `gui/monitor_runner.py`, `monitor_cli.py`, тесты `test_monitor.py`/`test_mission_schedule.py`/`test_monitor_cli.py`. Проверено: ruff clean, self-check 30 вкладок, полный pytest зелёный.

**Ранее на 2026-06-29 (Mission Center M9 — recurring scheduling):**
- M9: периодический перезапуск миссии по кадансу, переиспользуя примитивы `core/monitor` (без второго планировщика). Архитектурное решение (locked): тик НЕ двигает one-shot статус-машину миссии (`ready→running→completed`, у которой нет `completed→ready`) — вместо этого `mission_schedule.run_mission_audit` строит audit run миссии через `audit_runner.build_audit_run` (checks = `allowed_actions ∩ SAFE_CHECKS`, ROE-gated) и линкует его (`link_audit_run`→`save_mission`, статус сохраняется); это status-neutral counterpart `mission_runner.run_mission`. Состояние расписания — новая колонка `schedule` (JSON) таблицы `missions` (`MissionStore` SCHEMA_VERSION 1→2, миграция через идемпотентный `_add_column`; `JSON_FIELDS+=schedule`), ОТДЕЛЬНО от canonical `payload` (контракт M1 не тронут); `save_mission` не перезаписывает `schedule`. `core/mission_schedule.py`: `make_mission_schedule`/`set_mission_schedule`/`disable_mission_schedule` (reuse `monitor.compute_next_run`), `run_due_missions(*, store, now, run)` (walk `list_scheduled`, enabled+due через `monitor.is_due`, прогон, advance `last_run/next_run/last_status`; ошибка одной миссии не рушит проход — пишется в `last_status`). MissionStore: `set_schedule`/`get_schedule`/`list_scheduled`. Surfaces (D2 locked: standalone + manual/web, без OS-tick): GUI на вкладке Missions — interval-combo + Enable/Disable schedule + «Run due now», расписание показано в detail; web `POST /missions/{id}/schedule` (`ScheduleRequest` interval/enabled; 404/400) + `POST /missions/run-due`. Bundle (`project_io`) переносит `schedule` через `SELECT *` (whitelist на импорте) — round-trip зелёный. Файлы: `core/mission_schedule.py` (new), `core/mission_store.py`, `gui/tab_missions.py`, `remote/web_app.py`, тесты `test_mission_schedule.py` (new)/`test_missions_tab.py`/`test_web_missions.py`. Проверено: ruff clean, self-check 30 вкладок, полный pytest зелёный. Отложено: авто-тик в OS-monitor/cron.

**Ранее на 2026-06-29 (Mission Center M8 — timeline run events):**
- M8: события исполнения миссии в таймлайне, derive-on-read, без нового состояния и без правки поверхностей. `core/timeline.build_events` получил параметр `mission_runs` (список уже-резолвленных `{mission_id, objective, run_id, status, created_at, updated_at}`): на каждый — `mission_run_started` (severity info, по `created_at` run'а) и при терминальном статусе `mission_run_completed`/`mission_run_failed` (failed → medium, по `updated_at`), секция `missions`; дополняют M3-события статуса миссии (другой type/title, dedup не схлопывает). `build_timeline` строит `mission_runs`, резолвя `linked_audit_run_ids` каждой миссии против уже загруженного `audit_runs` (build_events остаётся чистым — без обращения к стору). Поверхности (GUI tab_timeline, web `/timeline`) не менялись — секция `missions` рендерится дженерик-путём ещё с M3. Файлы: `core/timeline.py`, тесты `test_timeline.py`. Проверено: ruff clean, self-check 30 вкладок, полный pytest зелёный.

**Ранее на 2026-06-29 (Mission Center M7 — overview/dashboard):**
- M7: портфельная сводка миссий, derive-on-read, без нового состояния. Новый `core/mission_overview.py`: `build_mission_overview(*, mission_store=None, audit_store=None, project=None)` → `{total, counts:{status:n}, client_facing, missions:[row]}`; для каждой миссии берётся последний linked Audit Run (по `updated_at`) и его client-facing счёт через `core.audit_report.client_findings` (отсутствующие runs пропускаются). View поверх `MissionStore`+`AuditRunStore`, второго стора нет. Surfaces: GUI карточка «Миссии (Mission Center)» на вкладке Overview (stat-cards total/ready/running/completed/failed/client-facing + строка «последняя миссия»), вплетена в существующий `_query_overview` (best-effort, портфолио рендерится даже если миссии упали) + `_populate_overview_missions`; web read-only `GET /missions/overview` (литеральный роут объявлен до `/missions/{id}`). Файлы: `core/mission_overview.py` (new), `gui/tab_overview.py`, `remote/web_app.py`, тесты `test_mission_overview.py` (new)/`test_overview_tab.py`/`test_web_missions.py`. Проверено: ruff clean, self-check 30 вкладок, полный pytest зелёный.

**Ранее на 2026-06-29 (Mission Center M6 — creation UI):**
- M6: создание миссии оператором (закрыт пробел, отложенный с M3/M5). GUI: панель «Create mission (client-safe)» на вкладке Missions — `QLineEdit` project/objective, scenario-`QComboBox` (None + `audit_templates.list_templates`), ROE-контролы (allowed domains/active/passive/rate, зеркало вкладки Audit Runs) и чекбоксы allowed_actions из `audit_checks.SAFE_CHECKS` (только client-safe действия); `_do_create_mission` (worker) зовёт `pentest_mission.create_mission`→`validate_mission` (гейт client-safe/ROE) → `MissionStore.save_mission`, затем рефреш с авто-выбором созданного проекта (`_mission_pending_project`). Web (D-locked): `POST /missions` (`MissionRequest`: project/objective/template/roe/allowed_actions) → `_mission_create` → 200 `{mission_id,status}` / 400 на невалидной (напр. не-client-safe action). Решения: GUI **и** web-эндпоинт; client-safe гейт через `validate_mission` перед сейвом (схема не ловит action-policy); создание не дублирует ядро — только контракт M1. Файлы: `gui/tab_missions.py`, `remote/web_app.py`, тесты `test_missions_tab.py`/`test_web_missions.py`. Проверено: ruff clean, self-check 30 вкладок, полный pytest зелёный.

**Ранее на 2026-06-29 (Mission Center M5 — report):**
- M5: evidence-first отчёт миссии — операторский takeaway, без второго стора (view поверх существующих сторов). Новый `core/mission_report.py`: `build_mission_report(mission, *, audit_store, findings_store)` ассемблирует канонический report-dict — envelope (objective/ROE/allowed_actions/status/report_orientation) + `runs` (по `linked_audit_run_ids`: per-run `client_findings`/`review_findings`/`audit_summary`, переиспользованы из `core.audit_report`; отсутствующий run помечается `missing`, не фейкается) + `linked_findings` (по `linked_finding_ids` из `FindingsStore.get`; stale → stub) + `summary`. Чистые детерминированные рендеры `render_json` (sort_keys), `render_markdown` (секции Linked Audit Runs / Linked Findings appendix), `render_html` (escape + markdown-sha, как `audit_report`). Surfaces (D2 locked): GUI кнопки Export JSON/MD/HTML на вкладке Missions (активны при выбранной миссии; рендер через `_render_mission_report`), web read-only `GET /missions/{id}/report` (JSON) + `/missions/{id}/report.md` (markdown; 404 unknown). Decisions (locked): D1 контент = evidence линкованных runs + appendix явных findings; схемы нет (производный view, не контракт-стор); D3 build читает сторы, рендеры чистые. Файлы: `core/mission_report.py` (new), `gui/tab_missions.py`, `remote/web_app.py`, тесты `test_mission_report.py` (new)/`test_missions_tab.py`/`test_web_missions.py`. Проверено: ruff clean, self-check 30 вкладок, полный pytest зелёный.

**Ранее на 2026-06-29 (Mission Center M4 — execution):**
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
- `PROJECT_REPORT.md` указывает актуальный масштаб набора; на 2026-07-02 (после DEV_PLAN остаток WS6 + пост-план опции) — 2597 offline/headless теста (зелёные, 1 Starlette/httpx warning; junit-xml подтверждает 2597); GUI — 29 вкладок.
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
