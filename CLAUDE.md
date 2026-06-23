# CLAUDE.md — Advanced Site Analyzer

> Этот файл Claude Code читает автоматически в начале каждой сессии.
> Он задаёт контекст, архитектуру и **жёсткие правила**. Не нарушать.

---

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

gui/                    # ТОНКИЙ UI-слой (mixin-паттерн)
  main_window.py        # чистый контейнер: собирает окно из mixin'ов
  task_runner.py        # TaskRunnerMixin: _start_task / _run_async — ЕДИНЫЙ раннер фоновых задач
  window_chrome.py      # меню, таб-бар из PluginManager, статус-бар
  window_helpers.py     # общие helpers (пути, архивация, busy-state, browse)
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

## 12. Текущее состояние (единый ориентир — чтобы не путаться)

> Это краткая «карта» статуса. Полный хронологический лог — `PROJECT_STATUS.txt`,
> каталог модулей — `PROJECT_REPORT.md`. **CLAUDE.md — единственная точка входа.**

**Документы-источники (не плодить новые):**
- `CLAUDE.md` — правила + архитектура + статус (этот файл, авто-загрузка).
- `ROADMAP_ASM_2.0.md` — план эпика F1–F6 (корень, НЕ `docs/`).
- `KICKOFF_PROMPT.md` — стартовый промпт эпика.
- `PROJECT_STATUS.txt` — детальный лог реализаций (исторический).
- `PROJECT_REPORT.md` — таблица модулей/метрик.

**Базовая зрелость:** платформа-анализатор + Full Collection + risk-движок +
Scan Diff + проекты (`Projects/<домен>/`) + ASM 2.0 (F1–F6) + Asset Inventory.
Тесты: 1563 collected/pass (offline/headless; web-live skip без httpx).

**Сделано до эпика (legacy #1–#13):** OSINT-бандл #13 (dns_intel, email_intel,
employee_intel, ct_history) и др. #14 (JSON `findings_status.py`) был **заменён**
на SQLite-стор в рамках F1 (см. ниже) — старого модуля/`findings.json` больше нет.

**Статус эпика ASM 2.0:**
- **F1 Findings Management** — `[ЗАКРЫТ]`: T1.1 fingerprint
  (`core/finding_fingerprint.py`) ✓, T1.2 SQLite-стор (`core/findings_store.py`,
  БД `data/findings.db`) ✓, T1.3 адаптер (`core/findings_adapter.py`) ✓,
  T1.4 `FindingsStore.sync()` + lifecycle в CollectionRunner (авто-FIXED со
  scope-guard, липкость IGNORED/FALSE_POSITIVE, риск исключает INACTIVE,
  карточка отчёта) ✓, T1.5 GUI-вкладка «Findings» (`gui/tab_findings.py`:
  селектор проекта + фильтры статус/severity, таблица, панель улик+истории
  событий, смена статуса через `_run_async`; read-primitive
  `FindingsStore.projects()`, общий `STATUS_LABELS`) ✓, T1.6 web-эндпоинты
  (`remote/web_app.py`: `GET /findings` с фильтрами project/status/severity,
  `POST /findings/{id}/status`; чистые хелперы `_findings_list`/
  `_findings_set_status` + read-кнопка «Findings» в консоли) ✓,
  T1.7 итоговые тесты (`tests/test_findings_lifecycle.py`: авто-FIX gated по
  факту прогона фазы-источника — dns/nuclei, цепочка triage→stamp→исключение
  из risk, reopen→stamp; fingerprint-стабильность и store-lifecycle уже
  покрыты ранее) ✓. **Находки персистятся между сканами, живут по жизненному
  циклу и триажатся из GUI и web (паритет).**
  **F1 ЗАКРЫТ.** Cross-project коллизия находок без URL-локации устранена
  (вариант B): строки стора ключуются проектно-скоупленным id
  `scoped_id(project, fingerprint)` (`core/finding_fingerprint.py`), сам
  fingerprint остаётся контентным/проектно-агностичным (golden не тронут);
  миграция БД v1→v2 идемпотентна (`FindingsStore._migrate_to_v2`, SCHEMA_VERSION=2),
  публичные сигнатуры стора/GUI/web не менялись. Покрыто
  `test_findings_store_migration.py` + cross-project тестами.
- **F2 Timeline / Change Events** — `[ЗАКРЫТ]` (derive-on-read, без новой
  таблицы): T2.1 ✓ — общее ядро `scan_diff.diff_events` (единый классификатор
  diff→события для F2 и F4; `alerts.extract_alerts` — тонкий фильтр над ним,
  поведение неизменно), `core/timeline.py` (`build_series` из `metadata.scans[]`,
  `build_events` из попарного scan_diff + `finding_events`, дедуп+хронология;
  `build_timeline(project)`), `FindingsStore.project_events()`. T2.2 поглощён
  (отдельной записи не требуется — артефакты уже персистентны). T2.3 ✓ —
  GUI-вкладка «Timeline» (`gui/tab_timeline.py`: селектор проекта, лента
  изменений с severity-подсветкой, таблица метрик по сканам; ленивая загрузка
  через `_run_async`). T2.4 ✓ — `test_diff_events.py`/`test_timeline.py`/
  `test_timeline_tab.py`. GRAPHQL отложен.
- **F3 Continuous Monitoring** — `[ЗАКРЫТ]` (решения: in-app + OS-флаг,
  расписание в `metadata.json` extend, per-job options). T3.1 ✓ — движок
  расширен: `default_monitor_options()`, `make_schedule(..., options)` +
  `last_status`, `_build_run_fn(base, options)` (заменил `_default_run_fn`),
  `run_due` строит run_fn **per-project** из его options, `run_project`/
  `_advance_schedule` пишут `last_status` (failed-скан тоже двигает расписание),
  `monitor.format_event` (единый формат событий — web делегирует). **Находка
  аудита:** OS-level адаптер УЖЕ ЕСТЬ — `monitor_cli.py` (`run` = прогон готовых
  для cron/Task Scheduler, `watch` = блокирующий цикл) → плановый T3.3 не нужен.
  T3.2 ✓ — in-app проводка `MonitorScheduler` в GUI: `gui/monitor_runner.py`
  (`MonitorRunnerMixin` + `_MonitorBridge` QObject-сигнал маршалит события
  фон-потока в GUI; `_init/_start/_stop_monitor_scheduler`, индикатор в
  статус-баре), autostart из `settings.monitor_autostart`, `stop()` в
  `closeEvent`; настройки `monitor_autostart`/`monitor_check_interval` в
  DEFAULT_SETTINGS. T3.4 ✓ — GUI Collection-вкладка: чекбокс «Авто (фоном)»
  (toggle in-app планировщика + персист `monitor_autostart`), общий
  `_collection_options()` (читает чекбоксы; переиспользован Full Collection и
  monitor-enable → мониторинг гоняет ровно выбранные фазы; `_build_run_fn`
  расширен на полный набор), показ `last_status` в статусе. T3.5 ✓
  (test_monitor*/test_monitor_gui). OS-level — `monitor_cli.py` (run/watch).
- **F4 Alert Center** — `[ЗАКРЫТ]`. Был во многом готов: `core/alerts.py`
  (каналы telegram/discord/email + `extract_alerts` поверх общего `diff_events`),
  диспетч из monitor/web/CLI, GUI-настройка каналов+типов+тест-отправка (Settings
  → «Уведомления», `gui/dialogs.py`), токены только в settings, маскирование.
  Закрывающий инкремент: **журнал доставки** через переиспользование
  `OperationRegistry` (`alerts._record_delivery` пишет каждую отправку как
  операцию `phase='alert'` → видно в History/`/history`; новой таблицы нет).
  conftest изолирует `operations.db` (маркер `real_operations_db` для opt-out).
  Пороговые правила + generic-webhook — **отложены** (YAGNI; плоский `types`-
  фильтр + diff-триггер дают естественный дедуп). 3-табличная модель роадмапа
  отклонена как избыточная для десктопа.
- **F5 Executive Dashboard** — `[ЗАКРЫТ]` (решение по графике: native Qt /
  inline-SVG, БЕЗ QWebEngine/ECharts — сохраняет инвариант «тяжёлые деп не
  бандлятся в .exe», повторяет уже принятый паттерн `report_charts.py`).
  T5.1 ✓ — `core/portfolio.py` (pure): `build_portfolio` (строки по проектам:
  latest риск/surface/secrets/high/medium, `risk_delta` vs прошлый скан,
  active-findings) + `totals`, `build_exposure_matrix` (проекты×категории →
  ячейки с цветом по severity-рампе), тонкий `load_portfolio(base)`
  (`ProjectStore.list_projects` + `FindingsStore.summary`). Ничего не
  пересчитывает — переиспользует `metadata.json` + F1-стор (I3). T5.2 ✓ —
  `core/dashboard_charts.py` (pure stdlib SVG, брат `report_charts.py`):
  `sparkline`, `heatmap`; в GUI рендер через `QSvgWidget` (входит в PyQt5).
  T5.2-GUI/T5.3 ✓ — вкладка «Overview» (`gui/tab_overview.py`,
  `OverviewTabMixin`): roll-up карточки + «худший риск», портфолио-таблица
  (худший риск сверху, дельта ↑/↓), exposure-heatmap, per-project тренд-
  sparklines; всё off-thread через `_run_async`, lazy-load в
  `tab_history._on_tab_changed`, регистрация в `BUILTIN_TABS` между Timeline и
  Dashboard. T5.4 ✓ — кнопка «Граф атак-поверхности»: переиспользует
  `attack_surface.build_surface`+`render_svg` последнего скана (инъекция
  `xmlns` для standalone `QSvgRenderer`), показ в диалоге. T5.5 ✓ —
  `test_portfolio.py`/`test_dashboard_charts.py`/`test_overview_tab.py`.
  **Web-паритет** ✓ — `remote/web_app.py`: `GET /overview` (тонкий
  `_overview_summary` поверх `load_portfolio`) + кнопка «Overview» в консоли
  (`test_web_overview.py`). **Heatmap-разбивка** ✓ — exposure-heatmap получил
  detection-колонки SourceMap/Cookie/GraphQL рядом с Secrets (API-ключи = текущая
  Secrets, без дубля); GraphQL красится по introspection (open → critical),
  SourceMap — как секрет, Cookie — moderate. Числа уже считаются в
  `executive_summary.metrics` (`source_map_leaks`/`weak_cookies` + новые
  `graphql`/`graphql_introspection` через `_graphql_exposure`) и теперь
  **персистятся** в `Project._scan_entry` → portfolio читает их из дешёвого
  `metadata.json`, без загрузки report по каждому проекту (I3); pre-F5 метаданные
  без этих ключей мягко деградируют в чистые ячейки. `_EXPOSURE_COLUMNS`
  level-фунции переведены на приём строки (чтобы GraphQL учитывал второй сигнал).
  Покрыто расширенными `test_portfolio`/`test_executive_summary`/`test_project`.
  **Тренд-графики в HTML-отчёте** ✓ — карточка «Trends» в report.html:
  sparkline'ы Risk score / Attack surface / Secrets / High vulns по истории
  сканов проекта. Серия строится в `CollectionRunner.run` через
  `timeline.build_series` (prior-сканы из metadata + текущий через
  `Project._scan_entry`, переиспользование без второй модели — I3) и кладётся в
  `report['trends']`; `_render_trends_card` рисует через offline-`dashboard_charts.
  sparkline` (без новых зависимостей). Показывается только при ≥2 сканах; новый
  ключ `report['trends']` не трогает scan_diff (phase-based). Покрыто
  `test_collection_runner` (multi-scan рисует, single-scan скрыт). **F5 полностью
  закрыт.**
- **F6 GUI Redesign** — `[вариант A ЗАКРЫТ; вариант B ЗАКРЫТ — P0–P3b]`.
  Вариант B (миграция на PySide6+qfluent) идёт строго поэтапно, стабильность №1.
  Решения: стек PySide6+PySide6-Fluent-Widgets, шов `qtpy`, глубина «гибрид»
  (Fluent-оболочка, внутренности вкладок как есть). **P0** (спайк): замер `.exe` —
  tuned-проекция ~51 MB (+32%) с excludes Qt6-Addons; шов `qtpy` верифицирован на
  обоих байндингах (оговорка: `QSvgWidget` — Qt5 `QtSvg` / Qt6 `QtSvgWidgets`).
  **P1** (готов): все `from PyQt5.X` → `from qtpy.X` (gui/ 27 файлов + main.py +
  plugins/scrapy_tab + conftest/тесты), `pyqtSignal/Slot`→`Signal/Slot`, `QAction`→
  `qtpy.QtGui`, `QSvgWidget` биндинг-агностично; `qtpy` в requirements; `QT_API=pyqt5`
  пиновано (флип P2 = заменить на `pyside6` в main.py+conftest). Байндинг ОСТАЁТСЯ
  PyQt5, поведение байт-в-байт, 925 passed, обратимо. **P2** (готов): флип `QT_API`
  на `pyside6` (PySide6 6.11.1; PyQt5 оставлен как fallback), единственное трение —
  3×`exec_()`→`exec()`; enum-scoping правок НЕ потребовал. 925 passed под PySide6,
  frozen `.exe` собирается и проходит self-check. **Открытый вопрос — размер:**
  module-`excludes` НЕ режут Qt6-DLL (PySide6-хук PyInstaller тащит плагины
  принудительно) → 69.7 MB; после TOC-фильтра в build.spec (translations + qml/quick/
  pdf/virtualkeyboard; opengl оставлен) — **60.1 MB (+56%)** против 38.5 MB на PyQt5.
  Это ВЫШЕ согласованных в P0 +32% — пользователь **принял ~60 MB**. **P3a** (готов):
  Fluent-навигация через адаптер — `gui/fluent_nav.py` `FluentTabWidget` (фасад
  QTabWidget над qfluent `NavigationInterface`+`QStackedWidget`, отдаёт только нужный
  подмножество API), `make_central_tabs()` в `window_chrome._build_central`; контракт
  плагинов/lazy-load/тесты целы. Тема: `theme.apply_theme`→qfluent `setTheme`. Гейт
  `_HAVE_FLUENT` по `qtpy.API_NAME=='PySide6'` (под PyQt5 — мягко QTabWidget, без
  кросс-байндинг краша). `PySide6-Fluent-Widgets` в requirements; build.spec бандлит
  его ресурсы (`collect_all`). **P3b** (готов, вариант B ЗАКРЫТ): решено дропнуть
  PyQt5-fallback (коммит на PySide6) + кастомный статус-бар. `MainWindow`→`FluentWindow`
  (frameless); меню (Настройки/О программе/Выход) → nav-footer; `self.tabs` — фасад
  `FluentWindowTabs` над встроенными nav+stack окна (addTab→`addSubInterface`, per-tab
  иконки, `currentChanged`); кастомный `StatusBar` (showMessage/addPermanentWidget/
  currentMessage) монтируется под nav+content через перенос layout. theme→qfluent
  setTheme. 925 passed, ruff чист, self-check 19 вкладок, frozen `.exe` 63.5 MB.
  **Оговорка ЗАКРЫТА (живой запуск):** frozen `dist_pyside6/SiteAnalyzer.exe`
  запущен вживую и визуально проверен (скриншоты + PrintWindow PW_RENDERFULLCONTENT) —
  frameless FluentWindow рендерится корректно: кастомная caption-полоса (back-arrow+
  title+min/max/close), nav-рельс с per-tab иконками, функц. переключение вкладок,
  полный рендер контента, тёмная тема, стабильность при maximize/restore/resize, чистая
  сборка nav+content+низ без разрывов лэйаута. Остаток: idle-status-strip и nav-футер
  не изолированы визуально на 1536×864 (min-высота окна), но их API покрыт тестами.
  Полный план/цифры — в памяти `project-gui-variant-b`.
  Решение: opt-in тёмная тема, дефолт `system` (вид не меняется,
  пока не переключишь) — стабильность №1. T6.1/T6.2 ✓ — `gui/theme.py`
  (единый источник chrome-палитры; `dark_palette()` Fusion-friendly QPalette,
  `theme_qss`, `apply_theme(app, name)`), ключ `gui_theme` в DEFAULT_SETTINGS,
  применение в `main.py` при старте + комбо «Оформление» в Settings-диалоге с
  live-apply. T6.3 ✓ — `gui/ui_components.py` (`StyledButton`/`SectionGroupBox`)
  берут цвета из `theme.button_qss`/`group_box_qss` (публичные сигнатуры не
  тронуты; светлый вид байт-в-байт прежний, нейтральные виджеты адаптируются под
  тёмный). T6.4 ✓ — `theme.is_dark`/`chrome`; heatmap в `dashboard_charts` принял
  `label_color`/`header_color` (дефолты сохраняют светлый/отчётный вид), Overview
  отдаёт тёмные подписи под тёмной темой. **Полировка:** `theme.risk_color`/
  `theme.severity_color` — тема-зависимые яркие варианты (на тёмном фоне тёмно-
  красный `#8b0000` и тёмно-зелёный `#2e7d32` как текст нечитаемы); прокинуты в
  Dashboard/Overview/Findings/Timeline; `_SEVERITY_COLORS` остался алиасом
  `theme.LIGHT_SEVERITY` (back-compat). Отчётные палитры (core RISK_COLORS /
  scan_diff / report) НЕ тронуты — там светлый фон; `collect_log` (всегда тёмный
  console) оставлен как был. T6.5 ✓ — `test_theme.py` + параметры heatmap в
  `test_dashboard_charts.py`. **Без новых
  зависимостей; `.exe` не раздувается; Fusion+QPalette перекрашивает всё разом
  без свипа по 16 вкладкам.**

**Пост-эпик инкременты (после ASM 2.0, по запросу):**
- **Detection-углубление** (существующие движки расширены, не переписаны):
  `tech_fingerprint` — категория «JS Framework» (Next.js/Nuxt/SvelteKit/Gatsby/
  Remix/Astro/Angular с версией из `ng-version`; добавлен `version_html`);
  `dependency_audit` — axios/underscore/marked + CVE-диапазоны (marked заякорен
  от `bookmarked`); `graphql_discovery` — field-suggestions + query-batching +
  больше путей (единый seam `_post_raw`). Всё offline, формы находок/технологий
  прежние → автоматически в risk/attack-surface/report.
- **`core/asn_intel.py`** — АКТИВНАЯ ASN/netblock-разведка (opt-in, keyless):
  RDAP CIDR/range + RIPEstat префиксы (кэп 50) + reverse-IP co-hosted домены
  (HackerTarget, best-effort, кэп 100). Паттерн dns_intel: инъектируемый
  `_get_text`, TTLCache, мягкая деградация. Проводка: флаг `asn_intel` в
  CollectionRunner (фаза 7j, карточка отчёта), чекбокс в Collection,
  monitor-паритет (`_build_run_fn`), Settings «Очистить кеш» суммирует
  `clear_cache()`. `infrastructure.py` (offline derive) не тронут.
- **`core/osv_correlation.py`** — АКТИВНАЯ CVE-корреляция через OSV.dev (opt-in,
  keyless, live API — НЕ оффлайн-снимок: полный npm-дамп раздул бы `.exe`).
  Заменяет ручное устаревание захардкоженных CVE в `dependency_audit`: паттерн
  asn_intel — инъектируемый `_post_json` (POST `/v1/query`, stdlib), TTLCache,
  мягкая деградация; `_parse_osv`→severity в 3-бакетный словарь vuln-скана;
  `to_findings` с `source='dependency-audit'` (тот же producer → F1/adapter без
  правок) и `discriminator=CVE`. Проводка: флаг `osv` в CollectionRunner (фаза
  7k `_phase_osv` — **вытесняет** бандл-находки покрытых либ из `vulns.findings`,
  fold-in как `_phase_dns`; OSV-вулны обогащают существующую карточку
  Dependencies, новой карточки нет), чекбокс в Collection, monitor-паритет,
  Settings «Очистить кеш». Хардкод-таблица остаётся offline-fallback. Покрыто
  `test_osv_correlation.py` (+osv в `test_monitor`). UX: ряд из 14 opt-in
  чекбоксов Collection переведён на `FlowLayout` (`gui/ui_components.py`) —
  переносится на 2+ строк вместо клиппинга за краем экрана (14-й чекбокс OSV
  раньше уходил за правый край на 1536px).
- **Dedup + SLA находок (стиль DefectDojo).** **SLA** (`core/findings_sla.py`,
  pure, derive-on-read из `first_seen_at`+severity, без схемы): окна по severity
  (DefectDojo-дефолты critical 7/high 30/medium 90/low 120; info — нет),
  `sla_status`/`annotate`/`label`/`breached_count`; колонка «SLA» в GUI Findings
  (+подсветка просрочки), счётчик в report-карточке, поля в web `/findings`;
  кастомизация через `settings['findings_sla']`. **Кросс-сканерный dedup по CVE**:
  `findings_adapter` стал CVE-осведомлённым (`extract_cve`; при наличии CVE
  identity канонизируется в `category=vuln`/`rule_id=cve-…`), один CVE от
  nuclei+OSV+dependency-audit схлопывается в одну находку, `sources` копятся в
  evidence («N references»); `dedup_findings` + `collection_runner._dedup_vuln_findings`
  дедупят risk-список перед F1-sync/summary (CVE считается раз). Не-CVE находки —
  identity не тронута. Churn идентичности принят (без миграции, как OSV-вытеснение).
  Покрыто `test_findings_sla.py`/`test_findings_dedup.py`.
- **`core/report_export.py`** — CSV-экспорт `findings_csv`/`portfolio_csv`/
  `assets_csv` (stdlib); кнопки «Export CSV» в Findings/Assets/Overview
  (utf-8-sig). PDF — печатью самодостаточного `report.html` (тяжёлый PDF-движок
  не добавляли).
- **Asset Inventory** (`core/asset_adapter.py` + `core/asset_store.py`) —
  ПЕРСИСТЕНТНЫЙ реестр активов, аналог Findings Management, но для активов
  (domain/subdomain/ip/asn/netblock/endpoint/technology). Актив живёт между
  сканами, не внутри отчёта: `asset_adapter.derive_assets` (pure, offline —
  читает уже собранный report, сканеры не трогает; identity = sha1(type␟norm),
  endpoint через `finding_fingerprint.normalize_location`, технология = имя без
  версии) → `AssetStore` (SQLite `data/assets.db`, scoped-id ключ, lifecycle
  ACTIVE⇄GONE→REAPPEARED, scope-guard «gone только если фаза-источник
  отработала», `SCHEMA_VERSION=1`). Проводка: `collection_runner._sync_assets`
  (best-effort, `report['assets']` + карточка «Asset Inventory» в report.html
  рядом с Findings — `_render_assets_card`), GUI-вкладка «Assets» (`gui/tab_assets.py`,
  read-only — активы не триажат: селектор проекта + фильтры тип/статус, таблица,
  детали+история, Export CSV; off-thread + lazy-load), web `GET /assets` +
  кнопка «Assets» (read-only, без POST), интеграция в Timeline (asset-события
  CREATED/GONE/REAPPEARED → `new_asset`/`asset_gone`/`asset_reappeared`,
  секция `assets`; `AssetStore.project_events`). conftest изолирует
  `assets.db`. Покрыто `test_asset_*`/`test_assets_tab`/`test_web_assets` +
  расширены `test_timeline`/`test_report_export`.

**Company / Workspace tier (эпик F-C1→F-C4) — `[ЗАКРЫТ]`.** Слой группировки
НАД проектами как логический ярлык, НЕ уровень каталогов (раскладка
`Projects/<slug>/` и scoped-id-контракты не тронуты, миграции нет):
- **F-C1** ядро: `core/company.py` (`CompanyRegistry` — тонкий `data/companies.json`
  только имена/атрибуты, НЕ membership; `company_slug`; `UNASSIGNED`;
  `group_projects` derive-on-read), membership = ключ `company` в `metadata.json`
  проекта (`Project.get/set_company`, RMW как `monitor`), `ProjectStore.companies()/
  assign()`.
- **F-C2** аналитика: `build_company_rollup` (поверх `portfolio.build_portfolio`,
  без пересчёта) + `load_company_view`; общий `portfolio.active_findings_map()`.
- **F-C3** GUI: Overview-вкладка — таблица сводки по компаниям, клик фильтрует
  таблицу проектов, контрол назначения (editable combo → registry.create +
  assign, off-thread).
- **F-C4** web-паритет: `GET /companies` + `POST /projects/{slug}/company`,
  кнопка «Companies» в консоли.

**Cross-Entity Correlation (эпик F-K1→F-K4) — `[ЗАКРЫТ]`.** Связь
findings↔assets↔infra **вычисляется (derive-on-read)** по уже существующим
ключам, без новой таблицы/схемы (как F2/F5/Company):
- **F-K1** ядро: `core/correlation.py` — `build_correlation(findings, assets)`
  (джойн `Finding.evidence.location`→endpoint-актив, host→subdomain/domain,
  цепочка через `attrs`: subdomain.ip→ip.asn→asn) → `finding_chains`,
  `asset_findings` (direct + severity-counts + worst), `exposure` (host-активы с
  закаченными находками эндпоинтов, worst-first), `summary`;
  `load_correlation(project)` — тонкий ридер (active findings + assets).
- **F-K2** отчёт: карточка «Exposure by Asset» (`_build_correlation` +
  `_render_correlation_card` в `collection_runner`).
- **F-K3** GUI: детали Findings-вкладки → «Цепочка: endpoint→host→ip→asn»;
  детали Assets-вкладки → «Связанные находки: N (worst …)».
- **F-K4** web: `GET /correlation?project=…` + кнопка «Correlation» в консоли.

**Finding Objects (эпик F-O1→F-O4) — `[ЗАКРЫТ]`.** description/impact/
remediation как **чистый offline-каталог, резолвящийся на чтении** (derive-on-read,
как `findings_sla`) — без миграции схемы, без изменения fingerprint, сканеры почти
не тронуты:
- **F-O1** `core/finding_knowledge.py` — per-category каталог + rule-specifics +
  generic-фоллбэк; `describe(category, rule_id, title, evidence)` (explicit
  evidence → rule → category → generic); `annotate(findings)`.
- **F-O2** захват explicit-текста: `findings_adapter.Finding` +опц.
  description/impact/remediation (в evidence при наличии); `parse_nuclei_jsonl`
  тащит `info.description/impact/remediation` (реальный remediation от nuclei).
- **F-O3** поверхности: GUI Findings-деталь (Описание/Воздействие/Remediation);
  `report_export.findings_csv` +колонки (DefectDojo-style экспорт).
- **F-O4** web: `/findings` обогащается каталогом рядом с SLA.

**Executive Headline (бэклог п.3) — `[ЗАКРЫТ]`.** `executive_summary.headline()`
(приоритизированные чипы «что важно за 10 сек», Cortex-Xpanse-стиль) →
chip-строка в report.html (`render_html`) + в Dashboard Security Overview
(FlowLayout цветных меток). Web-паритет автоматом (консоль отдаёт тот же
report.html). Чистый derive, без новых зависимостей.

**IA Menu Consolidation (бэклог п.4) — `[ЗАКРЫТ, безопасный срез]`.**
Консолидация nav-рельса **группировкой**, БЕЗ слияния/удаления вкладок —
контракт плагинов (I4/I7) и тесты целы: `TabPlugin` += опц. `section`/`position`
(обратносовместимо), `BUILTIN_TABS` переупорядочены в кластеры (Обзор→Разведка→
Безопасность→Управление→Отчёты→Инструменты→Система) и размечены; `build_into`
прокидывает хинты (fallback на 2-арг addTab); `FluentWindowTabs.addTab` рисует
разделитель на смене TOP-секции и якорит `position='bottom'` (System/История)
вниз рельса; отложенная стартовая подгрузка первой вкладки (singleShot — в
headless-тестах не стреляет). **Вне scope (ломает контракт, отложено):** слияние
вкладок в под-табы, вынос Video/Image/Clone из главного UI.

**Risk Engine deepening (F-R1→F-R3) — `[ЗАКРЫТ]`.** Фаза «внутренности до идеала,
GUI не трогаем» (память `feedback-internals-first-no-gui`). `executive_summary`
переведён на **объяснимый взвешенный скоринг**: `RISK_WEIGHTS`-таблица +
`_risk_factors()` (именованные вклады `{factor,count,weight,points,detail}`,
score = Σ points — числа для старых сигналов байт-в-байт прежние). Закрыта дыра:
**GraphQL introspection** теперь весит в score (×4) и форсит ≥High в `_risk_level`
(reachable-only GraphQL по-прежнему 0). Объяснимость в отчёте: блок «Из чего риск»
в `render_html`. `build_summary` остался pure над report; раскладка report.json и
`risk_100`/`RISK_ORDER` целы; новый ключ `summary['risk_factors']` аддитивен.

**Correlation deepening (F-K5→F-K7) — `[ЗАКРЫТ]`.** Backend-фаза. Углублён
`core/correlation.py`: **F-K5** apex-домен резолвит полную инфра-цепочку
(`asset_adapter`: domain-актив получил `attrs.ip`/`asn`); **F-K6** netblock-
вложенность в цепочке (`_netblock_for`: ip ∈ cidr через stdlib `ipaddress`,
longest-prefix); **F-K7** инфра-exposure «blast radius» (`_build_infra_exposure`:
свёртка находок вверх по ip/asn/netblock → `infra_exposure` в выводе, секция в
отчётной карточке, web `/correlation` тащит автоматом). Pure, без новых
зависимостей, identity/схемы целы.

**Findings SLA & lifecycle deepening (F-S1→F-S5) — `[ЗАКРЫТ]`.** Backend-фаза
(internals-first, GUI не перестраиваем — память `feedback-internals-first-no-gui`).
Всё pure / derive-on-read, без миграции схемы, сигнатуры аддитивны (I7):
- **F-S1** `core/findings_sla.py`: **SLA-часы рестартятся при reopen** — reference
  = `max(first_seen, last_reopened)` (`_reference`; DefectDojo-семантика: дедлайн
  считается от текущего открытого эпизода, исходный `first_seen_at` сохранён для
  истории). Раньше переоткрытая старая находка мгновенно «просрочена» — закрыто.
  Классификатор `sla_bucket` (breached/due_soon/on_track; `SLA_WARN_DAYS=7`),
  агрегат `sla_summary` (счётчики бакетов + разбивка по severity + aging-гистограмма),
  `sla_events` (находки в просрочке как timeline-события — время-, не скан-
  триггерные). `annotate`/`breached_count` получили опц. `reopened` map.
- **F-S2** `core/findings_store.py`: `reopen_dates(project)` — read-примитив
  `finding_id → ts последнего REOPENED` (питает reopen-aware SLA-часы; только
  реально переоткрытые попадают, иначе fallback на `first_seen`).
- **F-S3** `core/timeline.py`: `build_events` принял опц. `sla_events`;
  `build_timeline` деривит просрочки активных находок (reopen-aware) → лента; ярлык
  `sla_breach` в `gui/tab_timeline._EVENT_LABELS`.
- **F-S4** тонкая проводка: `reopened` прокинут в web `/findings`, GUI Findings-таб,
  карточку отчёта (`collection_runner` → `report['findings']['sla']` = `sla_summary`,
  показ breached + due_soon в карточке).
- **F-S5** тесты: reopen-рестарт/reference-max, бакеты, summary+aging, sla_events,
  `reopen_dates` (latest+project-scope), мердж в timeline. Алерт-канал для SLA-
  просрочки **отложен** (нужна персистентность «было/стало» чтобы не алертить
  каждый прогон — конфликт с derive-on-read; timeline-событие — верная поверхность).

**Risk ↔ infra concentration (F-R4) — `[ЗАКРЫТ]`.** Backend-фаза. Связал F-K7
«blast radius» с risk-движком: `executive_summary._infra_concentration(report)`
(pure над `report['correlation'].infra_exposure` — уже деривится ДО build_summary
в `collection_runner.run`: sync→correlation→summary) считает инфра-узлы (ip/asn/
netblock), концентрирующие находки на **≥2 хостах** = структурные single-points-
of-exposure. Новый взвешенный фактор «Концентрация на инфраструктуре»
(`RISK_WEIGHTS['infra_concentration']=2`, count×weight, worst-узел в detail) →
аддитивен в score и в таблицу «Из чего риск»; метрика `infra_concentration` +
чип «N× shared infra» (medium) в headline. `_risk_level` НЕ тронут (амплификатор,
не clear-cut). Старые числа байт-в-байт (фактор=0 без correlation/одно-хостовых
узлов). Покрыто `test_executive_summary` (фактор/score/headline/отсутствие).

**Asset coverage & attrs (F-A1) — `[ЗАКРЫТ]`.** Backend-фаза. `asset_adapter.
derive_assets` обогащён атрибутами, которые УЖЕ были в report, но дропались (pure
derive, identity не тронута → ноль churn в сторе; `asset_store.upsert` рефрешит
attrs через COALESCE): **domain** — TLS-факты из фазы `certificate` (`tls_issuer`/
`tls_subject`/`tls_not_after`/`tls_sans` через `_split_sans`) + `provider`/`location`;
**subdomain** — данные active-пробы (`cname`/`service`/`takeover`/`server`/
`http_status`/`title`/`status`, только непустые через `_present`, takeover лишь при
True); **ip**/**asn** — `provider`/`location`/`org` из infrastructure. Детали видны
в Assets-табе автоматически (рендер attrs generic). Покрыто `test_asset_adapter`
(TLS/probe/provider + identity-инвариант).

**Asset per-source lifecycle gating (F-A2, хвост F-A1) — `[ЗАКРЫТ]`.** Backend-фаза.
Закрыт отложенный F-A1: cert-SAN и CT-имена (crt.sh) теперь **первоклассные
subdomain-активы**, а не только `domain.attrs.tls_sans`. Раньше блокировал churn —
`asset_store.sync` гейтил GONE по **типу** (`any(phase ran)`), поэтому cert-only
субдомен мигал бы GONE/REAPPEARED, когда cert-фаза пропущена, а active-subdomains
гонялась. Фикс: гейтинг **по source**. Каждый актив уже несёт `attrs['source']` =
имя продьюсящей фазы (recon/subdomains/certificate/ct/asn_intel/katana/openapi), и
эти строки = имена фаз → `AssetStore.sync` получил опц. `source_in_scope(source)`
(новый `_gone_in_scope`: source-гейт приоритетно, fallback на type-гейт для legacy-
строк без source; back-compat — старый `in_scope`-контракт цел при
`source_in_scope=None`). `collection_runner._sync_assets` строит
`source_in_scope=phase_ok(source)`. `asset_adapter.derive_assets`: cert SANs →
`source='certificate'`, CT `names` → `source='ct'` (фильтр `_is_concrete_host`:
концертный host в пределах apex, без wildcard/apex/чужих multi-SAN доменов);
active-проба выигрывает identity (first-occurrence, богаче attrs). Endpoint-гейтинг
заодно стал точнее (katana-эндпоинт GONE только если katana гонялась, не
`any(katana|openapi)`). Identity не тронута → ноль churn. Покрыто
`test_asset_adapter` (cert/CT promotion, apex/wildcard/out-of-scope drop, probe
wins) + `test_asset_store` (per-source no-flap + fallback).

**GraphQL in Scan Diff / Timeline (F2 хвост) — `[ЗАКРЫТ]`.** Backend-фаза. Закрыт
отложенный с F2 GRAPHQL: GraphQL-экспозиция теперь диффится между сканами и течёт
в Timeline + Alert Center. Раньше SecurityAuditor считал `graphql`/`graphql_
introspection` только для risk-score, но `scan_diff` не имел секции `security` →
открывшаяся схема не порождала событий. Добавлена секция `graphql` (фаза-источник
`security`): `_extract_graphql` (per-endpoint `url → 'introspection on'|'reachable'`,
field-compare как headers/dns → переход reachable→open виден как *changed*, не
молчаливый re-discovery). События в общем `diff_events`: `new_graphql` (medium,
timeline-only — surface discovery как `new_endpoint`) и `graphql_introspection`
(high — добавленный уже-открытый эндпоинт ИЛИ переход reachable→open; матчит
risk-движок, форсящий ≥High на открытой интроспекции). `graphql_introspection`
добавлен в `alerts.ALERT_TYPES` (алертится — схема открылась = регрессия), `new_
graphql` остаётся timeline-only. Метки в `gui/tab_timeline._EVENT_LABELS` (label-
константа, прецедент F-S3). Pure, без новых зависимостей, контракт diff/alerts/
timeline цел. Покрыто `test_scan_diff` (added+introspection-flip, skip без фазы) +
`test_diff_events` (классификация + alertable-подмножество).

**SLA-breach alert-канал (F-S6, хвост F-S5) — `[ЗАКРЫТ]`.** Backend-фаза. Закрыт
отложенный в F-S5 алерт-канал для просрочки SLA. Проблема была: просрочка
*время*-, не скан-триггерная (находка пробивает дедлайн сама по себе), а derive-on-
read не знает «было/стало» → наивный алерт стрелял бы каждый прогон. Решение —
**one-shot маркер в существующей events-таблице** (без новой таблицы/схемы):
`findings_store` += event-тип `SLA_BREACH` + `record_sla_breaches(project, ids)`
(логирует маркер раз на просрочку, возвращает только новые id; **эпизод-аккуратно**
— маркер старше последнего `REOPENED` не считается, поэтому переоткрытая-и-снова-
просроченная находка алертится заново). `alerts`: `collect_sla_alerts(store,
project)` (детект через `findings_sla.sla_status` reopen-aware → дедуп через стор →
lean-события только для новых), `notify_sla` (types-фильтр + общий `_send`-хвост,
выделенный из `notify`; журнал доставки kind='sla'); `sla_breach` в `ALERT_TYPES`.
`monitor.run_project` зовёт `_dispatch_sla_alerts` каждый успешный прогон
**независимо от диффа** (просрочка диффом не ловится); `result['sla_alerts']`
аддитивен. Pure-детект отделён от транспорта (стор инжектится → тесты на temp-БД).
Покрыто `test_findings_store` (one-shot + reopen-reset + dedup), `test_alerts`
(collect new→deduped, within-window пусто, notify_sla dispatch/filter/disabled),
`test_monitor` (run_project шлёт раз, второй прогон молчит). **Все 3 именованных
backend-пункта закрыты (F-A2, GraphQL-timeline, F-S6).**

**Scanner robustness (F-SR1) — `[ЗАКРЫТ]`.** Backend-фаза. Закалка pure-точек
входа детект-движков на битый ввод (degrade-not-raise). Аудит показал, что
сетевые парсеры (`osv_correlation`/`asn_intel`/`graphql_discovery`) уже хорошо
защищены (guarded json+isinstance) — реальные дыры были в pure-функциях,
принимающих corpus от вызывающего: `dependency_audit.detect_libraries` и
`tech_fingerprint.fingerprint` падали на `'\n'.join(scripts)`, если в списке
не-строка (None/dict/bytes) → теперь нестроки скипаются, не-str html → ''.
`tech_fingerprint._norm_headers` терпит не-dict headers (list → {} вместо
AttributeError). `dependency_audit.render_html` выбор worst-severity переведён
с `tuple.index` (ValueError на чужой severity) на rank-dict с дефолтом. Покрыто
`test_dependency_audit`/`test_tech_fingerprint` (нестроки/bytes/не-dict/чужой
severity — деградация без падения).

**Risk ↔ SLA breach (F-R5) — `[ЗАКРЫТ]`.** Backend-фаза. Связал F-S «просроченная
ремедиация» с risk-движком: `executive_summary._sla_breaches(report)` (pure над
`report['findings']['sla']` — уже стампится `_sync_findings` ДО build_summary в
`collection_runner.run`: sync→correlation→summary) считает активные находки с
просроченным SLA-окном (DefectDojo-семантика, reopen-aware — из `findings_sla.
sla_summary`). Просрочка = команда **знала** о находке после дедлайна и не закрыла
→ хуже свежей того же severity, поэтому лёгкая надбавка ПОВЕРХ severity-веса (уже
посчитанного через vuln_score). Новый взвешенный фактор «Просроченная ремедиация
(SLA)» (`RISK_WEIGHTS['sla_breach']=1`, count×weight, худший overdue severity в
detail) → аддитивен в score и в таблицу «Из чего риск»; метрика `sla_breaches` +
чип «N× SLA overdue» (high) в headline. `_risk_level` НЕ тронут (амплификатор, как
infra_concentration). Старые числа байт-в-байт (фактор=0 без `report['findings']`/
нулевой breached → старые отчёты и тесты деградируют в 0). Покрыто
`test_executive_summary` (надбавка/score/amplifier-not-clearcut/headline/отсутствие).

**Risk ↔ cert expiry (F-R6) — `[ЗАКРЫТ]`.** Backend-фаза. Закрыл пробел: TLS-факты
УЖЕ собирались (`cert_info`→`report['phases']['certificate'].data.not_after`,
`tls_not_after` на domain-активах, `expired_count` в CT-истории), но истечение
leaf-сертификата нигде не вливалось в risk. `executive_summary._cert_expiry(report,
now=None)` (pure derive, инжектируемый `now` для детерминизма) флагует **истёкший**
ИЛИ истекающий в пределах `CERT_EXPIRY_WARN_DAYS=14` сертификат; толерантный
`_parse_cert_date` (ISO / OpenSSL-«Aug  1 00:00:00 2026 GMT» / `%b %d %Y`,
degrade→None на битом, F-SR1-этос). Новый лёгкий взвешенный фактор «TLS-сертификат
истёк/истекает» (`RISK_WEIGHTS['cert_expiry']=2`) → аддитивен в score и в таблицу
«Из чего риск»; метрики `cert_expiry`/`cert_expired` + чип «Cert expired» (high) /
«Cert expiring» (medium) в headline. `_risk_level` НЕ тронут (амплификатор, как
infra/SLA). Старые числа байт-в-байт (0 без certificate-фазы/непарсимой даты).
Покрыто `test_executive_summary` (parse-форматы/классификация по injected-now/
фактор+чип/amplifier-not-clearcut/отсутствие). **Хвост F-R6 — cert expiry в
Diff/Timeline/Alerts** `[ЗАКРЫТ]`: `_parse_cert_date`→**публичный** `parse_cert_date`
+ единый классификатор `cert_expiry_status(not_after, ref)` (источник правды порога,
шарится risk-фактором и diff'ом; `_cert_expiry` отрефакторён через общий
`_cert_status_days`). `scan_diff._extract_certificate` добавляет **синтетическое**
поле `expiry` (valid/expiring/expired), оцениваемое против **времени самого скана**
(`report['started_at']`, а не «сегодня» — исторический дифф корректен) → переход
valid→expiring→expired виден как *changed* (рефреш-сертификат→valid НЕ событие).
`diff_events`: `cert_expired` (high) / `cert_expiring` (medium) из added/changed
`expiry` (generic `cert_change` для прочих полей цел). `cert_expired` в
`alerts.ALERT_TYPES` (diff-триггер → дедуп естественный, одно событие на переход —
без one-shot-маркера как F-S6); `cert_expiring` timeline-only (как `new_graphql`).
Метки в `gui/tab_timeline._EVENT_LABELS` + подпись в `gui/dialogs` (fallback на raw
ключ цел). Web-паритет автоматом (общий `diff_events`→`extract_alerts`/timeline).
Покрыто `test_scan_diff` (статус по scan-time/переход/рефреш-флип) + `test_diff_events`
(классификация added+changed, рефреш=не-событие, alertable-подмножество).

**Risk ↔ regression (F-R7) — `[ЗАКРЫТ]`.** Backend-фаза. Связал F1-lifecycle
«переоткрытая находка» с risk-движком: `executive_summary._reopened_regressions(report)`
(pure над `report['findings']['reopened']` — per-scan счётчик, который
`_sync_findings` УЖЕ стампит из `FindingsStore.sync()['reopened']`; правка
collection_runner НЕ нужна, как F-R5 с `sla`) считает находки, которые были
auto-FIXED и вернулись (REOPENED) в этом скане. Регрессия = прошлый фикс не
удержался → хуже свежей находки того же severity, поэтому лёгкая надбавка ПОВЕРХ
severity-веса (переоткрытая снова OPEN → уже в vuln_score). Новый взвешенный фактор
«Регрессия (переоткрытые находки)» (`RISK_WEIGHTS['regression']=2`, count×weight) →
аддитивен в score и в таблицу «Из чего риск»; метрика `regressions` + чип
«N× regression» (high) в headline. `_risk_level` НЕ тронут (амплификатор, как
infra/SLA/cert). Семантика per-scan: «регрессировало в этом скане» (как diff-
триггер — следующий скан, если всё ещё OPEN но не переоткрыто заново, надбавки нет;
обычная активная находка уже в score). Старые числа байт-в-байт (0 без
`report['findings']`). Карточка findings в report уже показывает `reopened`. Покрыто
`test_executive_summary` (надбавка/score/amplifier-not-clearcut/headline/отсутствие).

**Security signals → attack-surface + Full Collection (F-SEC1) — `[ЗАКРЫТ]`.**
Backend-фаза, два связанных инкремента. **(1) Attack-surface graph**:
`attack_surface.build_surface` получил две risk-несущие категории, которые
risk-движок УЖЕ считал, но граф ронял — **Source Maps** (отданные `.map` с
`has_content` — только реальная утечка) и **GraphQL** (достижимые эндпоинты,
`[introspection]` в тултипе). Читаются из `phases.security.data.{source_maps,
graphql}` — тот же контракт, что `executive_summary`/`scan_diff` (I3, без
повторного зондирования); вес 3 в `surface_score` (risk-несущие, как Findings/
Source Maps), цвет GraphQL `#512da8`. **(2) Security-фаза в Full Collection**:
раньше `phases.security` писал только standalone SecurityAuditor (GUI/web tab),
поэтому source-map/GraphQL-сигналы в обычном скане были 0. Заведена opt-in фаза
`security` в `CollectionRunner` (флаг `security=False`, мирроринг osv/asn:
`__init__`/`configure`/`run` фаза 7a сразу после vulns, `_phase_security` →
`SecurityAuditor.audit` → `phases.security.data` = полный audit-результат, артефакт
`security/audit.json`, карточка отчёта «Security Audit» с утёкшими maps + GraphQL).
SecurityAuditor-секреты в risk НЕ вливаются (secrets идут из `api.keys_found` —
без двойного счёта); фаза питает только source-map/GraphQL-сигналы +
attack-surface. Проводка-паритет: `monitor._build_run_fn` (`security=opts.get(...)`),
чекбокс «Security audit (JS/maps/GraphQL)» в Collection + `_collection_options`.
Web-консоль намеренно гоняет базовый пайплайн (все opt-in off) → web-правок нет
(как osv/asn). Opt-in решение — память пользователя (GraphQL активно зондирует
пути; дефолтный пайплайн остаётся быстрым).

**Хвост F-SEC2 — source-map/GraphQL как полноценные F1-находки `[ЗАКРЫТ]`.**
Решение пользователя: «F1-находки, без дубля score». Risk-несущие экспозиции
аудита теперь **первоклассные findings** (персист, lifecycle, SLA, триаж), а не
только метрики: `collection_runner._security_findings(data)` синтезирует raw-
находки (утёкший source map → **High**, GraphQL introspection → **High**,
reachable-only GraphQL → **Info**; канонические `category='sourcemap'/'graphql'`
из `finding_fingerprint.CATEGORIES` + `location=url` → стабильная Findings-
identity, одна на URL; категория — часть fingerprint, поэтому каноническое имя
важно) и фолдит их в
`vulns['findings']` + ресуммирует (паттерн `_phase_dns`) → они идут через F1-sync
(`_sync_findings`) и считаются в risk через severity (vuln_score). **Двойной счёт
разведён:** из `executive_summary` убраны выделенные score-факторы
`source_map_leaks`/`graphql_introspection` (+ ключи из `RISK_WEIGHTS`) — сигнал
считается один раз через находку. **Сохранено** (display, не score): metrics
`source_map_leaks`/`graphql`/`graphql_introspection` (heatmap/headline читают из
metadata), `_risk_level` graphql-force (level-гейт, не score-адденд),
recommendations/key_findings. `attack_surface`: категории Source Maps/GraphQL
**остались**, но findings с `category in (source-map,graphql)` исключены из общей
категории «Findings» → нет дубля в surface_score. **Числа risk изменились
сознательно** (одинокий source-map leak теперь High-находка → level High через
`high>=1`; reachable GraphQL +1 Info). Покрыто `test_attack_surface`
(Source Maps/GraphQL категории + score + exclude-из-Findings), `test_collection_runner`
(фолд severity/identity + reachable=Info), `test_executive_summary` (метрика
сохранена/фактор убран/level сохранён), `test_monitor` (проброс флага).
**Finding Objects (F-O) автоматом:** канонические категории `sourcemap`/`graphql`
УЖЕ есть в каталоге `finding_knowledge._CATEGORY` (+ rule-specific `introspection`)
→ description/impact/remediation резолвятся в specific-знание (не generic) в GUI/
CSV/web без правок каталога. Покрыто `test_finding_knowledge`.

**Diff-coverage добивка — Source maps & Cookies в Scan Diff/Timeline/Alerts
`[ЗАКРЫТ]`.** Backend-фаза, два инкремента по образцу «GraphQL в Scan Diff»
(risk-несущий сигнал считался, но не диффился → не порождал событий). **(1)
Source maps:** секция `sourcemap` (фаза-источник `security`, `_extract_sourcemap`
сёрфит только утёкшие карты `has_content` по URL; set-like, added-only — карта,
переставшая течь, просто выпадает) → `diff_events` эмитит `new_sourcemap` (high,
alertable, как открытая GraphQL-схема). **(2) Cookies:** секция `cookies`
(фаза-источник `cookies`, `_extract_cookies` keyed by name, value = verdict аудита
через generic header-style label/changed → cookie, потерявшая Secure/HttpOnly/
SameSite, видна как *changed* Strong/Moderate→Weak, не churn) → `cookie_weakened`
(high, **alertable** — регрессия) на degrade и `weak_cookie` (medium,
timeline-only — discovery, как `new_graphql`) на ново-поданную слабую cookie.
Метки в `gui/tab_timeline._EVENT_LABELS` + Settings alert-types (`gui/dialogs`,
fallback на raw-ключ цел). Pure, без новых зависимостей; контракт diff/alerts/
timeline цел. Покрыто `test_scan_diff` (added+has_content-гейт / degrade=changed+
newly-weak=added / skip без фазы) и `test_diff_events` (классификация + alertable-
подмножество). Web-паритет автоматом (общий `diff_events`→`extract_alerts`/timeline).
**(3) Weak Cookies в attack-surface** `[ЗАКРЫТ]`: тот же асимметричный пробел, что
F-SEC1 закрыл для Source Maps/GraphQL — слабые cookie risk-несущие (вес 2) и теперь
диффятся, но граф атак-поверхности их ронял. `attack_surface.build_surface` получил
категорию «Weak Cookies» (сёрфит только cookie с verdict=Weak из
`phases.cookies.data.cookies`; strong/moderate — не attack surface, как source_maps
сёрфит только утёкшие); `_SCORE_WEIGHTS['Weak Cookies']=2` (risk-несущий, ниже
source-map/findings-тира). Pure. Покрыто `test_attack_surface` (weak-only,
omit-when-none, score). Cookie-колонка в exposure-heatmap уже была (метрика
`weak_cookies`).

**Weak-cookie risk double-count — `[ЗАКРЫТ]`.** Backend-фаза, замыкает
cookie-паритет на последней поверхности (risk-score). Слабая cookie считалась
**дважды**: как Medium-находка от `VulnScanner._check_cookies` (вес 2 в
`vuln_score`) И повторно как выделенный фактор `weak_cookies` (вес 2) → 4 очка
вместо 2. Приведено к принципу F-SEC2 (source-maps/GraphQL): risk-несущая
экспозиция, ставшая первоклассной находкой, считается **один раз** через
severity, не вторым выделенным фактором. Убран `weak_cookies` из `RISK_WEIGHTS`
и фактор «Слабые cookie» из `_risk_factors`; **display-метрика** `weak_cookies`
(heatmap/headline-чип/key_findings/recommendations) не тронута. Числа риска для
cookie-насыщенных целей **снизились сознательно** (как F-SEC2). Тест-хелпер
`test_executive_summary._report` теперь моделирует слабые cookie как Medium-
находки (числа скоринга совпадают с продакшеном); добавлен регресс-тест
no-double-count. Покрыто `test_executive_summary`.

**Weak-cookie attack-surface double-count — `[ЗАКРЫТ]`.** Backend-фаза,
тот же дефект, но во **второй** оси (surface_score, не risk). Категория
«Findings» в `attack_surface.build_surface` уже исключала source-map/GraphQL-
находки, чтобы не дублировать их выделенные категории, но для cookie был пробел:
cookie verdict=Weak попадала и в «Weak Cookies» (вес 2), и её находка от
`VulnScanner._check_cookies` — в «Findings» (вес 3) → 5 очков охвата на cookie
вместо 2. Фикс: cookie-находки помечены канонической `category='cookie'`
(адаптер УЖЕ выводил её из title → fingerprint байт-в-байт, ноль churn в сторе),
и `'cookie'` добавлена в исключающий кортеж «Findings» рядом с
sourcemap/graphql. Cookie SameSite=None-without-Secure всегда score≤1 → всегда
Weak → уже представлена в «Weak Cookies», сигнал не теряется. Покрыто
`test_attack_surface` (расширен exclude-тест) + `test_vuln_scanner`
(category на High/Medium cookie-находках).

**Vulnerable-dependency в Timeline/Alerts — `[ЗАКРЫТ]`.** Backend-фаза, тот же
асимметричный пробел (risk-несущий сигнал диффился, но не порождал событий), что
закрыт для cookies/source-maps. Секция `dependencies` уже диффилась (с флагом
`⚠ vulnerable` на каждой либе), но `diff_events` не имел обработчика → ново-
поданная известно-уязвимая JS-либа (или существующая, ставшая уязвимой при
матче нового CVE на её версию) не давала ни timeline-события, ни алерта (только
слабый косвенный `risk_increase`). Добавлены два события поверх существующих
diff-данных (без повторного зондирования, без списка имён — `⚠` уже в
label/changed): `new_vulnerable_dependency` (уязвимая либа появилась) и
`dependency_vulnerable` (существующая деградировала до уязвимой). Оба high и
**alertable** — матч CVE = явный новый риск, как ново-утёкший source map.
`EVENT_SEVERITY` + `alerts.ALERT_TYPES` расширены; метки в
`gui/tab_timeline._EVENT_LABELS` и в Settings alert-types (`gui/dialogs`).
Pure, контракт diff/alerts/timeline цел, web-паритет автоматом. Покрыто
`test_diff_events` (классификация + alertable-подмножество) и `test_scan_diff`
(end-to-end: added vulnerable → label → событие).

**Security-header regression в Timeline/Alerts — `[ЗАКРЫТ]`.** Backend-фаза, тот
же асимметричный пробел, что закрыт для cookies/source-maps/dependencies. Убранный
security-заголовок (HSTS/CSP/X-Frame-Options…) — регрессировавшая защита, но
сёрфился слабо: через сменившуюся находку «Missing security headers (N)» (без
события) + возможный косвенный `risk_increase`. `diff_events` теперь эмитит
`security_header_removed` (high, **alertable**), когда security-заголовок был в
скане A и пропал в B. Ново-поданный/сменивший значение заголовок — НЕ регрессия
(скип): добавление = улучшение, смену значения нельзя обобщённо счесть ослаблением.
**SSOT-рефактор:** словарь security-заголовков вынесен из `recon_engine` в новый
чистый `core/security_headers.py` (`SECURITY_HEADER_NAMES`), чтобы offline-
`scan_diff` шарил единый источник без тяжёлой цепочки импортов recon (recon
импортирует оттуда; usage не изменился). `EVENT_SEVERITY` + `alerts.ALERT_TYPES`
расширены; метки в `gui/tab_timeline._EVENT_LABELS` и Settings alert-types
(`gui/dialogs`). recon хранит имена в lower-case → матч без доп. нормализации.
Pure, web-паритет автоматом. Покрыто `test_diff_events` (классификация +
не-security removal игнор + alertable) и `test_scan_diff` (end-to-end removal →
label → событие).

**Subdomain takeover → first-class finding — `[ЗАКРЫТ]`.** Backend-фаза, решение
пользователя. Кандидат на takeover (субдомен, CNAME-ящий на неактивный сторонний
сервис) был только risk-фактором + метрикой — не персистился как находка (нет
lifecycle/SLA/triage). Теперь каждый кандидат фолдится в vuln-фазу как **High**-
находка (`category='takeover'`, `location=host`) сразу после subdomain-фазы — тот
же паттерн, что security-audit экспозиции (`CollectionRunner._takeover_findings` +
инлайн-фолд в `run`). **Считается один раз** через severity находки, не вторым
выделенным фактором: вес `takeovers` убран из `RISK_WEIGHTS`/`_risk_factors`.
**Вердикт не изменился** — `_risk_level` по-прежнему форсит Critical на любом
takeover (clear-cut level-гейт, как GraphQL introspection форсит High); меняется
лишь raw-score за takeover (High=5 через находку вместо 8 через фактор). Метрика
`takeovers`, рекомендация и headline-чип сохранены. `'takeover'` добавлен в
канон-вокабуляр `finding_fingerprint.CATEGORIES` и каталог `finding_knowledge`
(description/impact/remediation). Двойного счёта в attack-surface нет: «Subdomains»
= breadth (все субдомены), takeover-находка идёт в «Findings» — разные оси (как
dependencies vs Technologies, не как cookies). Покрыто `test_collection_runner`
(High/host-located/empty) и `test_executive_summary` (Critical-force + score=2×High
+ нет фактора).

**Takeovers как attack-surface категория — `[ЗАКРЫТ]`.** Backend-фаза, хвост
takeover-находок: достроил параллель с Source Maps/GraphQL/Weak Cookies в графе
атак-поверхности. Takeover — risk-несущее подмножество субдоменов (форма как
«Weak Cookies» vs cookies), но в surface_score шёл только как breadth «Subdomains»
(вес 2) + «Findings» (вес 3). Заведена отдельная категория «Takeovers»
(`attack_surface.build_surface` сёрфит `subdomains.summary.takeover_candidates`),
вес `_SCORE_WEIGHTS['Takeovers']=5` (top-tier, как Secrets — takeover самый
тяжёлый одиночный exposure), цвет `#b71c1c`. Хост ОСТАЁТСЯ в «Subdomains»
(breadth/presence — отдельное измерение, как уязвимая либа в «Technologies»), но
takeover-находка **исключена из «Findings»** (рядом с sourcemap/graphql/cookie),
чтобы не дублировать в surface_score. Итог per-takeover: было 2(Subdomains)+
3(Findings)=5, стало 2(Subdomains)+5(Takeovers)=7 — точнее отражает критичность
(меняется метрика surface_score/сортировка, НЕ risk-вердикт). Pure. Покрыто
`test_attack_surface` (своя категория + остаётся в Subdomains + omit-when-none +
exclude-из-Findings + вес).

**Auto-FIX scope-guard для opt-in источников — `[ЗАКРЫТ, баг-фикс]`.** Backend-фаза.
`_sync_findings.in_scope(source)` гейтит авто-FIX находки по тому, отработала ли
её **фаза-продьюсер** (пропущенная opt-in фаза ≠ «исправлено»). Маппинг покрывал
`dns`/`nuclei`/`dependency-audit`, а всё прочее падало в дефолт `phase_ok('vulns')`
(vulns всегда идёт). Из-за этого находки с источником из **opt-in**-фаз авто-
FIXились, когда их фаза просто не запускалась: `subdomain-active` (takeover, фаза
subdomains) и `security-audit` (source-map/GraphQL, фаза security). Симптом —
**флаппинг FIXED/REOPENED** между сканами (ложный lifecycle, сброс SLA, ложные
regression-алерты) в зависимости от того, включил ли пользователь opt-in фазу.
Фикс: `in_scope` маппит `security-audit`→`phase_ok('security')`,
`subdomain-active`→`phase_ok('subdomains')`. Затрагивает мою takeover-находку и
ретроактивно F-SEC2 source-map/GraphQL. Cookie/header-находки идут из always-on
vulns → дефолт корректен (не тронут). OSV-нюанс (`dependency-audit` из opt-in osv)
оставлен — это документированный accepted churn вытеснения. Покрыто
`test_findings_lifecycle` (takeover ran→FIXED / skipped→OPEN; source-map
skipped→OPEN).

**Secret confidence в risk-движке + Scan Diff/Alerts — `[ЗАКРЫТ]`.** Backend-фаза.
Закрыт перекос точности: `api`-фаза отдавала плоский `keys_found`, и
`executive_summary._risk_level` форсил **Critical** на `secrets>0` — но
`api_key_extractor` НЕ прогонял структурный валидатор, поэтому плейсхолдер вроде
`your_api_key_here` (который `secret_validator._generic` метит `invalid_format`)
форсил Critical как реальный ключ. **#1 risk:** новый pure
`executive_summary._plausible_secrets(api)` (derive-on-read над `api['details']` —
значения уже там, без ре-фетча, I3; переиспользует SSOT `core.secret_validator`)
отбрасывает явные плейсхолдеры (`invalid_format`) из risk-несущего счёта;
`valid_format`+`unverifiable` считаются. `secrets` (метрика/гейт/фактор/headline/
key_findings/recommendation) = plausible; добавлена метрика `secrets_detected`
(сырой счёт) + пометка в key_finding, когда часть подавлена. Легаси-отчёты без
`details` → fallback на `keys_found`, поведение байт-в-байт. **#2 diff/alerts:**
`scan_diff._extract_secrets` валидирует каждый `(type,value)` и метит плейсхолдер-
лейбл `⚠ placeholder` (виден в HTML-диффе, трюк как `⚠ takeover` у субдоменов);
`diff_events` эмитит `new_secret` только для не-плейсхолдеров → ложно-позитивный
«секрет» больше не алертит и не шумит в Timeline (в HTML-диффе всё ещё показан с
пометкой). `alerts.py` не тронут (`new_secret` уже алертабелен; плейсхолдеры просто
не эмитятся). Числа risk для целей с плейсхолдер-«секретами» снизились сознательно
(как F-SEC2). attack-surface «Secrets» (breadth) оставлен как есть — отдельная ось.
Покрыто `test_executive_summary` (плейсхолдер не форсит Critical / plausible форсит /
mixed только plausible / легаси без details), `test_scan_diff` (пометка+не-алертабелен),
`test_diff_events` (плейсхолдер не событие).

**Per-type secret severity (хвост secret confidence) — `[ЗАКРЫТ]`.** Backend-фаза.
Плоский вес секрета (5 за любой) заменён на **по-tier**: высокоценный credential
(cloud/payment/VCS/messaging-ключ с точным форматом) весит `SECRET_WEIGHTS['critical']=5`
и форсит Critical; generic/opaque-матч (`_GENERIC_SECRET_TYPES`: Generic API Key/
Generic Secret/Bearer/JWT/Stripe Publishable) весит `SECRET_WEIGHTS['generic']=3` и
форсит **≥High** (не Critical). `_plausible_secrets` → `_secret_signal(api)` (возвращает
`{plausible,detected,critical,generic,points}`, derive-on-read над `api['details']`,
переиспользует `secret_validator`). `_risk_level` стал tier-aware (`secrets_critical`→
Critical, `secrets_generic`→High); `_risk_factors` принимает явные `secret_points`/
`secret_weight`/`secret_detail` (вес = tier при однородном наборе, иначе None +
разбивка в detail). Метрика `secrets_high_value` + headline-чип красится critical/high
по ней. **Вердикты для generic-only целей снизились сознательно** (Critical→High; как
F-SEC2). Back-compat: легаси-`keys_found` без details → высокоценный tier → байт-в-байт
(вес 5, Critical). `'secrets'` убран из `RISK_WEIGHTS` (вытеснён `SECRET_WEIGHTS`).
attack-surface «Secrets» (breadth) и portfolio-heatmap (any plausible key = critical
cell) не тронуты — отдельные оси. Покрыто `test_executive_summary` (generic=High/вес 3 /
mixed=Critical+score 8 / high-value форсит / SECRET_WEIGHTS).

**Historical-URL → Timeline-событие — `[ЗАКРЫТ]`.** Backend-фаза, тот же
асимметричный пробел: секция `historical` (интересные архивные URL — admin/auth/api/
config из веб-архивов) диффилась и была в attack-surface, но `diff_events` не имел
обработчика → ново-всплывший интересный URL не давал события. Добавлен
`new_historical_url` (medium, **timeline-only** — НЕ в `alerts.ALERT_TYPES`: архивное
наличие = discovery, не живая регрессия; URL мог быть заархивирован давно и лишь
ново-замечен этим сканом) поверх существующих diff-данных секции. `EVENT_SEVERITY` +
метка в `gui/tab_timeline._EVENT_LABELS`. Reappeared-актив уже был покрыт
(`asset_reappeared` в `timeline`). Pure, web-паритет автоматом. Покрыто
`test_diff_events` (классификация + не-алертабелен) и `test_scan_diff` (end-to-end
added → событие).

**Утёкшие секреты → первоклассные F1-находки (convergence) — `[ЗАКРЫТ]`.** Backend-фаза.
Закрыт последний асимметричный пробел: секрет — самый тяжёлый risk-сигнал — был
**единственной** экспозицией без lifecycle/SLA/triage (питал только risk-счёт,
attack-surface, scan-diff). Фундамент уже был построен и не использован (`'secret'`
в `finding_fingerprint.CATEGORIES`, неутекающий `secret_discriminator`, ветка в
`findings_adapter`, запись `finding_knowledge['secret']`) — не хватало **продьюсера**.
Решение пользователя — **1b (полная конвергенция, паттерн F-SEC2)**: каждый
**plausible** секрет (плейсхолдеры отброшены `secret_validator`) фолдится из
always-on api-фазы в vuln-фазу как **High**-находка (`CollectionRunner._secret_findings`:
`category='secret'`, `location=url`, явный неутекающий `discriminator` = vendor+маска;
маскирование как в Scan Diff) сразу после vulns — паттерн takeover. Теперь секреты
**считаются один раз** через severity (vuln_score), а не выделенным фактором: из
`executive_summary` убраны `SECRET_WEIGHTS` и секрет-фактор (`_risk_factors` без
секрет-аргументов). `_secret_signal(api)` оставлен ТОЛЬКО для display-метрик
(`secrets`/`secrets_high_value`/`secrets_detected`) и **Critical-гейта** `_risk_level`
(high-value ключ → Critical, паттерн takeover; generic-гейт убран — generic-секрет
теперь High-находка → High через `high>=1`). attack-surface: `'secret'` добавлен в
exclude-кортеж «Findings» (нет дубля с категорией «Secrets»). scope-guard:
`source='secret'`→`phase_ok('api')`. **Вердикты сохранены** (high-value→Critical,
generic→High, плейсхолдер→none); **числа сдвинулись сознательно** (generic-секрет
3→5 как High-находка; #3-веса вытеснены severity). Lifecycle/SLA/triage/finding-objects/
dedup работают автоматом (downstream уже поддерживал `secret`). (Изначальный
компромисс «гейт api-derived, триаж не снижает вердикт» закрыт следующим
инкрементом — status-aware гейт.) Покрыто
`test_collection_runner` (producer: High/неутекающая identity/плейсхолдер-skip/пусто),
`test_attack_surface` (secret исключён из «Findings»), `test_executive_summary`
(generic=High / high-value→Critical-гейт / нет выделенного фактора / SECRET_WEIGHTS
удалён / плейсхолдер не считается).

**Tier-aware secret events + dedup с F1-находками — `[ЗАКРЫТ]`.** Backend-фаза, хвост
secret-конвергенции. (1) **Tier-aware:** scan-diff `new_secret` был всегда `high`;
теперь tiered по **единому источнику истины** — новый публичный
`executive_summary.is_high_value_secret(type)` (обёртка `_GENERIC_SECRET_TYPES`,
переиспользована и в `_secret_signal`, и в diff — без второй системы оценки).
`diff_events` разбивает по типу из лейбла: high-value → `new_secret` (high),
generic/opaque → `new_secret_generic` (medium); оба алертабельны (тип в
`alerts.ALERT_TYPES`), метки в `gui/tab_timeline` + `gui/dialogs`. (2) **Dedup:**
аудит выявил дубль, внесённый #1b — секрет в Timeline шёл и как scan-diff
`new_secret`, и как F1 `new_finding` («[High] Leaked secret: …»). Фикс в
`timeline.build_events`: F1 `new_finding` с `category=='secret'` пропускается
(scan-diff-событие, теперь tier-aware, владеет «появлением»; fix/reopen-lifecycle
секрета из F1 сохранён — у diff его нет). `project_events` уже отдаёт `category`
(джойн), так что дедуп точечный. **Обратная совместимость:** старые проекты (без
secret-находок) не затронуты — их `new_secret` в Timeline цел; alerts берут diff
напрямую (фильтр build_events их не трогает). derive-on-read сохранён, без новых
зависимостей, раскладка отчётов цела. Покрыто `test_diff_events`
(high-value→high / generic→medium / оба алертабельны), `test_timeline`
(secret new_finding дедуплицирован, non-secret и resolve/reopen сохранены).

**Attack-surface secret plausibility filter — `[ЗАКРЫТ]`.** Backend-фаза, замыкает
secret-confidence на последней оси (граф/surface_score). `attack_surface.build_surface`
сёрфил типы секретов прямо из `api.details.keys()` без проверки правдоподобности —
плейсхолдер-only тип (`your_api_key_here`) инфлейтил граф и surface_score (вес 5).
Фикс: тип попадает в категорию «Secrets», только если у него есть ≥1 plausible-значение
(тот же `secret_validator` SSOT, что risk-движок/Scan Diff — без второй системы оценки).
Все-плейсхолдер details схлопывают категорию (без fallback на сырой `keys_found`, иначе
вернулись бы false-positive). **Обратная совместимость:** легаси-отчёт без `details`, но
с `keys_found` → прежний `"N keys"`-узел цел (fallback срабатывает только при отсутствии
details). derive-on-read, без новых зависимостей. Покрыто `test_attack_surface`
(плейсхолдер-тип отброшен / все-плейсхолдер → нет категории / legacy keys_found fallback).

**Status-aware Critical-гейт секретов — `[ЗАКРЫТ]`.** Backend-фаза, закрыт компромисс
#1b. Гейт `secrets_critical → Critical` читался из `_secret_signal(api)` (status-
независимо) → триаж секрета в FALSE_POSITIVE/IGNORED/FIXED снижал score (находки
фильтруются из vsum), но НЕ вердикт-гейт (оставался Critical). Фикс: когда секреты —
находки (post-#1b), `secrets`/`secrets_high_value` (и питаемый ими гейт) деривятся из
**активных** (triage-filtered) secret-находок, а не из api. Tier (high-value) восстановлен
из стабильного тайтла продьюсера `'Leaked secret: {type}'` через `is_high_value_secret`
SSOT (новый `_is_high_value_secret_finding`; неузнаваемый тайтл → high-value, консервативно).
**Fallback:** легаси-отчёт без secret-находок → прежний `_secret_signal(api)` (триажа там
нет). `secrets_detected` остаётся сырым api-счётом (детекция, не триаж). Теперь триаж
high-value секрета в FALSE_POSITIVE снимает Critical-вердикт, а не только score. derive-on-read,
без новых зависимостей, без второй системы оценки. Покрыто `test_executive_summary`
(OPEN high-value→Critical/secrets=1; FALSE_POSITIVE→secrets=0/не Critical).

**Security-audit секреты → первоклассные находки — `[ЗАКРЫТ]`.** Backend-фаза. #1b
сделал находками секреты api-фазы (начальная страница); SecurityAuditor (opt-in,
глубокий скан inline+внешнего JS) находил БОЛЬШЕ секретов (`result['secrets']`), но
они шли только в счётчик+валидацию report-карточки — НЕ находки/risk/гейт/surface/diff.
Фикс: общий хелпер `CollectionRunner._secret_finding(type, value, location, source)`
(одна secret-находка или None для плейсхолдера; переиспользуют api- и audit-фолдеры —
без дублирования). `_security_findings` фолдит `data['secrets']` (`source='secret-audit'`,
`location`=URL скрипта); `_secret_findings` (api) — `source='secret'`. Пересечение
дедупится по fingerprint. Risk/гейт/SLA/triage — автоматом (обе category='secret' High-
находки; status-aware гейт считает их → high-value audit-секрет форсит Critical).
Scope-guard: `'secret-audit'→phase_ok('security')` (пропущенный opt-in аудит ≠ «fixed»).
**Timeline (пересмотр дедупа #3):** audit-секретов НЕТ в scan-diff секции `secrets`
(api.details only), поэтому пер-event подавление #3 спрятало бы их. Новый подход —
**F1 владеет secret-таймлайном, когда у проекта есть secret-находки**: scan-diff секция
`secrets` исключается из ленты (F1 new_finding/lifecycle покрывает api+audit, верный
first-seen), tier-aware secret-АЛЕРТЫ не тронуты (читают diff_events напрямую). Обратная
совместимость: старый проект без secret-находок сохраняет scan-diff `new_secret` в ленте.
Attack-surface: типы audit-секретов влиты в breadth «Secrets» (plausibility-filtered).
**Остаток (закрыт ниже):** алерты для audit-ONLY секретов (нет diff-представления —
нужен finding-based alert-канал). Покрыто `test_collection_runner` (audit-фолд: High/
secret-audit/location/плейсхолдер-skip/без plaintext), `test_timeline` (F1 владеет при
наличии secret-находок; legacy сохраняет scan-diff), `test_attack_surface` (типы влиты).

**Audit-only-secret alert-канал — `[ЗАКРЫТ]`.** Backend-фаза, закрыт остаток выше.
Секрет, найденный ТОЛЬКО глубоким JS-аудитом (`source='secret-audit'`), становится
первоклассной F1-находкой, но НЕ имеет представления в Scan Diff (секция `secrets`
читает только api-фазу) → diff-алерт `new_secret` для него не стрелял. Решение —
finding-based one-shot канал по образцу SLA-просрочки (F-S6): обе механики
«триггер без diff-представления» теперь делят `FindingsStore._record_oneshot`
(episode-aware, маркер старше последнего `REOPENED` не считается → переоткрытый
секрет алертится заново; `record_sla_breaches` отрефакторён через него,
`record_secret_alerts` + тип события `SECRET_ALERTED`). `alerts.collect_secret_alerts`
(активные secret-находки БЕЗ api-источника `secret` — `_is_audit_only_secret` через
`sources`/`source` в evidence, дедуп через стор, tiered `new_secret`/`new_secret_generic`
по `executive_summary.is_high_value_secret` — тот же SSOT, что diff) + `notify_secret`;
общий хвост `_notify_collected` выделен (notify_sla делегирует, поведение байт-в-байт).
`monitor.run_project` зовёт `_dispatch_secret_alerts` каждый успешный прогон,
diff-независимо, best-effort (рядом с SLA; `result['secret_alerts']` аддитивен).
api-секреты (`source='secret'`) НЕ дублируются — они diff-covered. Новых типов алертов
нет (`new_secret`/`new_secret_generic` переиспользованы). Pure-детект отделён от
транспорта (стор инжектится). Покрыто `test_findings_store` (one-shot+reopen-reset+dedup),
`test_alerts` (audit-only→alert+dedup / api-источник и merged-sources пропущены /
generic-tiering / notify dispatch+filter+disabled), `test_monitor` (run_project шлёт раз,
второй прогон молчит).

**Generic high/critical-finding alert-канал — `[ЗАКРЫТ]`.** Backend-фаза, тот же
асимметричный пробел в последней непокрытой оси. Секция `findings` в `scan_diff`
(`_extract_findings`) вычисляется и показывается в HTML-диффе, но `diff_events` НЕ имеет
для неё обработчика → ново-появившаяся generic vuln-находка (nuclei-шаблон, чек сканера
SQLi/XSS, не-dependency CVE) не порождала алерта, только косвенный `risk_increase`. Каждый
*специфичный* опасный сигнал (secret/takeover/source-map/GraphQL/cookie/dependency) уже
имеет таргетный алерт — `category='vuln'` была единственной категорией без него. Решение —
finding-based one-shot канал (как secret/SLA): `alerts.collect_finding_alerts` (активные
high/critical находки `category='vuln'`, исключая dependency-audit CVE — их покрывает
`new_vulnerable_dependency`; дедуп через стор) + `notify_findings`; `new_finding` в
`ALERT_TYPES`; `FindingsStore.record_finding_alerts` + событие `FINDING_ALERTED`
(переиспользует общий `_record_oneshot`). **Рефактор:** три почти-идентичных
finding-based диспетчера монитора (SLA/secret/finding) слиты в один
`_dispatch_finding_based_alerts(collect, notify, kind)`; finding-канал зовётся каждый
успешный прогон (`result['finding_alerts']` аддитивен). **Timeline не тронут** — F1 уже
владеет finding-событиями там; добавлен только недостающий alert-путь. Находки с
dedicated-категорией/источником НЕ дублируются. Покрыто `test_findings_store` (one-shot),
`test_alerts` (high→alert+dedup / low+dependency-audit+secret-категория пропущены / notify
dispatch+filter+disabled), `test_monitor` (шлёт раз, второй прогон молчит).

**OSINT-discovery события в Timeline (email/employee/CT) — `[ЗАКРЫТ]`.** Backend-фаза,
тот же «вычисляется, но теряется» пробел в discovery-оси. Секции `emails`/`employees`/`ct`
в `scan_diff` диффятся и показываются в HTML-диффе, но `diff_events` не имел для них
обработчика → ново-найденный email/сотрудник/залогированный сертификат не давал записи в
ленте — хотя проект уже сёрфит discovery там (`new_endpoint`/`new_subdomain`/
`new_historical_url`). Ни одна из секций не является находкой → **нулевой F1-оверлап** (в
отличие от DNS email-auth — тогда отложен из-за мнимого F1-оверлапа, позже закрыт отдельно,
см. «DNS email-auth регрессия» ниже). `diff_events` эмитит `new_email`/`new_employee`/`new_ct_cert` из
`added`-списков (info, как `new_endpoint`); все **timeline-only** (НЕ в `ALERT_TYPES`) —
чистый discovery, не регрессия, по образцу `new_historical_url` (без alert-шума). Метки в
`gui/tab_timeline._EVENT_LABELS`. Ценность: новый email/сотрудник расширяет phishing-
поверхность; ново-залогированный сертификат сигналит свежую инфраструктуру или (если
неожиданный) возможную mis-issuance. Pure; на web видны через `/timeline` (см. ниже).
Покрыто `test_diff_events` (классификация info + не-алертабельны) и `test_scan_diff`
(end-to-end added→событие).

**`/timeline` web-эндпоинт (F2 web-паритет) — `[ЗАКРЫТ]`.** Закрыл пробел паритета: у GUI
есть вкладка Timeline над `core.timeline.build_timeline`, но web-консоль НЕ имела роута
`/timeline` — при том что каждый другой read-вью (findings/assets/overview/correlation/
companies) его имеет. F2 закрыл GUI, но не web. `remote/web_app._timeline_view(project)` —
тонкий ридер: резолвит проект из `_REPORT_BASE` через `ProjectStore.get` и делегирует
`build_timeline` (series+events), зеркало `_correlation_view`. Роут `GET /timeline?project=…`
+ кнопка «Timeline» в консоли (`showTimeline()` авто-берёт первый проект и печатает свежую
ленту). Pure derive-on-read; только что добавленные OSINT-discovery события идут через него
автоматом. Покрыто `test_web_timeline` (helper для проекта/пустой/неизвестный + наличие
кнопки + live TestClient).

**`timeline_csv` + Export CSV Timeline-вкладки (export-паритет) — `[ЗАКРЫТ]`.** Findings/
Assets/Overview экспортируют CSV, а лента изменений (Timeline) — нет; единственный
data-вью без экспорта. `core/report_export.timeline_csv(events)` — pure-stdlib CSV F2-ленты
(When/Scan/Severity/Section/Event/Detail), брат `findings_csv`/`assets_csv`. GUI
Timeline-вкладка получила кнопку «Export CSV» (точное зеркало хендлера Findings/Assets) над
текущими загруженными событиями (стэшатся при загрузке как источник). Покрыто
`test_report_export` (header+row / пустой = только header). Кнопка аддитивна (не
реструктуризация GUI).

**Alert-type метки в Settings (полнота) — `[ЗАКРЫТ]`.** Вкладка «Уведомления» строила
чекбоксы alert-типов из method-local словаря меток, отстававшего от `ALERT_TYPES`:
`graphql_introspection`, `sla_breach` (F-S6) и `new_finding` показывались сырыми ключами.
Метки вынесены в module-level `_ALERT_TYPE_LABELS` (рядом с `_THEME_LABELS`), три пробела
заполнены; тест `test_alerts_gui` проверяет покрытие всех `ALERT_TYPES` (новый тип не
сможет регрессировать в сырой ключ). Аддитивно.

**Рендер alert-события в monitor-фиде — `[ЗАКРЫТ]`.** `monitor.format_event` (общий для
web-консоли и in-app планировщика) не имел кейса для события `alerts` → падал в generic
`[monitor] slug: alerts`, теряя count/sent/reason/alert_kind, которые эмитят диспетчеры.
Наблюдатель не видел, сколько алертов сработало, сколько доставлено и какого вида (diff/
sla/secret/finding). Добавлен кейс `alerts` (рендер `N alerts (kind), M sent · reason`).
Pure, SSOT-формат, web+GUI одинаково. Покрыто `test_monitor` (diff без kind / finding-based
с kind+reason).

**DNS email-auth регрессия → Diff/Timeline/Alerts — `[ЗАКРЫТ]`.** Закрыт ранее отложенный
DNS-сигнал. Posture email-auth (SPF/DMARC/DKIM/CAA) диффился и был в HTML-диффе, но
`diff_events` не имел dns-обработчика → убранный SPF/DMARC или **даунгрейд DMARC-политики**
не давали ни события, ни алерта (а dns_intel-находки «No SPF/No DMARC» — Medium/Info, ниже
High-порога `new_finding` → просадка анти-спуфинга вообще не алертилась). **Пересмотр
прежнего F1-оверлап-опасения:** оверлапа нет — «SPF removed» (дельта-регрессия) и «No SPF
record» (F1-находка состояния) суть **разные** события, как `risk_increase` сосуществует с
`new_finding` (таймлайн штатно мешает дельты и находки; dedup по `(scan_id,type,title)` их
не схлопывает). `diff_events` эмитит `dns_email_auth_weakened` (high) на removed SPF/DMARC
или даунгрейд DMARC (reject>quarantine>none через `_dmarc_rank`); только регрессии (добавление/
усиление — скип, контентную смену SPF не судим, как `security_header_removed`). Тип в
`alerts.ALERT_TYPES` (явная регрессия), метки в `gui/tab_timeline`+`gui/dialogs` (покрыты
alert-label тестом). Pure, web-паритет автоматом (`/timeline`+diff_events). Покрыто
`test_diff_events` (классификация high+alertable / улучшение=не событие) и `test_scan_diff`
(end-to-end SPF removed + DMARC downgrade = 2 события). **Последний обозримый
«вычисляется-но-теряется» backend-пробел закрыт.**

**Security-audit endpoints → surface + assets — `[ЗАКРЫТ]`.** Backend-фаза. Audit
извлекал endpoints из inline+внешнего JS (`security.data.endpoints` = `{url, found_in}`),
но они были orphaned: attack-surface «Endpoints» читала только `katana.endpoints`, а
asset-inventory/diff их не видели → при пропущенной katana JS-endpoints терялись.
Фикс: (1) `attack_surface.build_surface` мёржит URL audit-endpoints в breadth
«Endpoints» (дедуп с katana); (2) `asset_adapter.derive_assets` деривит их как
endpoint-активы с `source='security'` (после katana/openapi — `_dedup` first-wins, так
overlap сохраняет katana-source; audit-only гейтит GONE на фазе security),
`ASSET_SOURCE_PHASES['endpoint']` += `'security'`. Через asset-инвентарь они автоматом
попадают в Timeline (asset-события new_asset/gone) и web. Scan-diff `endpoints` секция
НЕ тронута (гейт на katana — мёрж opt-in security туда нарушил бы comparison-honesty,
как с audit-секретами; asset-путь — корректная поверхность для diff). derive-on-read,
без новых зависимостей. Покрыто `test_asset_adapter` (audit-endpoint→актив source=security
/ shared с katana сохраняет katana-source), `test_attack_surface` (katana+audit мёрж+дедуп).

**Document-Intelligence секреты в alert-канал (хвост secret-convergence) — `[ЗАКРЫТ]`.**
Backend-фаза, баг-фикс. Document Intelligence (opt-in, F2) эмитит секреты как
первоклассные F1-находки (`category='secret'`, `source='document'`), но они не
алертились **никаким** каналом: diff-канал `new_secret` читает секции `secrets`
только из api-фазы (`source='secret'`), а finding-based `_is_audit_only_secret`
узнавал **лишь** `'secret-audit'` (deep-JS аудит). Документ-only секрет → находка
есть, риск считается, но **алерта нет** — тот же пробел, что F-S6 закрыл для
secret-audit, переоткрытый позже добавленной document-фазой. Фикс: `_is_audit_only_
secret` обобщён с «несёт secret-audit» на «секрет-находка БЕЗ api-источника
`secret`» (`bool(sources) and 'secret' not in sources`) — дифф покрывает **только**
api-секреты, поэтому любой иной продьюсер (secret-audit / document / будущие) не
diff-covered и корректно идёт в one-shot finding-канал. api-секреты (одни или
merged с api) по-прежнему исключены (нет двойного алерта). `collect_secret_alerts`/
`record_secret_alerts`/monitor-проводка не тронуты — generic-предикат пускает
document-секреты автоматом. Покрыто `test_alerts` (document-only→alert+one-shot;
api-only и merged-with-api по-прежнему пропущены; generic-tiering цел).

**Robustness-проход по data-collection engine'ам — `[ЗАКРЫТ]`.** Backend-фаза,
degrade-not-raise аудит (этос F-SR1). Вывод: engine'ы адекватно устойчивы там, где
важно — все обёрнуты phase-level try/except (app-graceful), а общий http-слой
(`http_retry.decompress`/`urlopen_retry`/`urlopen_text`) уже guarded (decompress
возвращает raw на любой сбой gzip/deflate). `paywall_bypass._decompress` — менее-
guarded дубликат, но его вызов обёрнут, и унификация регрессировала бы поведение на
битом gzip (raise→None→skip уместнее, чем raw→мусор) — не трогал. **Один таргетный
фикс:** `site_extractor.strip_html`/`_extract_script_urls` — публичные/тестируемые
pure-парсеры, падали на не-str (None из неудачного fetch → `re.sub` TypeError);
теперь `isinstance(html,str)`-гейт → '' / [] (safe building block, как F-SR1
гардил tech_fingerprint/dependency_audit). Приватные парсеры image/frontend_cloner
получают внутренние строки + phase-wrapped — гардить = busywork (не делал). Покрыто
`test_site_extractor` (None/не-str → пусто).

**Dynamic-analyzer секреты: фильтр placeholder/JWT-FP — `[ЗАКРЫТ, accuracy]`.**
Backend-фаза (аудит неаудированного engine). `dynamic_analyzer` майнит секреты из
перехваченных API-ответов и статического JS через SSOT `secret_scanner.scan_text`,
но не отбрасывал хиты, которые структурный валидатор метит INVALID — а scan_text-
хиты несут `validation`. Конкретный FP: base64-блоб вида `eyJ…` матчит JWT-правило,
но не является реальным JWT (валидатор декодит → INVALID) → ложный High «Secret
exposed in API response». Фикс: `_scan_json_for_secrets` (path-1, pattern) и
static-JS-путь пропускают INVALID-хиты — тот же placeholder-фильтр, что api/document/
audit-фолдеры. Path-2 (key-name эвристика, тип `token-field`) валидатор НЕ фильтрует
(unverifiable — сознательно без фильтра, чтобы не вводить в заблуждение). Покрыто
`test_dynamic_js_urls` (JWT-FP отброшен / реальный GitHub-token сохранён). Аудит
также подтвердил исправным: secret-детект делегирует SSOT (без дубля правил),
findings_store-миграция v1→v2 идемпотентна/version-gated, asset/cve-сторы версионны.

**Консьюмер `cdn:true` — метрика+карточка+web — `[ЗАКРЫТ]`.** Backend-фаза, замкнул
маркер из предыдущего инкремента на поверхностях. `asset_graph.load_asset_graph`
summary += `cdn_clusters` (сколько кластеров — CDN-edge) и `largest_real_cluster`
(крупнейший НЕ-CDN); totals (`clusters`/`largest_cluster`) целы для display.
`executive_summary._exposure_clusters` (метрика/чип «N× co-hosted») теперь считает
**только реальные** single-points-of-exposure (`clusters − cdn_clusters`),
`exposure_largest` = largest_real; полностью-CDN проект → 0 → нет чипа (не blast
radius клиента). Back-compat: старые отчёты без `cdn_clusters` → real=total,
largest=largest_cluster (байт-в-байт). Display (аддитивно, ничего не прячет):
report-карточка «Asset Relationships» тегает CDN-кластер `(CDN edge)`, web-консоль
`/correlation` — ` (CDN edge)`. Покрыто `test_asset_graph` (summary cdn_clusters/
largest_real), `test_executive_summary` (метрика исключает CDN / all-CDN=0 чипа /
старый отчёт unchanged). **CDN-вена закрыта end-to-end: детект (#20) → метрика+
поверхности.**

**CDN-аннотация exposure-кластеров (`cdn:true`) — `[ЗАКРЫТ, accuracy]`.** Backend-фаза,
решение пользователя (аннотировать, НЕ исключать). `asset_graph.shared_infra` считал
хосты на общем IP единым single-point-of-exposure, но для CDN-fronted сайтов (Cloudflare/
Fastly/Akamai) десятки субдоменов резолвятся в **общий edge-IP** — это CDN-артефакт, не
blast radius клиента. Фикс **аддитивный** (ничего не прячет): `cloud_classifier.CDN_CLOUDS`
(SSOT: только чистые edge-провайдеры; гиперскейлеры AWS/GCP/Azure ИСКЛЮЧЕНЫ — там IP
инстанса = реальный blast radius) + `is_cdn_cloud()`; `shared_infra` резолвит cloud узла
кластера (`_node_cloud`: готовый `attrs.cloud` → fallback `classify_cloud` по provider/ASN;
загружены asn-активы) и ставит `cdn:True` на CDN-кластер. Кластер ОСТАЁТСЯ в выводе
(count/members целы) — потребители могут де-эмфазировать. Display-only (exposure_clusters —
не risk-score). Покрыто `test_asset_graph` (CDN-IP→cdn:true+не дропнут / не-CDN без ключа),
`test_cloud_classifier` (is_cdn_cloud: CDN да / гиперскейлер нет / None).

**SPF-enforcement downgrade → diff-регрессия (хвост #11) — `[ЗАКРЫТ]`.** Backend-фаза,
закрыт self-flagged follow-up из weak-SPF (#11). `dns_email_auth_weakened` ловил
removal SPF/DMARC + DMARC policy downgrade, но **смену SPF-строки не судил** («не
provably weaker»). Теперь судит: квалификатор `all`-механизма orderable
(`-all > ~all > ?all > +all`), так что `-all → +all` = реальная анти-спуфинг
регрессия. Фикс: `_SPF_QUAL_RANK` (локальный, как `_dmarc_rank`) + в dns-handler
`diff_events` для changed SPF (обе стороны не-'—') парсит квалификаторы через
**функция-локальный** импорт `dns_intel._spf_all_qualifier` (SSOT, без дубля; lazy
— модуль-загрузка scan_diff остаётся лёгкой; dns_intel lean, не recon-heavy) →
downgrade эмитит `dns_email_auth_weakened` (high, alertable, как DMARC-downgrade).
Upgrade (~all→-all) и неранжируемая смена (нет `all` ни у одной стороны) — не
событие. Покрыто `test_diff_events` (downgrade=high+alertable / strengthen+unrankable
не событие). SPF-строка в HTML-диффе цела (full string для display).

**Security-headers SSOT — устранён дубликат-дрейф — `[ЗАКРЫТ, debt/latent-bug]`.**
Backend-фаза. `core/security_headers.py` объявлял себя «single source of truth», но
`vuln_scanner._EXPECTED_SECURITY_HEADERS` был **отдельным дубль-списком** тех же 6
заголовков (не derive). Совпадали по удаче — дрейф (добавить заголовок в один список,
не в другой) дал бы false-positive: recon-фильтр `SECURITY_HEADER_NAMES` не захватил
бы новый заголовок → present-заголовок репортился бы «missing» (или наоборот).
Фикс: `security_headers.py` стал истинным SSOT — **упорядоченный** `SECURITY_HEADERS`
(канон-порядок для «missing: …» detail) + `SECURITY_HEADER_NAMES = frozenset(...)`
derive; `vuln_scanner` импортит `SECURITY_HEADERS` (дубль удалён). Поведение байт-в-
байт (тот же порядок/набор). Регресс-гард `test_vuln_scanner`: `_EXPECTED ⊆
SECURITY_HEADER_NAMES` (expected-набор не может разойтись с capture-набором). recon/
scan_diff (frozenset) не тронуты.

**http→https redirect = НЕ «plain HTTP» (false-High закрыт) — `[ЗАКРЫТ, accuracy-фикс]`.**
Backend-фаза, отложенный follow-up из #query-param (теперь сделан — user-present).
`_check_https` рейтил `http://`-URL как **High** «served over plain HTTP», но если
сайт редиректит на HTTPS — это false-High (инфлейтит risk-**level**, не только score).
Причина: `recon['url']` хранил ВХОДНОЙ url, финальный (post-redirect) не
захватывался. Фикс (multi-module, backward-compat): `utils.http_retry.urlopen_retry`
+= opt-in `return_final_url` (3-tuple с `response.geturl()`; 4 прочих вызова целы);
`recon_engine._fetch_with_headers` тащит final-url → `result['final_url']`;
`_check_https` судит по `final_url or url` (fallback при fetch-fail/legacy →
прежнее поведение). http→https → не флагается; http→http → High; downgrade
https→http → High (корректно). Покрыто `test_http_retry` (opt-in 3-tuple),
`test_vuln_scanner` (redirect/plain/fallback), стабы `test_recon_engine` → 3-tuple.

**Query-param «sensitive path» → Info — `[ЗАКРЫТ, accuracy-фикс]`.** Backend-фаза,
severity-калибровка. `_check_sensitive_paths` рейтил ВСЕ паттерны Medium, включая
query-param-хинты `?id=`/`?user=`/`?file=` — но наличие параметра само по себе слаб.
IDOR/LFI-recon (вездесущи на динамике), не подтверждённая проблема → постоянный
false-Medium на каждом сайте. Фикс: `_SENSITIVE_PARAM_HINTS` → Info; path-паттерны
(`.env`/`/admin`/`/credentials`…) остаются Medium. Severity НЕ часть fingerprint →
ноль identity-churn. Снижает risk-инфляцию. Покрыто `test_vuln_scanner`
(path=Medium / param=Info). **Отложенный follow-up (флаг):** `_check_https` рейтит
`http://`-URL как High, но если сайт редиректит на HTTPS, это false-High —
`recon['url']` хранит ВХОДНОЙ url, финальный (post-redirect) не захватывается
(`urlopen_retry` дропает `geturl()`); фикс требует прокинуть final-url через
shared http-util → deliberate multi-module, не leaf (триггерится лишь на явный
`http://`-ввод, т.к. голый домен → https).

**Server-disclosure severity по версии — `[ЗАКРЫТ, accuracy-фикс]`.** Backend-фаза,
severity-калибровка (под-класс accuracy). `_check_server_disclosure` рейтил ЛЮБОЙ
`Server`/`X-Powered-By`/`X-Generator` как **Medium**, но реальный риск — **версия**
(`nginx/1.18.0` → targeted CVE-lookup), а голое имя (`nginx`/`cloudflare`,
вездесущее) раскрывает лишь технологию. Фикс: версия (есть цифры) → Medium, голое
имя → Info (как CMS-fingerprint). Снижает инфляцию risk для повсеместного
version-less `Server`. Покрыто `test_vuln_scanner` (versioned=Medium / bare=Info).

**CSP unsafe-inline ложно «weak» при nonce/hash — `[ЗАКРЫТ, accuracy-фикс]`.**
Backend-фаза, тот же FP-класс, что XFO/frame-ancestors. `_check_csp_weakness`
флагал `unsafe-inline` безусловно, но по CSP3 браузеры **игнорируют** `'unsafe-
inline'` при наличии nonce- или hash-источника (это backward-compat fallback для
старых браузеров) → корректная современная политика `script-src 'nonce-…'
'unsafe-inline'` ловила ложный «Weak CSP». Фикс: `unsafe-inline` флагается только
БЕЗ nonce/hash (`'nonce-`/`'sha256-`/`'sha384-`/`'sha512-`). `unsafe-eval`
исключения НЕ получает (nonce на eval не влияет); wildcard-проверка цела. Снижает
FP/risk для корректно-настроенных CSP. Покрыто `test_vuln_scanner`
(unsafe-inline+nonce/+hash не флагается / без nonce — флагается / unsafe-eval+nonce
всё равно флагается).

**X-Frame-Options ложное «missing» при CSP frame-ancestors — `[ЗАКРЫТ, accuracy-фикс]`.**
Backend-фаза, иной класс — не «detected-but-not-promoted», а **ложноположительная
находка**. `_check_security_headers` репортил `x-frame-options` как missing при
отсутствии легаси-заголовка, хотя современный CSP `frame-ancestors` его **вытесняет**
(OWASP/MDN): сайт с frame-ancestors защищён от clickjacking эквивалентно/сильнее, но
ловил ложное «Missing security headers (x-frame-options)». Фикс: при наличии
`frame-ancestors` в CSP `x-frame-options` считается present (не missing). Пермиссивный
`frame-ancestors *` всё равно ловится `_check_csp_weakness` (wildcard) — реальный
пробел защиты сёрфится корректной находкой, а не легаси-missing. Снижает шум/FP в
risk для современных сайтов (числа для них падают сознательно). Покрыто
`test_vuln_scanner` (frame-ancestors→XFO не missing / без него — missing цел).

**Weak DMARC (pct<100 / sp=none) → находка — `[ЗАКРЫТ]`.** Backend-фаза, прямой
параллель к weak-SPF: `_dmarc_policy` извлекал только `p=`, а захваченная DMARC-
запись несёт и `pct=` (частичное применение — известный обход: остаток почты идёт
без политики) и `sp=` (политика субдоменов). `p=reject` с `pct=10` или `sp=none`
детектился, но находкой не становился. Рефактор: `_dmarc_tags(records)` парсит все
теги (lower-keys), `_dmarc_policy` теперь поверх него (контракт цел: present-no-p →
'none', absent → None); `analyze` в enforcing-ветке (p=quarantine/reject) эмитит
`DMARC partial enforcement (pct=N)` и `DMARC subdomain policy is sp=none` (оба Info).
pct=100/без sp — чисто (healthy-тест цел). `source='dns'`→A05/CWE-16. Покрыто
`test_dns_intel` (pct+sp findings / pct=100 чисто / _dmarc_tags+policy парсинг).

**Weak SPF (+all/?all) → находка — `[ЗАКРЫТ]`.** Backend-фаза, тот же
detected-but-not-promoted паттерн, что #GraphQL (лид с него). `dns_intel.analyze`
флагует только **отсутствие** SPF, а present-but-weak SPF (квалификатор `all`)
детектился (полная строка в `email_auth.spf`), но находкой не становился. Фикс:
`_spf_all_qualifier(spf)` парсит квалификатор `all`-механизма (`-`/`~`/`?`/`+`, bare
`all`→`+` по RFC 7208); `analyze` эмитит `SPF allows all senders (+all)` (Medium —
проходят все отправители, SPF бесполезен) и `SPF policy is neutral (?all)` (Info).
**`~all` (softfail) НЕ флагуется** — это де-факто стандарт (Google/Microsoft), флаг
был бы шумом и ломал бы established «healthy»-тест. `source='dns'` (scope-guard цел),
category='dns'→A05/CWE-16 (compliance/knowledge/risk автоматом). SPF-qualifier
downgrade в dns_email_auth_weakened (diff-регрессия, теперь orderable как DMARC) —
возможный follow-up; пока покрыто F1 new_finding. Покрыто `test_dns_intel`
(+all=Medium/bare-all/?all=Info/qualifier-парсинг; healthy ~all и weak-dmarc тесты
целы).

**GraphQL field-suggestions / query-batching → находки — `[ЗАКРЫТ]`.** Backend-
фаза, computed-but-lost. `GraphQLDiscovery` детектит 4 экспозиции (introspection,
reachable, **field suggestions**, **query batching** — последние две независимо от
introspection, leak схемы / amplification-DoS) и кладёт флаги в endpoint-данные
(`data.graphql[].suggestions/batching`), но `collection_runner._security_findings`
синтезировал находки **только** для introspection/reachable → suggestions и batching
детектились, но не становились находками (нет risk/F1/SLA/alerts/compliance).
SecurityAuditor берёт из discovery лишь endpoints (его собственные 4 находки
отбрасываются), поэтому коллекция — единственный путь, и он ронял два сигнала. Фикс:
`_security_findings` эмитит `GraphQL field suggestions enabled` (Info) и `GraphQL
query batching enabled` (Medium) из флагов endpoint'а, независимо от introspection,
дословно повторяя severity/формулировки `graphql_discovery`. Один endpoint теперь
даёт до 3 graphql-находок (разные тайтлы → разные rule_id → разные fingerprint, без
коллизии). category='graphql' → finding_knowledge/attack-surface/compliance/dedup
работают автоматом. **Числа risk выросли сознательно** для batching-целей (Medium-
находка). Покрыто `test_collection_runner` (suggestions=Info+batching=Medium+мульти-
находка на endpoint; reachable-тест цел — без флагов нет лишних находок).

**Detection-метрики в trend-аналитике — `[ЗАКРЫТ]`.** Backend-фаза. `_scan_entry`
денормализует в `metadata.json` 9 метрик per-scan **специально для cross-scan
анализа** (heatmap), но `timeline.build_series` тащил лишь 5 — детект-категории
(`source_map_leaks`/`weak_cookies`/`graphql`/`graphql_introspection`) персистились,
но trend-слой их не видел. Для CSM-платформы «деградирует ли наша exposure-гигиена
во времени?» — ровно тот вопрос, на который trends должен отвечать. Фикс:
`build_series` несёт 4 детект-метрики (None при их отсутствии — gap, не фейковый 0),
`trends.METRICS` их трендит. Pure/additive, данные уже персистятся. Потребители целы:
`_render_trends_card` использует фикс-список из 4 sparkline'ов (не METRICS) →
визуал отчёта не меняется; `trend_summary` (web `/timeline`) подхватывает новые
метрики автоматом; старые проекты без этих ключей → `metric_trend` возвращает None →
метрика опускается (graceful). Покрыто `test_timeline` (build_series несёт+gap),
`test_trends` (детект-метрика трендится / отсутствующая опускается).

**Dead-write чистка `report['trends_summary']` — `[ЗАКРЫТ 2026-06-23]`.** Backend-полировка.
Закрыт flagged-выше кандидат: `report['trends_summary']` персистился в каждый
`report.json`, но НЕ читался никем — HTML-карточка `_render_trends_card`
пересчитывает `trends.metric_trend` из уже переданной серии, web `_timeline_view`
пересчитывает `trend_summary` из **живой** серии (снимок-времени-скана там и не
годится). Персист derive-but-unread + дивергенция snapshot↔live = ровно тот долг,
что был помечен. Убраны оба присваивания в `collection_runner.run` (success +
except-fallback) и ставший лишним импорт `trends as _trends`; `report['trends']`
(серия — читается карточкой) и функция `trends.trend_summary` (web) целы. report.json
теряет неиспользуемый ключ; contract-тесты subset → не задеты, ни один тест его не
читал. Покрыто прогоном `test_collection_runner`/`test_trends`/`test_contracts`/
`test_web_timeline` (95 passed).

**Структурный per-CVE CWE → SARIF-теги (follow-up к NVD CWE) — `[ЗАКРЫТ]`.**
Backend-фаза. Завершил отложенный follow-up: NVD-CWE из предыдущего инкремента жил
только в `detail`-строке находки (human-display), машинные поверхности (SARIF)
не могли его взять структурно. Проведён структурный `cwe`-канал через модель
находки (опц., обратносовместимо): `Finding.cwe` (dataclass) + `_cwe_list(raw)`
(нормализация в `CWE-NNN`, дедуп, фильтр junk) в обеих ветках `from_raw` +
`to_store` кладёт `cwe` в evidence; `cve_intel.to_findings` отдаёт структурный
`cwe` рядом с detail; `report_export._sarif_tags` читает explicit `evidence.cwe` и
эмитит точный тег (`external/cwe/cwe-79`) **рядом** с generic category-маппингом
(`cwe-1395`), дедуп — теги аддитивны, точность строго лучше. compliance/issue-body
оставлены на category-уровне (cwe-1395/A06 корректен для уязвимого компонента;
SARIF — главный машинный потребитель CWE для GitHub code-scanning). Покрыто
`test_findings_adapter` (cwe в evidence+нормализация+отсутствие), `test_cve_intel`
(структурный cwe), `test_report_export` (explicit+generic тег+дедуп). Цепочка
NVD→find→store→SARIF замкнута.

**NVD CWE извлекается и сёрфится в CVE-находке — `[ЗАКРЫТ]`.** Backend-фаза,
fetched-but-lost. `nvd_provider._parse_nvd` тащил CVSS/severity/published/summary,
но **ронял `weaknesses` (CWE)** — авторитетный per-CVE класс слабости (CWE-79/89…),
который NVD-ответ уже несёт. Фикс: `_extract_cwes(cve)` (из `weaknesses[].
description[].value`, фильтр `^CWE-\d+$` — плейсхолдеры `NVD-CWE-noinfo`/`-Other`
скипаются, дедуп) → `cwe` в parse-результат → `_enrich` мёржит в CVE-record →
`to_findings` добавляет CWE в `detail` рядом с CVSS/датой (тот же surface-паттерн).
CWE теперь виден в Findings-UI/report-карточке/CSV. Pure, инъектируемый seam,
без новых зависимостей. (Точный per-CVE CWE в SARIF/compliance-таксономию —
естественный follow-up; generic `cwe-1395`/A06 уже корректен для компонента.)
Покрыто `test_nvd_provider` (CWE+дедуп+плейсхолдеры/пусто), `test_cve_intel`
(CWE в detail).

**GitHub-issue body несёт CWE/OWASP-класс — `[ЗАКРЫТ]`.** Backend-фаза, третий
(и последний) потребитель таксономии после SARIF/compliance. `github_issues.
issue_body` нёс Severity/Category/Location, но **ронял OWASP/CWE** — хотя его же
docstring обещал «same enrichment as the SARIF export» (который теперь таксономию
несёт). Триажер в трекере не видел класс находки. Фикс: meta-строка body обогащена
`**OWASP:**`/`**CWE:**` через тот же SSOT `compliance.classify` (как SARIF-теги).
Метки issue не трогал (severity-only — избегаем label-проливерации; CWE как label
плодил бы десятки значений). Pure, без новых зависимостей. Покрыто
`test_github_issues` (sqli-находка → A03/CWE-89 в body). **Все три EPIC-16
deliverable (SARIF / compliance / GitHub Issues) несут одну таксономию из единого
`compliance.classify`.**

**SARIF rule-теги несут CWE/OWASP-таксономию — `[ЗАКРЫТ]`.** Backend-фаза. SARIF-
экспорт (`findings_sarif`, EPIC 16) клал в `rule.properties.tags` только
`[category]` + security-severity, **роняя CWE-таксономию**, которую compliance уже
вычисляет. GitHub code-scanning распознаёт `external/cwe/cwe-NNN` для группировки/
фильтрации — без них SARIF не нёс класс находки, хотя compliance-отчёт нёс. Фикс:
`_sarif_tags(finding)` через единый SSOT `compliance.classify` добавляет к категории
CWE-теги (`external/cwe/cwe-NNN`, конвенция GitHub) + OWASP-класс (`OWASP:A06:2021`) →
SARIF и compliance-отчёт несут одну таксономию. Pure stdlib, без новых зависимостей,
без второй системы маппинга. CVE-находки автоматом получают `cwe-1395`/A06 (от только
что добавленного правила). Покрыто `test_report_export` (secret→cwe-798/A07,
CVE→cwe-1395/A06).

**CVE-находки → OWASP A06 в compliance — `[ЗАКРЫТ]`.** Backend-фаза, баг-фикс.
CVE-находка канонизируется `findings_adapter` в `category='vuln'`/`rule_id='cve-…'`,
но `compliance.classify` не имела для неё правила → `owasp=None` → попадала в
**unmapped**, хотя CVE — учебниковый случай **A06:2021 Vulnerable and Outdated
Components**. Фикс: правило `('cve-', A06/CWE-1395)` в конце `_RULE_MAP` (порядок
важен: специфичный класс — XSS-CVE → A03 — выигрывает выше; неклассифицированный
CVE падает в A06, а не в unmapped). `cve-` матчит и канонический `rule_id`, и
ссылку «CVE-XXXX» в тайтле. Чистый derive, mapping — единый SSOT (как
finding_knowledge). Покрыто `test_compliance` (cve→A06+CWE-1395; XSS-CVE сохраняет
A03; «weird»/«Mystery» по-прежнему unmapped).

**Document-секреты в attack-surface «Secrets» — `[ЗАКРЫТ]`.** Backend-фаза, тот же
асимметричный пробел, что закрыл «Security-audit секреты → breadth»: document-only
секрет (найден ТОЛЬКО Document Intelligence) был **полностью вне графа атак-
поверхности** — категория «Secrets» читала api.details + security.secrets, а из
«Findings» секреты исключены (category='secret', анти-дубль). Фикс: `attack_surface.
build_surface` добавляет типы из `phases.documents.data.findings` (плейсхолдеры уже
отброшены продьюсером, тип — из стабильного тайтла `'Leaked secret: <type>'`), дедуп
против api/audit-типов — мирроринг блока audit_secrets. Document-only ключ теперь в
breadth/`surface_score`, как api/audit. Pure, без новых зависимостей, без влияния на
risk-вердикт (surface — отдельная ось). Покрыто `test_attack_surface` (document-типы
в Secrets + дедуп с api + не-secret findings игнорятся).

**BBOT recon → attack-surface breadth — `[ЗАКРЫТ]`.** Backend-фаза, тот же
асимметричный пробел, что закрыл «Security-audit endpoints → surface» — но для
opt-in внешнего recon BBOT. BBOT-хосты/эндпоинты/технологии уже промоутятся в
asset-инвентарь (`asset_adapter.derive_assets` из `phases.bbot.data`) и видны в
Assets-табе + Timeline (asset-события), но `attack_surface.build_surface` их ронял:
«Subdomains» читала только `subdomains.results`, «Endpoints» — `katana+security`,
«Technologies» — `recon` → BBOT-only активы молча выпадали из графа атак-поверхности
и `surface_score`. Фикс: `build_surface` мёржит `bbot.data` hosts→Subdomains,
endpoints→Endpoints, technologies→Technologies (дедуп против нативных), переиспользуя
**те же предикаты apex/host** (`asset_adapter._is_concrete_host`/`_host_of`, ленивый
импорт — SSOT, поэтому граф совпадает с инвентарём; apex/wildcard/out-of-scope хосты
отфильтрованы как в инвентаре). ips/asns/netblocks BBOT в Infrastructure НЕ вливаются
(там Domain→ASN→IP-цепочка из recon-geo, host-уровневые BBOT-узлы — отдельная ось,
как co-hosted). Pure, без новых зависимостей. **Числа surface_score для BBOT-сканов
выросли сознательно** (граф недосчитывал то, что инвентарь уже считал); легаси-отчёты
без bbot-фазы — байт-в-байт (gate `if bbot`). Покрыто `test_attack_surface`
(мёрж+дедуп hosts/endpoints/tech, apex/scope-фильтр, отсутствие bbot=без изменений).

**EPIC 3 — CVE Intelligence (фаза 1: JS-либы) — `[ЗАКРЫТ]`.** Мульти-источниковый
CVE-движок поверх существующего OSV-пайплайна (расширение, не дубль). Новые модули:
`core/cve_store.py` (SQLite `data/cve_cache.db`, `SQLiteStore`, user_version=1 —
таблицы lib_cves+cve_details с fetched_at; **оффлайн-фундамент**: свежий хит минует
сеть / устаревший рефрешится онлайн / при недоступной сети переиспользуется),
`core/nvd_provider.py` (NVD 2.0 обогащение по CVE id: CVSS v3.1>v3.0>v2, severity-
бакет через osv-SSOT, published/summary; keyless+опц. `nvd_api_key`; инъектируемый
`_get_text`), `core/cve_intel.py` (ОРКЕСТРАТОР `correlate`→`_enrich`→cache: чистая
либа НЕ закрепляется за stale-хитом, провайдер-down → stale; `to_findings` с CVSS+
датой; `summarize` для метрики). Проводка: `osv_correlation._parse_osv` +published/
+cvss (аддитивно); `collection_runner._phase_osv` → cve_intel, пишет `cve_summary`;
`executive_summary` **МЕТРИКА** `cve_total/high/medium` + headline-чип «N CVE» —
**НЕ слагаемое risk-score** (каждый CVE считается раз через severity находки, §12 —
решение пользователя «CVE Score = метрика»); `dependency_audit.render_html` CVE·CVSS·
дата; GUI clear-cache + `nvd_api_key`/`CVE_CACHE_DB`. **Dedup автоматом** (findings_
adapter мёржит nuclei+OSV+bundled по CVE id). Решения пользователя: метрика / NVD
live+кеш / фаза 1 только JS (server-версии через CPE — фаза 2). EPIC 4 (Historical
Intelligence) на тот момент в scope не входил — **закрыт позже** отдельным блоком
ниже. Покрыто `test_cve_store`/`test_nvd_
provider`/`test_cve_intel` (+17) + правки `test_osv_correlation`/`test_executive_
summary`. 1214 collected, full suite PASS, ruff чист.

**EPIC 4 — Historical Intelligence (тренды риска + история изменений) — `[ЗАКРЫТ]`.**
Аудит: ~85% уже было (история — `timeline.build_events`/Timeline/web `/timeline`/
`timeline_csv`; тренды — `build_series` + sparklines в report.html и Overview +
`portfolio.risk_delta`). Решение пользователя: scope = **backend-аналитика поверх
существующего визуала, GUI не трогать** (`feedback-internals-first-no-gui`). Добавлено
(всё pure derive-on-read, без новых данных/деп): `core/trends.py` —
`trend_summary(series)` → per-metric `{n, current, baseline, delta_total (vs ПЕРВЫЙ
скан), direction (up/down/flat), peak, low}` (+ `metric_trend`/`risk_direction`;
пропуск None-точек, не фейковый 0). Проводка: `report['trends_summary']` рядом с
`report['trends']`; `_render_trends_card` +строка-вердикт «Риск: ↑ рост (a→b, ±N с
первого скана)»; `report_export.history_csv` (экспорт risk-истории, брат
`timeline_csv`); web `_timeline_view` +`trend`-сводка; `portfolio` row +`risk_trend`
(направление за всю историю, рядом с `risk_delta`=latest-vs-prev). Историю изменений
НЕ дублировал (build_events уже полная). Покрыто `test_trends`(7) + history_csv/
portfolio/web/collection_runner-verdict (+13 всего). EPIC 4 ЗАКРЫТ.

**EPIC 5 — Asset Correlation Engine & Exposure Intelligence — `[ЗАКРЫТ]`.** «От хранения
активов к пониманию отношений между ними». Аудит: `correlation.py` (F-K) — finding-
центричный (Finding→Asset→Infra); чистых **asset↔asset** отношений не было. Решения
пользователя: scope = **backend (GUI отложить)**, exposure-кластеры = **display-метрика**
(не слагаемое score — F-R4 уже считает концентрацию находок). Новый `core/asset_graph.py`
(pure derive-on-read, **без новой схемы**): `build_asset_graph(assets)` → `{nodes, edges}`
с рёбрами apex(domain→subdomain)/resolves(host→ip)/announces(ip→asn)/contains(netblock∋ip
через `ipaddress`)/serves(endpoint→host) **только между существующими активами** (CIDR-матч
и `_host` переиспользуют `correlation` — одна реализация); `asset_neighbors`;
`shared_infra(min_members=2)` → **Exposure Intelligence**: host-активы, делящие ip/asn/
netblock (single point of exposure, blast radius на уровне активов; ASN хоста — через его
ip-актив); `load_asset_graph(project)` тонкий ридер + summary. Проводка:
`collection_runner._build_asset_graph` → `report['asset_graph']` + карточка «Asset
Relationships»; web `_correlation_view` +`asset_graph` (+ console-вывод кластеров);
`executive_summary` метрика `exposure_clusters/exposure_largest` + чип «N× co-hosted»
(medium, display — ярлык отличает от F-R4 «shared infra»). Все рёбра из существующих attrs
(новых данных нет). GUI не тронут. Покрыто `test_asset_graph`(6) + web/es/report-card
(+10 всего). EPIC 5 ЗАКРЫТ. **Хвост — Exposure-кластер в Scan Diff/Timeline:**
`shared_infra` вычислялся, но не диффился → ново-сформированный single-point-of-exposure
был невидим в ленте. Секция scan_diff `exposure` (фаза-гейт `subdomains`; `_extract_exposure`
из `report['asset_graph'].shared_infra`, keyed by node) → `diff_events` эмитит
`new_exposure_cluster` (medium, **timeline-only** — структурный discovery, не алертабелен,
как `new_subdomain`). Метка в `gui/tab_timeline`. +2 теста.

**EPIC 6 — Launcher & Dependency Management — `[ЗАКРЫТ]`.** Единый Launcher
(Install/Repair/Update/Launch), offline-first, **без обязательного update-сервера**.
Аудит: Launcher'а не было, но `core/features.py` (OPTIONAL_FEATURES/summary()/missing();
pip-модуль `find_spec` vs PATH-бинарник `which`) и `PathManager` уже есть. Решения
пользователя: **engine+UI** (pure core + тонкий UI), локальный update зависимостей
(pip --upgrade; без remote git), внешние бинарники → инструкции (не качаем).
Новый `core/launcher.py`
(pure, subprocess инъектируется): `REQUIRED={qtpy,PySide6,requests,beautifulsoup4}`
(lxml опц.); `health_check` (REQUIRED + **переиспользует** `features.summary()` для
OPTIONAL + `PathManager.get_temp_path` write-probe — **PathManager не дублирован**);
`installable_components` (pip vs manual); `install_optional` (pip-модуль / инструкция+
URL для бинарника); `repair` (pip install -r requirements.txt); `update`
(pip --upgrade -r requirements.txt; `git pull/fetch/push/clone` запрещены правилами
без явного разового разрешения); `launch_app` (subprocess). Тонкий `launcher.py` (root):
`run_cli(argv)` (`--health/--components/--install/--repair/--update/--launch`, exit-коды) +
Qt-окно `LauncherWindow` (Module 5: 5 кнопок; fast синхронно, Repair в QThread;
переиспользует `gui.ui_components`). **Переиспользовано:** features, PathManager,
`external_tools.run_command` (never-raise subprocess), ui_components. Архитектура цела
(изолированный модуль+entry). Живая проверка: `--health` поймал реально отсутствующий
bs4. Покрыто `test_launcher`(15) + `test_launcher_cli`(7). EPIC 6 ЗАКРЫТ.

**EPIC 7 — Core Intelligence Framework — `[ЗАКРЫТ]`.** «От обнаружения к объяснению»:
Confidence + Priority + Explanation per finding. Аудит: confidence/priority не было,
но все входы есть (`Finding.sources` корроборация, `secret_validator`/`is_high_value_
secret` валидация, `finding_knowledge` объяснение, `correlation.exposure`+`asset_graph.
shared_infra` exposure/blast-radius, `findings_sla` срочность, severity). Решения
пользователя: **backend** (GUI отложить), формулы как предложено (confidence
**дисконтирует** severity в priority), **отдельный `/intelligence`**. Новый
`core/intelligence.py` (pure derive-on-read, **без новых моделей**): `confidence` =
base(категория; cve-rule→85) + корроборация(+10/источник, cap 20) + валидация
(высокоценный секрет +15) → 0–100 + band; `priority` = round(severity_base ×
conf/100) + exposure(+10 blast / +5 correlated) + SLA(+10/+5), cap 100; `explain` →
`finding_knowledge.describe`; `build_intelligence` ранжирует (priority desc) с
factors; `load_intelligence(project)` тонкий ридер. Проводка:
`collection_runner._build_intelligence` → `report['intelligence']` + карточка
«Priorities»; web `/intelligence` (+ кнопка/JS в консоли); `executive_summary`
метрики `top_priority`/`high_confidence_findings` (display, НЕ слагаемое — priority
выведен из severity). **Переиспользовано:** findings_store, correlation, asset_graph,
finding_knowledge, findings_sla, `_is_high_value_secret_finding`, severity. Новых
таблиц/моделей — ноль. Покрыто `test_intelligence`(11 unit) + `test_web_intelligence`
(4 integration: стор→корреляция→граф→ранжирование+live) + es-метрика/card (+19). EPIC 7 ЗАКРЫТ.

**EPIC 7 GUI-хвост — `[ЗАКРЫТ]`.** Снят отложенный по решению пользователя GUI:
вкладка «Priorities» (`gui/tab_intelligence.py`, `IntelligenceTabMixin`) — read-only
поверхность над `intelligence.load_intelligence`. Per-project (как Timeline/
Correlation → селектор без «Все проекты», дефолт — первый проект), 3 rollup-карты
(Находок/Высокая увер./Макс. priority из `summary`), таблица `[Priority, Confidence,
Severity, Категория, Заголовок]` (ранжирование backend'а priority desc), панель
деталей (explanation описание/воздействие/remediation + факторы priority+confidence,
объяснимость числа). Двухстадийная off-thread загрузка (`FindingsStore.projects()` →
`load_intelligence`) по образцу Assets; lazy-load в `tab_history._on_tab_changed`;
регистрация в `BUILTIN_TABS` (секция «Управление», после Findings). Export CSV —
`report_export.intelligence_csv` (flatten `explanation`, паритет со всеми data-
вкладками). UI тонкий (вся логика в `core/intelligence.py`), без новых зависимостей,
risk-числа не тронуты (priority — display). Покрыто `test_intelligence_tab`(9) +
`intelligence_csv` в `test_report_export`(3). **Web-паритет был с EPIC 7
(`/intelligence`); теперь поверхность есть и в GUI.**

**Advanced Intelligence Framework — MODULE 1: Unified Scan Accuracy — `[ЗАКРЫТ]`.**
Backend-фаза, расширение EPIC 7 (решение пользователя: «расширять, не дублировать» +
жить в `core/intelligence.py`, НЕ новый `accuracy.py` — память
`project-advanced-intelligence`). EPIC 7 дал confidence/priority/explanation **только
для findings**; MODULE 1 обобщает «насколько это достоверно?» на ВСЕ сущности.
Добавлено в `core/intelligence.py` (pure / derive-on-read, без новых таблиц):
`confidence_for(entity_type, entity)` → единый словарь `{score, band, factors,
evidence, source, verification}` для 7 типов — `finding / technology / cve / asset /
infrastructure / api / secret`. Один движок, ноль дублей: каждый тип переиспользует
готовый сигнал достоверности — `secret_validator.validate` (секреты: VALID→+20,
INVALID-плейсхолдер→−35), `executive_summary.is_high_value_secret`/
`_is_high_value_secret_finding` (tier), evidence-метод из `tech_fingerprint`
(`header:`/`cookie:`/`script:`>`html`), CVSS+мульти-БД из `cve_intel`,
`Asset.attrs.source` (probed>tls-observed>derived), active-RDAP vs passive-derive у
infrastructure, 2xx-ответ у API. `build_accuracy(entities_by_type)` — чистый
агрегатор (rollup `{by_type, items confidence-desc, summary}`), развязан от формы
report (extraction = EPIC 12). `confidence()` отрефакторён на общие `_clamp`/`_band`
(вывод **байт-в-байт** прежний, контракт тестов цел). `build_intelligence` items
получили аддитивные `evidence`/`source`/`verification` (через `confidence_for`).
Risk-вердикт НЕ тронут (display-метрики — решение пользователя). Покрыто
`test_intelligence.py` (+13: per-type confidence_for, build_accuracy rollup,
unified-поля в build_intelligence). 1227 collected, full suite PASS, ruff чист.
**Все запланированные продолжения закрыты** (отдельными блоками ниже): Asset
Criticality (EPIC 9), Priority deepening (EPIC 10), Attack Paths (EPIC 11) —
display-метрики; Surfaces report/web (EPIC 12) + Scan Accuracy GUI+web и
GUI-хвосты Criticality/Attack Paths/Exposure; Monitoring (EPIC 13). Advanced
Intelligence имеет полный GUI+web+report+monitoring паритет — MODULE 1 закрыт.

**Advanced Intelligence Framework — EPIC 9: Asset Criticality — `[ЗАКРЫТ]`.**
Backend+report-фаза (паттерн EPIC 5/7). «Какой актив важнее» (priority = «какую
находку чинить первой»; criticality = «какой актив важнее») — **display-метрика, НЕ
слагаемое risk-score** (решение пользователя; `_risk_level`/`risk_100` не тронуты).
Добавлено в `core/intelligence.py` (pure / derive-on-read, без новых данных):
`asset_criticality(asset, *, dependents, findings)` → `{score 0-100, band, factors}`
из тип-веса (`_ASSET_TYPE_WEIGHT`: domain 40 … technology 8) + blast radius
(зависимые активы) + worst-severity находок + exposure (takeover +20 / reachable +5);
`build_asset_criticality(assets, correlation, asset_graph)` ранжирует — blast radius
из `asset_graph` (входящие рёбра + размер shared-infra кластера, матч по (type,value)),
находки из `correlation` (`asset_findings` + host-роллап `exposure` + инфра-концентрация
`infra_exposure`); `load_asset_criticality(project)` тонкий ридер. **Переиспользует**
correlation + asset_graph (уже построены до этого в `run`), ноль новых таблиц.
Проводка: `collection_runner._build_asset_criticality` → `report['asset_criticality']`
(после `_build_asset_graph`) + карточка «Asset Criticality» (`_render_asset_criticality_card`);
`executive_summary` display-метрики `critical_assets`/`top_asset_criticality`
(`_asset_criticality`, читает summary; НЕ score-фактор) + headline-чип «N critical
assets». Покрыто `test_intelligence`(+6: тип-вес/band, blast+findings, takeover/reachable,
build-ранжирование, empty), `test_executive_summary`(+2: метрика+чип/zero, risk_score
неизменен), `test_collection_runner`(+1: карточка). Risk-числа байт-в-байт.

**Advanced Intelligence Framework — EPIC 10: Priority deepening — `[ЗАКРЫТ]`.**
Вплёл Asset Criticality (EPIC 9) в ранжирование находок: `intelligence.priority`
получил опц. `criticality_band` → бонус (high +10 / medium +5) поверх severity×
confidence + exposure + SLA — та же находка на более важном активе чинится раньше.
`build_intelligence` принял опц. `criticality` (rollup из `build_asset_criticality`),
строит `value→band` карту и прокидывает band находки в `priority` + в item-поле
`asset_criticality`; `load_intelligence` строит criticality из **уже загруженных**
correlation+asset_graph (без дублирующих чтений стора). priority — display (не
risk-score), вердикт не тронут. Обратная совместимость: `criticality`/
`criticality_band` опциональны (None → поведение прежнее, тесты EPIC 7 целы).
Покрыто `test_intelligence`(+2: priority-бонус high/medium/low, build с criticality).

**Advanced Intelligence Framework — EPIC 11: Attack Paths — `[ЗАКРЫТ]`.**
Последний вопрос фреймворка — «как это связано». Латеральный путь = находко-несущий
exposed-хост делит инфра-узел (ip/asn/netblock) с другими хостами → компрометация
слабого entry даёт pivot ко всем co-located активам, часть из которых критичны. Это
превращает Exposure-кластеры (EPIC 5) + находки на них (correlation) + criticality
(EPIC 9) в явный рассказ «entry → pivot → targets». Добавлено в `core/intelligence.py`
(pure / derive-on-read, без новых данных): `build_attack_paths(correlation,
asset_graph, criticality)` — на каждый shared-infra кластер с ≥1 находко-несущим
членом и ≥1 другим: worst-severity член = entry, узел = pivot, остальные = targets
(критичные считаются отдельно); `score` = severity entry (`_PATH_SEV_PTS`) + размер
кластера + critical_targets×5, band high≥60/medium≥35; `load_attack_paths(project)`
тонкий ридер. **Переиспользует** `correlation._sev`/`_SEVERITY_RANK`, shared_infra,
exposure, criticality (уже построены). Проводка: `collection_runner._build_attack_paths`
→ `report['attack_paths']` + карточка «Attack Paths» (`_render_attack_paths_card`);
`executive_summary._attack_paths` → метрики `attack_paths`/`critical_attack_paths`/
`top_attack_path` (НЕ score-фактор) + headline-чип «N attack paths» (high если есть
критичный target). Display-only, вердикт не тронут. Покрыто `test_intelligence`(+3:
латеральный путь score=41/targets/crit, нет entry→нет пути, empty),
`test_executive_summary`(+2), `test_collection_runner`(+1).

**Advanced Intelligence Framework — EPIC 12: Surfaces (report/web) — `[ЗАКРЫТ]`.**
Вывод intelligence-сигналов на поверхности. **MODULE 1 Scan Accuracy:**
`intelligence.accuracy_from_report(report, findings, assets)` собирает все
просканированные сущности (technologies/infrastructure/API/secrets из фаз отчёта +
findings/assets из сторов; CVE = findings) и скорит через `build_accuracy`;
`collection_runner._build_accuracy` → `report['accuracy']` (summary + by_type +
low_confidence top-10) + карточка «Scan Accuracy» (`_render_accuracy_card`);
`executive_summary._scan_accuracy` → display-метрики `scan_accuracy_avg`/
`low_confidence_entities` (НЕ risk-сигнал, без чипа — мера доверия к детекции, не
экспозиции). **Web-паритет EPIC 9/11:** `remote/web_app._criticality_view`/
`_attack_paths_view` поверх `load_asset_criticality`/`load_attack_paths`; роуты
`GET /criticality` + `GET /attack-paths` + кнопки в консоли (per-project, пустой →
пустой вью). Покрыто `test_intelligence`/`test_executive_summary`/
`test_collection_runner`/`test_web_intelligence`. Коммиты 432a265 + ddb7f95.

**Advanced Intelligence Framework — EPIC 13: Monitoring — `[ЗАКРЫТ]`.** Сделал
intelligence-сигналы наблюдаемыми между сканами. Закрыт последний «вычисляется-но-
теряется» пробел: attack paths (EPIC 11) считались в `report['attack_paths']`, но не
диффились → ново-сформированный латеральный путь не давал ни события, ни алерта.
**Scope:** мониторим Attack Paths (эксплуатируемая эскалация); Asset Criticality
осознанно НЕ мониторим (непрерывный display-ранкинг из сигналов, которые уже
алертятся → избыточный шум). `scan_diff`: секция `attack_path` (фаза-гейт
`subdomains`, как exposure), `_extract_attack_path` читает `report['attack_paths'].
paths` keyed by стабильной pivot-identity «{type} {node}» (один путь на кластер),
value несёт band → эскалация (band растёт) видна как *changed*, churn entry/targets
под стабильным band — нет (`_changed_entry` attack_path-ветка). `diff_events`:
`new_attack_path` (high, alertable — как `new_sourcemap`; фаерится рядом с
`new_exposure_cluster` на разных осях, как takeover ⊂ subdomain) и
`attack_path_escalated` (high, alertable — band поднялся через `_band_rank`; падение
band = улучшение, не событие, как DMARC-апгрейд). `alerts.ALERT_TYPES` += обе;
метки в `gui/tab_timeline`+`gui/dialogs`. Web-паритет автоматом (общий `diff_events`).
Покрыто `test_diff_events`(+2)/`test_scan_diff`(+1, section-coverage += attack_path).
**Advanced Intelligence Framework (EPIC 8–13) полностью закрыт** — backend + report +
web + мониторинг; GUI-вкладки Criticality/Attack Paths опциональны (память
`feedback-internals-first-no-gui`).

**Scan Accuracy — GUI + web (MODULE 1 surface parity) — `[ЗАКРЫТ]`.** Закрыт
последний пробел поверхностей MODULE 1: «насколько достоверен детект» имел
report-карточку + es-метрики, но (в отличие от Criticality/Attack Paths) НЕ имел
ни GUI-вкладки, ни web-эндпоинта. Добавлено (всё derive-on-read, без новых
данных/таблиц): **core** `intelligence.load_accuracy(project)` — тонкий
**report-based** ридер (как `timeline.build_timeline` — accuracy нужны фазы скана,
не только сторы): берёт `report.json` последнего скана (`project.latest_scan()['id']`
→ `load_scan_report`) + active-находки/активы из сторов → `accuracy_from_report`
(полный `{by_type, items, summary}`); guarded, пустой вид при отсутствии
скана/ошибке. **web** `remote/web_app._accuracy_view` (резолвит проект из
`_REPORT_BASE` через `ProjectStore`, как `_timeline_view`) + роут `GET /accuracy` +
кнопка «Scan Accuracy»/`showAccuracy()` в консоли. **GUI** вкладка «Scan Accuracy»
(`gui/tab_accuracy.py`, `AccuracyTabMixin`) — read-only, **зеркало Timeline-таба**
по резолву проектов (`ProjectStore(output_dir).list_projects()`, двухстадийная
off-thread загрузка base+slug), плюс паттерн Criticality (3 rollup-карты
Сущностей/Высокая увер./Средняя увер.; таблица `[Confidence, Band, Тип, Сущность,
Проверка]` confidence-desc; панель деталей с evidence+source+verification+факторами).
band-цвет инвертирован (`_BAND_SEVERITY`: low-band красится attention-цветом — это
детекты на двойную проверку). Регистрация в `BUILTIN_TABS` (секция «Управление»,
после Attack Paths), lazy-load в `tab_history`, init-флаги в `main_window`. **Export
CSV** — `report_export.accuracy_csv` (flatten source/evidence). UI тонкий (логика в
`core/intelligence`), risk-числа не тронуты (accuracy — мера доверия к детекции, не
экспозиции; без чипа/score-фактора). Покрыто `test_accuracy_tab`(10) +
`accuracy_csv` в `test_report_export`(2) + web в `test_web_intelligence`(5: scores/
empty/unknown/dashboard/live endpoint). **Advanced Intelligence: полный
GUI+web+report паритет по всем поверхностям (Priorities/Criticality/Attack Paths/
Scan Accuracy).**

**Advanced Intelligence — GUI tail (Criticality + Attack Paths) — `[ЗАКРЫТ]`.**
Снят отложенный по решению пользователя GUI: две read-only вкладки, точное зеркало
паттерна Priorities-вкладки (EPIC 7 GUI tail) — аддитивные, GUI НЕ перестраивается
(память `feedback-internals-first-no-gui`; прецедент Priorities принят). **(1)**
«Asset Criticality» (`gui/tab_criticality.py`, `CriticalityTabMixin`,
`_build_criticality_tab`) поверх `intelligence.load_asset_criticality`: per-project
селектор (источник проектов — `AssetStore.projects()`, т.к. криткритичность —
про активы), 3 rollup-карты (Активов/Высокая крит./Макс. крит.), таблица
`[Criticality, Band, Тип, Актив]` (ранжирование backend'а crit-desc), панель факторов
(объяснимость числа). **(2)** «Attack Paths» (`gui/tab_attack_paths.py`,
`AttackPathsTabMixin`, `_build_attack_paths_tab`) поверх `load_attack_paths`:
тот же per-project паттерн, таблица `[Score, Band, Entry, Pivot, Targets, Critical]`,
панель «entry → pivot → targets». Обе: двухстадийная off-thread загрузка
(`AssetStore.projects()` → `load_*`) по образцу Assets/Priorities, lazy-load в
`tab_history._on_tab_changed`, регистрация в `BUILTIN_TABS` (секция «Управление»,
между Priorities и Assets), init-флаги в `main_window`. Export CSV —
`report_export.criticality_csv`/`attack_paths_csv` (flatten factors/targets, паритет
со всеми data-вкладками). UI тонкий (вся логика в `core/intelligence.py`), без новых
зависимостей, risk-числа не тронуты (criticality/paths — display). Покрыто
`test_criticality_tab`(7)/`test_attack_paths_tab`(7) + `criticality_csv`/
`attack_paths_csv` в `test_report_export`(4). **Web-паритет был с EPIC 12
(`/criticality`,`/attack-paths`); теперь поверхность есть и в GUI — Advanced
Intelligence имеет полную GUI+web+report+monitoring проводку.**

**Asset Exposure (likelihood axis) — `[ЗАКРЫТ]`.** Закрыт единственный
запрошенный, но отсутствовавший скаляр из 4-формульного ТЗ Intelligence Foundation:
нормализованный **per-asset Exposure Score (0–100)**. Из четырёх формул три уже были
именованными величинами (`confidence`/`asset_criticality`/`priority`); экспозиция
жила лишь в двух не-нормализованных местах (`attack_surface.surface_score` —
проектная breadth; `correlation.exposure` — список хостов без балла). Классический
risk = likelihood × impact: `asset_criticality` ≈ **impact** (доминирует type-вес);
не хватало **likelihood**-оси — «насколько актив достижим/атакуем прямо сейчас».
Расширение `core/intelligence.py` (НЕ новый движок — память
`project-advanced-intelligence`), всё pure/derive-on-read, **переиспользует те же
входы**, что `build_asset_criticality` (`_dependents_map` из asset_graph,
`_asset_findings_map` из correlation, `Asset.attrs` reachability/takeover): новый
`exposure_score(asset, *, dependents, findings, cluster_size)` = reachability
(takeover +35 / public-2xx +20 / resolved +5) + открытые находки (worst-sev
crit30/high20/med10/low4 + min(10,(cnt−1)×2)) + blast radius
(min(20, max(dependents, cluster_size−1)×5)), clamp 0–100, band high≥60/med≥30/low —
**без type-веса** (отличие от criticality: likelihood, не impact). `build_exposure`
(ранжирование, как `build_asset_criticality`) + `load_exposure(project)` (тонкий
ридер) + новый `_cluster_size_map` (host→размер co-hosted кластера для blast). Это
**display-метрика, НЕ слагаемое risk-score** (вердикт `_risk_level` не тронут — как
criticality/paths/accuracy). Проводка-паритет по образцу EPIC 9/Scan Accuracy:
`collection_runner._build_exposure` → `report['exposure']` (после
`_build_asset_criticality`) + карточка «Asset Exposure» (`_render_exposure_card`);
`executive_summary._asset_exposure` → display-метрики `exposed_assets`/`top_exposure`
+ headline-чип «N exposed assets» (medium); web `_exposure_view` + `GET /exposure` +
кнопка/`showExposure()` в консоли; GUI вкладка «Asset Exposure»
(`gui/tab_exposure.py`, `ExposureTabMixin` — точное зеркало Criticality-таба,
per-project через `AssetStore.projects()`, секция «Управление» между Criticality и
Attack Paths); `report_export.exposure_csv` + `_EXPOSURE_COLUMNS` + Export-кнопка.
Risk-числа байт-в-байт (фактор 0, экспозиция нигде не складывается в score). Покрыто
`test_intelligence`(+6: no-type-weight/reachability-tiers/findings+blast/cluster-blast/
ранжирование/empty), `test_exposure_tab`(+8), `test_report_export`(+2),
`test_web_intelligence`(+1 view + assert в no-project/dashboard/testclient),
`test_executive_summary`(+2: метрика+чип/zero), `test_collection_runner`(+1: карточка).
1386 collected, full suite PASS, ruff чист. **Полный GUI+web+report паритет по
likelihood-оси — все 4 формулы Intelligence Foundation теперь именованные величины с
поверхностями.**

**Infrastructure chain — Cloud + Region классификация (EPIC infra-chain, phase 1) —
`[ЗАКРЫТ]`.** Backend-фаза. Достроена инфра-цепочка Domain→Subdomain→IP→ASN→Provider→
**Cloud→Region**→Certificate→Related Assets: первые 5 и Certificate/Related уже были
(`asset_graph` рёбра, `infrastructure.py`, `correlation` chain, `asn_intel`), не
хватало **нормализованного Cloud** и **структурного Region**. Решение: единый pure
`core/cloud_classifier.py` (`classify_cloud(provider, asn_name, asn, technologies,
cname)` → `{cloud, confidence, evidence}` или `{}`) — табличный матч по уже собранным
сигналам (provider/ASN-строка, CDN-tech из `tech_fingerprint`, takeover-CNAME из
`subdomain_active`), **сильнейший сигнал**: exact ASN-номер (90) > provider-keyword
(80) > CDN-tech (75) > CNAME (70); unknown остаётся unknown (нет догадок). Offline,
без сети/зависимостей, **не входит в risk-score** (display/derive, как exposure/
criticality). Проводка: `infrastructure.build_infrastructure` — структурные
`cloud`/`region`/`country` + hops Cloud/Region в `chain` + `render_html` (cloud
`#e65100`, region `#00838f`; cloud классифицируется по always-available provider/ASN,
т.к. recon строит infra ДО technologies — порядок учтён); `asset_adapter` кладёт
`cloud`/`region` в attrs domain/ip/asn (из infra) и **per-subdomain cloud из CNAME**
(аддитивно, identity байт-в-байт → ноль churn в сторе). **True cloud-region**
(`us-east-1`) **намеренно НЕ выдумывается** — не выводим offline из GeoIP. Покрыто
`test_cloud_classifier`(11: keyword/ASN/CDN/CNAME/unknown/strongest-wins/bad-types),
`test_infrastructure`(+3: cloud+region в chain/ASN-номер→AWS/unknown без hop),
`test_asset_adapter`(+4: cloud/region attrs domain/ip/asn, subdomain-cloud-from-CNAME,
no-cname→no-cloud, identity-инвариант). **Не делалось** (осознанно): cloud/region в
risk-score, новые SQLite-таблицы, сетевые cloud-лукапы, GUI.

**Infrastructure chain — Phase 2 (co-hosted related assets) — `[ЗАКРЫТ]`.** Bulk уже
был сделан в `feea0a6` (не отражён в статусе): derive-view `asn_intel.related_assets`/
`related_assets_from_report`/`load_related_assets` (co-hosted домены с reverse-IP минус
свои хосты) + report-карточка «Related Assets» (`report['related_assets']`) + web
`/related-assets` + кнопка + тесты. **Хвост (этот инкремент)** — surface co-hosted в
`asset_graph` (решение пользователя: asset_graph, backend+report+web; correlation НЕ
трогаем). Co-hosted соседи добавляются как **внешние (non-owned) узлы** типа `related`
(`external:True`) с ребром `co_hosted` от **owned**-IP-узла — **никогда** не пишутся в
`AssetStore` (уважает явное решение `asn_intel.py:210`: co-hosted ≠ наш актив, промоут
дал бы ложные ownership/takeover-сигналы). `build_asset_graph(assets, related=None)` +
`_add_co_hosted` (anchor только если shared_ip — owned `ip`-актив; дедуп + фильтр
коллизий со своими узлами); `load_asset_graph(project, related=None)` — summary держит
`nodes`/`edges` = **owned**-топология (внешние узлы/co_hosted-рёбра вынесены в
отдельный `related`-счётчик → существующие метрики не инфлейтятся). Проводка:
`collection_runner._build_asset_graph` передаёт `related=related_assets_from_report(report)`
(читает asn_intel-фазу напрямую → порядок с `_build_related_assets` неважен), карточка
«Asset Relationships» показывает «со-хостящихся доменов: N»; web `_correlation_view`
резолвит проект → `load_related_assets` → `load_asset_graph(project, related=…)` +
JS-консоль печатает co-hosted. **Гарантия:** criticality/exposure/attack_paths/
`shared_infra` не тронуты — они зовут `load_asset_graph(project)` БЕЗ related (внешние
узлы не owned-активы → blast-radius owned-активов и `_dependents_map` не меняются;
co_hosted-ребро идёт от IP к внешнему `dst`, IP как `src` не инфлейтится). Покрыто
`test_asset_graph`(+7: внешние узлы/ребро/anchor-skip/дедуп/related=None unchanged/
load-summary owned-only/shared_infra игнорит external), `test_collection_runner`(+2:
карточка показывает/скрывает co-hosted), `test_web_intelligence`(+1: correlation-view
surface). **Не делалось** (осознанно): промоут co-hosted в AssetStore, correlation,
GUI, влияние на risk/criticality/exposure.

**EPIC 15 — Technology Risk Scoring — `[ЗАКРЫТ]`.** Полный backend+report+web+CSV+GUI
паритет (GUI-вкладка добавлена — см. ниже). Чистый **display-слой**
(derive-on-read, **НЕ слагаемое risk-score** `_risk_level`/`risk_100` — как
exposure/criticality/accuracy): «какие из обнаруженных технологий/JS-зависимостей
заслуживают внимания» — EOL/устаревшие версии и уязвимые либы, **без двойного счёта
CVE** (уязвимые деп уже считаются через находки, EPIC 3). Новый pure
`core/tech_risk.py` (`build_technology_risk(report)` — читает только `phases.recon.data`
technologies+dependencies; консервативные `_TECH_POLICIES` PHP<8.1/AngularJS/Flask +
`_DEPENDENCY_EOL`; version-exposed для Server/Backend/Language; band high≥60/medium≥25/
low>0/clean; degrade-not-raise по этосу F-SR1; `load_technology_risk(project)` тонкий
report-based ридер, зеркало `intelligence.load_accuracy`). Проводка-паритет по образцу
Scan Accuracy: `collection_runner._build_technology_risk` → `report['technology_risk']`
(`{summary, top:10}`) + карточка «Technology Risk» (`_render_technology_risk_card` —
**был написан, но не вызван; хук добавлен**, закрыт техдолг); `executive_summary.
_technology_risk` → display-метрики `tech_risk_score`/`outdated_technologies`/
`vulnerable_dependencies` + headline-чип «N outdated components» (medium, НЕ score-
фактор — числа риска байт-в-байт); web `_technology_risk_view` + `GET /technology-risk`
+ кнопка «Technology Risk»/`showTechnologyRisk()` в консоли; `report_export.
technology_risk_csv` (+`_TECHNOLOGY_RISK_COLUMNS`). Покрыто `test_tech_risk`(16:
EOL/version-exposed/vuln-деп/clamp/band/сортировка/summary/empty/malformed/reader),
`test_executive_summary`(+2: метрика+чип/zero, risk_score неизменен),
`test_report_export`(+2), `test_web_intelligence`(+5: view/empty/unknown/dashboard/
testclient), `test_collection_runner`(+3: карточка/build/skip-when-empty). **GUI-
вкладка добавлена** (`gui/tab_technology_risk.py`, `TechnologyRiskTabMixin` — зеркало
Scan Accuracy: per-project report-based, таблица risk-desc с band-подсветкой (high =
attention), rollup-карты, панель причина+доказательства, Export CSV; секция
«Управление» после Scan Accuracy; lazy-load в `tab_history`; покрыто
`test_technology_risk_tab`(10) + `TechnologyRiskHost`). **Не делалось** (осознанно):
влияние на risk-score, новые таблицы, расширение EOL-политик за консервативный
минимум (для CVE есть EPIC 3). **EPIC 15 имеет полную GUI+web+report+CSV проводку.**

**EPIC 16 — Integrations & Reporting (wave 1) — `[ЗАКРЫТ]`.** Безопасная волна
интеграций без новых тяжёлых зависимостей (всё stdlib, opt-in). **F0+F1** SARIF
2.1.0 экспорт находок (`report_export.findings_sarif`: `APP_VERSION` из config;
каждая находка → SARIF result, пары category/rule_id → reportingDescriptors с
description/impact/remediation из `finding_knowledge` (то же обогащение, что
`findings_csv`); severity → SARIF level + numeric security-severity для GitHub;
`evidence.location` → physicalLocation URI; пустой список = валидный пустой run).
**F2** Markdown-отчёт. **F3** generic-webhook alert-канал (снят отложенный YAGNI из
F4 Alert Center — плоский POST). **F4 CI/CD-gate** (`core/ci_gate.py` pure-политика
+ `monitor_cli ci`): `evaluate_gate(events, fail_on='high')` фейлит сборку, если
появилась новая находка ≥ порога severity (counts/triggers/total; пустой/None =
PASS, как первый скан без baseline); `exit_code`/`summary_line` — CLI-обёртки.
Команда `monitor_cli ci <url>` — тонкая оркестрация: прогон скана через
`CollectionRunner` (или `--no-scan` гейтит два последних существующих скана) →
**канонический change-feed `timeline.build_timeline`, отфильтрованный по текущему
scan_id** (НЕ сырой `diff_events`: свежая generic high/critical vuln всплывает как
`new_finding` с её severity только через F1-lifecycle; timeline мёржит это с
Scan-Diff регрессиями takeover/source-map/GraphQL/dependency) → `ci_gate` →
process exit-code; опц. `--sarif-out` пишет SARIF активных находок. Первый скан
без baseline = PASS. Покрыто `test_ci_gate`(7: пороги/exit/summary/non-dict/empty)
+ `test_monitor_cli`(+4: single-scan PASS, takeover→critical FAIL, scan вызывает
run_fn, SARIF записан). Коммиты c42e70c (F0+F1) / 041da8c (F2) / ba7cbf4 (F3) /
28cf617 (F4).

**EPIC 16 — wave 2: GitHub Issues push (B2) — `[ЗАКРЫТ]`.** Открывает GitHub-issue
на каждую активную находку (триаж/закрытие в трекере). **Create-only и
идемпотентно**: маппинг `находка→issue` = событие `ISSUE_CREATED` в **существующей**
таблице `finding_events` (`note={number,url}`) — без новой таблицы, без schema-bump;
переоткрытая находка (новый REOPENED-эпизод) снова получает issue; авто-закрытие при
FIXED осознанно отложено. `core/github_issues.py` (pure-логика + инъектируемый
urllib-транспорт `_api_request`, зеркало `alerts.py`): `issue_title`/`issue_body`
рендерятся из `finding_knowledge` (то же обогащение, что SARIF/CSV);
`GitHubIssueClient.create_issue` (POST `/repos/{owner}/{repo}/issues`, 2xx=успех);
`sync_findings(store, project, config, *, client)` гейтит по `min_severity` (дефолт
high), скипает уже-отслеженные (`untracked_for_issue` — episode-aware read), пишет
маппинг **только после** успешного создания (упавший API оставляет находку
неотслеженной → ретрай). `findings_store`: тип события `ISSUE_CREATED` +
`record_issue`/`untracked_for_issue`. CLI `monitor_cli issues <url> [--min-severity]`;
дефолт `settings.json "github": {enabled:False}` (токен вне project-metadata, как
`alerts`). Решения пользователя: create-only/идемпотентно, min_severity=high,
**только core+CLI** (GUI/web отложены — `feedback-internals-first-no-gui`).
Offline-first, opt-in, без новых зависимостей. Покрыто `test_github_issues`(11:
рендер/гейт/build_client/idempotent-sync/min-sev/error-leaves-untracked/non-2xx)
+ `test_findings_store`(+3: record+untracked/reopen-reset/empty) +
`test_monitor_cli`(+1: cmd_issues через инъектируемый client). Коммит a5a1cdf.

**EPIC 16 — wave 2: OWASP/CWE compliance report (A3) — `[ЗАКРЫТ]`.** Свёртка
активных находок по **OWASP Top 10 (2021) + CWE** в Markdown-deliverable. Чистый
offline-derive, без схемы/новых данных, зеркало каталога `finding_knowledge` (один
источник правды маппинга). `core/compliance.py`: `OWASP_TOP10` (A01…A10, порядок),
консервативный `_CATEGORY_MAP` (канон-категория → `{owasp, cwe}`: header→A05/CWE-693,
secret→A07/CWE-798, dependency→A06/CWE-1104, sourcemap→A05/CWE-540, cookie→A05/CWE-614,
graphql→A05/CWE-200, takeover→A05/CWE-284, transport→A02/CWE-319) + keyword-`_RULE_MAP`,
уточняющий generic `vuln` (sqli→A03/CWE-89, ssrf→A10/CWE-918, xss→A03/CWE-79, idor→A01,
path-traversal→A01, rce→A03…); `classify()` + `build_compliance()` (свёртка по всем 10
категориям, count 0 = clean; неузнанные vuln-подтипы → **unmapped**, а не
ложно-классифицированы); `load_compliance()` — тонкий ридер по active-находкам
(текущая поза, триаж исключён). `report_export.compliance_markdown(findings)` —
таблица Top 10 (статус ✅OK/⚠️findings · CWE · counts · severities) + посекционные
находки + Unmapped. CLI `monitor_cli compliance <url> [--out PATH]`. Решение:
**только core+Markdown+CLI** (report.html-карточка/web отложены —
`feedback-internals-first-no-gui`). Покрыто `test_compliance`(11:
classify-defaults/rule-override/unmapped/all-10/grouping/non-dict/load),
`test_report_export`(+3: таблица+секции/all-clean/unmapped), `test_monitor_cli`(+1:
cmd_compliance пишет отчёт). Коммит e76afd8. **Остаток wave 2 (отложен):** опц.
GitHub auto-close при FIXED; GUI/web/report-card-поверхности для issues+compliance.
Память `project-epic16-integrations-reporting`.

**EPIC NEXT — Attack Path & Business Risk Intelligence Platform — `[ЗАКРЫТ
2026-06-22]`.** Сдвиг приоритизации с severity-driven на business-risk-driven.
Полный план/детали — `ROADMAP_ASM_2.0.md` → **EPIC NEXT**. Все фичи: core→report→
web/CLI, offline/headless тесты, без второй модели данных, risk-вердикт НЕ
перестроен (business/threat/drift — display/derive слой поверх существующих
движков). По фичам:
- **F0 Platform Trust Hardening** — единый каркас миграций SQLite (`utils/
  sqlite_store`: декларативные `SCHEMA_VERSION`+`MIGRATIONS`, forward-only,
  `_add_column`; findings/asset/cve-сторы сведены к одному паттерну) + contract-
  тесты back-compat ключей (`tests/test_contracts.py`: report.json/metadata.json/
  findings/assets/timeline/exec-summary, subset-ассерты — страховка §4.7).
- **F1 Business Context Model** — `core/business_context.py` (вокаб criticality +
  data sensitivity, веса, resolve default+per-asset); хранение = ключ
  `business_context` в `metadata.json` (`Project.get/set_business_context`, паттерн
  Company-tier, без таблицы); `ProjectStore.resolve`; вплетено в
  `intelligence.asset_criticality` (augment type-веса); report/web/CLI
  (`business_cli.py`). GUI отложен.
- **F2 Business-Aware Prioritization** — business criticality/data sensitivity
  доходят до priority через (business-aware) criticality-band; новый статический
  **threat-tier** (`intelligence._threat_tier`: takeover/secret/инъекция=high,
  graphql/sourcemap/CVE=medium) как явный priority-фактор. Без двойного счёта.
  Live KEV/EPSS — отложен.
- **F3 Deterministic Attack Paths** — `build_attack_paths` углублён: явный `goal`
  (самый ценный достижимый актив, business-aware) + `hops` (entry→pivot→critical),
  CDN-edge кластеры пропускаются. Display.
- **F4 Remediation Tasks** — work-item на находке (status/owner/due), **event-
  sourced** поверх `finding_events` (`REMEDIATION`-event, latest wins, без таблицы);
  `core/remediation.py` + report-карточка + web `/remediation` + `remediation_cli.py`
  (list/auto/set). Скан НЕ авто-создаёт (user/CLI-owned). GUI отложен.
- **F5 Semantic Drift Monitoring** — `scan_diff` += `posture`-блок (из exec-summary
  метрик); `diff_events` эмитит `attack_surface_drift`/`exposure_drift`/
  `criticality_drift` (значимый рост, гейт a>0&b>0), alertable. Attack-path drift не
  дублируется (EPIC 13).
- **F6 Auditor-Friendly Compliance** — `compliance.classify` += `frameworks`
  (derive над OWASP-классом: PCI DSS/ISO 27001/NIST CSF/SOC2); crosswalk-таблица в
  `compliance_markdown` + framework-теги в SARIF. Один SSOT.
- **F7 Cloud/Container/IaC Ingestion (фаза 1, без cloud API)** — `core/iac_scanner.py`
  (Dockerfile/Terraform/CFN-JSON stdlib; compose/k8s/CFN-YAML опц. PyYAML;
  консервативные misconfig-правила + секреты через SSOT); канон-категория `'iac'`
  (fingerprint/knowledge/compliance A05); opt-in фаза `_phase_iac` (флаги `iac`/
  `iac_path`, локально → не scope-gated), образы → technology-активы; `iac_cli.py`.
  GUI ad-hoc scan surface добавлен 2026-06-23 (`gui/tab_iac.py`, read-only для
  lifecycle, JSON export); monitor + live cloud-API отложены.

**Per-asset business-context GUI (EPIC NEXT F1 GUI-хвост) — `[ЗАКРЫТ 2026-06-23]`.**
Снят последний отложенный GUI F1: project-default редактор уже был в Criticality-
вкладке (`0c25800`), теперь добавлен **per-asset override** для выбранного актива.
Решение: расширить существующую `gui/tab_criticality.py` (UI тонкий, без новой вкладки/
таблицы) — под detail-панелью факторов появилась группа «Бизнес-контекст актива
(override выбранного)»: два комбо (Критичность для бизнеса / Чувствительность данных,
словарь из `core/business_context.py` — `CRITICALITY_TIERS`/`DATA_SENSITIVITY`, owner/
tags/notes core НЕ поддерживает → не добавлены) + кнопки «Применить к активу» / «Сбросить
override». При выборе актива показывается резолв (project default + override) и текущий
override актива; запись off-thread через `_run_async` → `business_context.set_business_
context`/`clear_business_context` (asset_fp), затем reload таблицы критичности с
**сохранением выбранного актива** (`_crit_reselect_fp`). Ключ override — **bare
fingerprint**: `build_asset_criticality` теперь кладёт `item['fp']` =
`asset_adapter.asset_fingerprint(type, value)` (тот же join-key, что CLI/`resolve`) —
снимает прежнюю неоднозначность «key на display-label». Хранение прежнее
(`metadata.json` → `business_context` → `assets`), risk-вердикт не тронут, новой
таблицы нет. Покрыто `test_criticality_tab` (+5: fp на items, editor disabled до
выбора, populate override+resolved, apply пишет override+сохраняет выбор, clear
удаляет override) + регресс `test_intelligence`/`test_collection_runner`/`test_contracts`
зелёные.

**Осознанно отложено (не блокеры):** live threat-feed KEV/EPSS (F2); live cloud-API
(F7); прямой path→task маппинг (F4). Remediation GUI и IaC GUI добавлены 2026-06-23.

**Следующий шаг:** фаза backend-доводки (по запросу). Отфильтрованный бенчмарк-
бэклог закрыт (Company tier, Correlation, Finding Objects, Executive Headline,
IA-консолидация безопасный срез) + Risk Engine углублён (F-R4 infra + F-R5 SLA +
F-R6 cert-expiry + F-R7 regression) + Correlation углублён + Findings SLA углублён +
Asset coverage + Scanner robustness + Secret confidence (валидатор в risk/diff/alerts +
по-tier severity + секреты как первоклассные F1-находки). Отклонено (конфликт
инвариантов): ECharts/Cytoscape (QWebEngine), SQLAlchemy/Postgres,
APScheduler/Apprise/WeasyPrint. Детали — память `project-benchmark-direction`.
**Рекомендуется** живой запуск `.exe` для визуальной проверки сгруппированного nav.
