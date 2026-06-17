# CLAUDE.md — Advanced Site Analyzer

> Этот файл Claude Code читает автоматически в начале каждой сессии.
> Он задаёт контекст, архитектуру и **жёсткие правила**. Не нарушать.

---

## 1. Что это за проект

**Advanced Site Analyzer** — десктопный инструмент (Python 3.11+ / PyQt5) для
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
- PyQt5 (GUI), многопоточность через QThread/QObject Signals-Slots
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
  report_export.py      # CSV-экспорт findings/portfolio (PDF — печатью report.html)
  # — detection-движки (вливаются в risk/attack-surface/report) —
  infrastructure.py     # Domain→ASN→IP→Provider (offline, из recon-geo)
  asn_intel.py          # АКТИВНО (opt-in): RDAP CIDR + RIPEstat префиксы + reverse-IP (keyless)
  tech_fingerprint.py  dependency_audit.py  graphql_discovery.py # tech/JS-фреймворки + уязв. JS-либы (хардкод-fallback) + GraphQL
  osv_correlation.py    # АКТИВНО (opt-in): live CVE-корреляция JS-либ через OSV.dev (вытесняет хардкод)
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
tests/                  # pytest-набор (~916 тестов, offline/headless)
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
Тесты: 951 passed / 6 skipped (offline/headless).

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

**Следующий шаг:** фаза backend-доводки (по запросу). Отфильтрованный бенчмарк-
бэклог закрыт (Company tier, Correlation, Finding Objects, Executive Headline,
IA-консолидация безопасный срез) + Risk Engine углублён (F-R4 infra + F-R5 SLA +
F-R6 cert-expiry + F-R7 regression) + Correlation углублён + Findings SLA углублён +
Asset coverage + Scanner robustness. Отклонено (конфликт
инвариантов): ECharts/Cytoscape (QWebEngine), SQLAlchemy/Postgres,
APScheduler/Apprise/WeasyPrint. Детали — память `project-benchmark-direction`.
**Рекомендуется** живой запуск `.exe` для визуальной проверки сгруппированного nav.
