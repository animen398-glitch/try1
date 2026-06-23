# AGENTS.md — Advanced Site Analyzer

> Этот файл Codex читает автоматически в начале каждой сессии.
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

**Ключевые рабочие модули:**
- `core/project.py` — единственный источник правды по проектам/сканам/metadata.
- `core/findings_store.py`, `core/findings_adapter.py`, `core/finding_fingerprint.py` — lifecycle находок и dedup.
- `core/asset_store.py`, `core/asset_adapter.py`, `core/asset_graph.py`, `core/correlation.py` — asset inventory/correlation/exposure.
- `core/timeline.py`, `core/scan_diff.py`, `core/monitor.py`, `core/alerts.py` — история, drift/change events, monitoring/alerts.
- `core/intelligence.py`, `core/business_context.py`, `core/remediation.py`, `core/compliance.py`, `core/iac_scanner.py` — business/risk/paths/remediation/compliance/IaC слой.
- `gui/tab_*` — тонкие mixin-вкладки; любые фоновые операции идут через `_start_task()` / `_run_async()`.
- `remote/web_app.py` — LAN web-console, parity через тонкие helpers/JOBS.

**Последние важные изменения на 2026-06-23:**
- Demo/Release подготовка: добавлен `ASA_DATA_ROOT` env-override в `PathManager._detect_data_root` (единый seam — уводит ВСЕ data-БД/configs/settings/workspaces под один каталог, портится поверх source- и frozen-дефолтов; явный `data_root=` ctor-арг по-прежнему выше). Добавлен `demo_seed.py` (entry-скрипт корня): сеет self-contained demo workspace (1 company + 3 домена, 7 сканов, lifecycle-находки с drift, активы, business-контекст, remediation) в один каталог через явные PathManager-пути; запуск приложения — `ASA_DATA_ROOT=<dir> python main.py`. Проверено end-to-end (override → GUI читает портфель) + `tests/test_demo_seed.py`/`test_paths.py`.
- Подтверждён GUI smoke (живой `MainWindow`, 28 вкладок): Criticality/Remediation/IaC/Overview-Portfolio на едином богатом проекте.
- Почищен устаревший статус-баннер EPIC NEXT в `ROADMAP_ASM_2.0.md` (NOT STARTED → ЗАКРЫТ).
- Добавлен per-asset business context editor в Criticality GUI.
- Backend polish (F-SR1): SSOT для SQLite timestamp/severity/OSINT target parse, robustness-hardening malformed inputs. Коммит: `abca7ee`.

**Тестовый ориентир:**
- `PROJECT_REPORT.md` указывает актуальный масштаб набора около 1794 offline/headless тестов.
- Перед релизной пометкой обязательно прогонять `pytest` и, если менялся GUI/frozen-контур, self-check окна/PyInstaller smoke.
- На Windows при полном pytest возможны temp/cache teardown quirks; для чистой проверки удобно использовать уникальный `--basetemp` и `-p no:cacheprovider`.

**Что делать дальше в первую очередь:**
1. ✅ Подтверждён полный pytest после backend polish (1798 зелёных).
2. ✅ Почищен устаревший статус-баннер EPIC NEXT в `ROADMAP_ASM_2.0.md`.
3. ✅ Проведён живой GUI smoke (Criticality/Remediation/IaC/Overview-Portfolio).
4. ✅ Подготовлен demo workspace (`demo_seed.py` + `ASA_DATA_ROOT` override).
5. Релиз: version/changelog, PyInstaller build (проверить, что frozen чтит `ASA_DATA_ROOT`), first-run/system-health screen, import/export проекта. Demo workspace уже годится для показа платформы.

**Осознанно отложено и не является блокером:**
- live KEV/EPSS threat feed;
- live cloud API ingestion;
- прямой path→task mapping;
- расширенная коммерческая упаковка/лицензирование;
- новые внешние сканеры без ясной пользы для lifecycle/business layer.

**Главное правило следующей разработки:** не добавлять “ещё один сканер” ради количества. Приоритет — стабильность, управляемость находок, понятная ценность для пользователя, demo/release готовность и аккуратное развитие lifecycle/business intelligence слоя.
