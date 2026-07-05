# Changelog

All notable changes to **Advanced Site Analyzer** are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
the project uses [Semantic Versioning](https://semver.org/).

Назначение продукта неизменно: **только авторизованное тестирование
безопасности, исследования и обучение.**

## [Unreleased]

### Changed
- **qfluentwidgets is now optional (GPL-free default build).** PySide6-Fluent-
  Widgets is GPL-3.0, so the public build no longer bundles it: `build.spec`
  excludes it by default (`ASA_BUNDLE_FLUENT=1` re-enables bundling for internal
  builds holding a commercial license), and `gui/_fluent.py` soft-degrades to a
  text-only side-navigation when it is absent. The native `QMainWindow` shell is
  unaffected — the full GUI (all tabs) stays usable. See `THIRD_PARTY_NOTICES.md`
  and `RELEASE_CHECKLIST.md`.

### Added
- **Release artifacts.** `RELEASE_CHECKLIST.md` (verification / licensing /
  packaging / pilot) and `THIRD_PARTY_NOTICES.md` (dependency + license inventory
  from installed metadata).
- **Risk-acceptance review.** Consolidated *Risk Acceptances* tab (accepted
  findings with reason/approver/until + an expired flag; revoke / CSV export) and
  an "expired-only" review filter across core, web, and GUI.
- **Portable / demo workspace.** `ASA_DATA_ROOT` env-override в `PathManager`
  уводит все БД, configs, settings и workspaces под один каталог (поверх
  source- и frozen-дефолтов; явный `data_root=` всё ещё выше). `demo_seed.py`
  сеет self-contained ASM/CSM-портфель (company + 3 домена, сканы, lifecycle
  находок с drift, активы, business-контекст, remediation) для демонстрации
  платформы: `ASA_DATA_ROOT=<dir> python main.py`.
- **Project export / import.** `core/project_io.py` — перенос проекта между
  машинами (или шаринг демо) одним `.zip`: дерево `Projects/<slug>/` + faithful
  срез findings/assets (строки и события lifecycle, id/статусы/таймстемпы
  сохраняются). Импорт защищён от zip-slip и SQL-инъекции из бандла. Доступно из
  вкладки Overview (Export/Import project…). Generic срез реализован в
  `SQLiteStore.export_project`/`import_project` (декларация `PROJECT_EXPORT`).

## [1.0.0]

Первый стабильный рубеж: из «мощного анализатора» продукт стал локальной
**ASM (Attack Surface Management) + CSM (Continuous Security Monitoring)**
платформой для авторизованного анализа.

### Платформа (ASM 2.0 F1–F6)
- Findings Management: persistent lifecycle находок (SQLite-стор + события
  CREATED/SEEN/STATUS_CHANGED/REOPENED/RESOLVED), кросс-сканерный dedup по CVE.
- Timeline / change events: derive-on-read серии и drift-события поверх сканов.
- Continuous Monitoring + Alert Center: фоновый watcher, оповещения по каналам.
- Executive Dashboard, Overview/Portfolio, company roll-up.
- Asset Inventory: lifecycle активов (ACTIVE/GONE), criticality, correlation,
  exposure, attack-surface граф.
- SLA по severity, offline-SVG charts (bars/sparkline/heatmap), risk/executive
  summary, report/web/CSV-проводки — без лишних таблиц.

### Intelligence & бизнес-слой (EPIC NEXT)
- Confidence / priority / explanation на находку; asset criticality.
- Business Context Model (criticality + data sensitivity), business-aware
  prioritization.
- Deterministic attack paths (внешняя точка → критичный актив).
- Remediation tasks; semantic drift monitoring; auditor-friendly compliance
  (поверх OWASP/CWE); Cloud/Container/IaC ingestion (фаза 1, без cloud API).

### Интеграции и отчётность
- SARIF, Markdown, generic webhook, CI gate, GitHub Issues push.
- Infrastructure/Technology waves: cloud/region classification, tech risk,
  CVE Intelligence (OSV + NVD, персист-кеш, offline).

### GUI / упаковка
- PySide6 + Fluent Widgets, тонкий mixin-слой вкладок, единый раннер задач.
- Launcher (EPIC 6): health check, install/repair/update, offline-first.
- LAN web-консоль (FastAPI) с паритетом по read-поверхностям.
- PyInstaller-поставка `.exe` (тяжёлые зависимости опциональны, не бандлятся).

### Качество
- ~1800 offline/headless тестов (Qt `offscreen`, сетевые вызовы стабятся).
- Backend polish: SSOT для SQLite timestamp/severity/OSINT parse;
  robustness-hardening malformed inputs (OpenAPI/source map/secret/history).
