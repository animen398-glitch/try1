# Changelog

All notable changes to **Advanced Site Analyzer** are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
the project uses [Semantic Versioning](https://semver.org/).

Назначение продукта неизменно: **только авторизованное тестирование
безопасности, исследования и обучение.**

## [Unreleased]

## [2.0.0] — 2026-07-05

Major release. The product became a local ASM / CSM + client-safe pentest
workbench (managed findings, assets, business risk, attack paths, remediation,
monitoring, missions, engagements, evidence, reporting) and dropped media
downloading — a removed feature, hence the major version bump. Grouped by theme;
authorized/client-safe, evidence-first, offline-by-default throughout.

### Added
- **Client-Safe Pentest Workbench (v1 + v2).** First-class audit runs with
  ROE / scope / action policy, finding validation + quality gate, scenario and
  ROE templates, re-validation of unresolved findings, and A/B run comparison
  with a gate — plus JSON/Markdown/HTML reports and an *Audit Runs* tab.
- **Mission Center.** Authorized "missions" over audit runs / findings: pure
  contract, persistent store, execution (run a mission as an audit run),
  evidence-first report, recurring scheduling, portfolio overview, run history,
  link-integrity + stale-link cleanup, CSV export, and a *Missions* tab + web /
  timeline surfaces.
- **Pentest Engagements.** Top-level client/engagement entity (scope /
  ROE / authorization) linking missions → audit runs → findings, with retest,
  overview, CSV, engagement-scoped mission creation, and an *Engagements* tab.
- **Retest runs.** Persisted point-in-time snapshots of an engagement's
  finding outcomes (fixed / open / accepted / missing), with report, CSV,
  timeline events, and history in the GUI.
- **External tool integration layer (offline, evidence-driven).** A contract +
  per-tool parsers + pipeline that turn already-captured scan evidence into
  normalized findings/assets for a mission — gated by ROE, no tool is executed
  and nothing is fetched. Includes a captured-scan → tool-evidence bridge.
- **Threat intelligence — KEV / EPSS.** CISA KEV + FIRST EPSS enrichment raises
  finding priority, tightens the SLA window (floor-only), adds a `new_kev`
  timeline event + alert rule and an exploitability badge in the findings detail.
- **Risk acceptance.** Time-boxed risk acceptance (reason / approver / until)
  with auto-expiry, timeline + Alert Center surfacing, exclusion from the
  active-risk view, bulk accept/revoke, CSV export, a consolidated
  *Risk Acceptances* review tab, and an "expired-only" review filter.
- **Findings workflow.** Keyword search over findings and assets; bulk triage
  (status / assignment); finding assignment + comments.
- **Compare projects (A-vs-B).** Side-by-side project comparison on the Overview
  tab with per-metric deltas and CSV / Markdown export.
- **Authorized enterprise recon (E1–E10).** Passive OSINT (Shodan / Censys /
  InternetDB, zero target traffic), coverage gate, execution profiles,
  browser-backed accuracy, context-aware wordlist planner, origin-exposure
  intel, a storage-backend seam (incl. Postgres), worker orchestration, and
  sensitive-data governance — all authorized-only, opt-in where they add traffic.
- **Reliability & operability.** Local-first crash reporter (redacted reports +
  breadcrumbs, opt-in send), web-console authentication + safe bind (loopback
  default, LAN opt-in) + request rate-limiting, scan retention + full
  backup/restore, an opt-in update check, and friendlier GUI error messages.
- **GUI.** Interactive attack-path graph, table pagination for heavy tables, a
  first-run / system-health screen, a crash dialog, and a headless end-to-end
  test layer.
- **Release artifacts.** `RELEASE_CHECKLIST.md` and `THIRD_PARTY_NOTICES.md`.
- **Portable / demo workspace.** `ASA_DATA_ROOT` env-override points all DBs,
  configs, settings and workspaces at one directory; `demo_seed.py` seeds a
  self-contained ASM/CSM portfolio for demos (`ASA_DATA_ROOT=<dir> python main.py`).
- **Project export / import.** `core/project_io.py` moves a project between
  machines as one `.zip` (tree + faithful findings/assets slice), zip-slip / SQL-
  safe, from the Overview tab.

### Changed
- **qfluentwidgets is now optional (GPL-free default build).** PySide6-Fluent-
  Widgets is GPL-3.0, so the public build no longer bundles it: `build.spec`
  excludes it by default (`ASA_BUNDLE_FLUENT=1` re-enables bundling for internal
  builds holding a commercial license), and `gui/_fluent.py` soft-degrades to a
  text-only side-navigation when it is absent. The native `QMainWindow` shell is
  unaffected — the full GUI stays usable. See `THIRD_PARTY_NOTICES.md`.
- **Concurrent scan engine.** Independent Full-Collection phases run concurrently
  (DAG scheduler) with byte-identical results to the old sequential order.
- **Windows CLI hardening.** External CLIs never flash a console window; a single
  cancellable process contract with process-tree kill, an AST guard enforcing the
  one subprocess seam, and a redacted run journal.

### Removed
- **Media downloading.** Video/image download features and their heavy optional
  dependencies (yt-dlp / ffmpeg) were dropped to narrow the product to security /
  recon + offline site cloning (2 tabs removed). Offline site cloning is retained.

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
