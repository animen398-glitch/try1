# ROADMAP — ASM Platform 2.0

> Цель этапа: превратить Advanced Site Analyzer из «мощного Security Analyzer»
> в платформу **ASM + CSM**. Сдвиг с *поиска* данных на *управление* данными.
>
> Двигаемся строго: **Epic → Feature → Task → Implementation → Testing →
> Review → следующий Task**. Код пишем только после утверждения плана фичи.

---

## 0. Принцип очерёдности (важно)

В исходной заметке порядок был: Monitoring → Findings → Timeline → Alerts.
Рекомендую скорректировать: **Findings-фундамент должен идти первым**, потому
что Timeline («что нового»), Continuous Monitoring (ценность = «что изменилось
между сканами») и Alerts («новая находка») — все опираются на **стабильную
идентичность находки**. Без неё «новое» не определить, а повторные сканы будут
плодить дубли и ложные оповещения.

Поэтому порядок Epic'ов ниже — по зависимостям, а не по «вау-эффекту».

```
F1 Findings (идентичность + lifecycle)   ← фундамент, делаем первым
        │
        ├──► F2 Timeline / Change Events  (нужна стабильная identity)
        │
        ├──► F3 Continuous Monitoring     (генерит сканы → кормит Timeline)
        │
        └──► F4 Alert Center              (триггерится событиями F2/F3)
                    │
                    └──► F5 Executive Dashboard  (читает F1–F4)

F6 GUI Redesign (PySide6/qfluent)  ← отдельный, опциональный, рискованный трек
```

---

## EPIC: ASM Platform 2.0

### Критерии готовности эпика (Definition of Done)

- Находки персистентны, дедуплицируются между сканами, имеют жизненный цикл.
- Видна история изменений проекта по времени (что появилось/исчезло, дельта риска).
- Сканы можно запускать по расписанию (daily/weekly/monthly) headless.
- При значимых событиях уходят оповещения в выбранные каналы.
- Executive Dashboard показывает сводку и тренды.
- Backward-compat: старые проекты/`metadata.json`/`report.json` читаются без миграционных потерь.
- Покрытие тестами offline/headless; `.exe`-путь не сломан.

---

## F1 — Findings Management (фундамент)

**Зачем:** сейчас находки живут внутри одного скана. Нужна сущность с
идентичностью и состоянием, как в DefectDojo (OPEN / IN_PROGRESS / FIXED /
IGNORED / FALSE_POSITIVE).

### Ключевое проектное решение — fingerprint находки

Стабильный детерминированный отпечаток, одинаковый для «той же» проблемы между
сканами. Кандидат:

```
fingerprint = sha1( category | rule_id | normalized_location | discriminator )
```

- `normalized_location` — нормализованный эндпоинт/URL/путь файла (через уже
  существующий `endpoint_index`/`pattern_analyser`), без хоста-варьирования.
- `discriminator` — например, для секрета: vendor + маскированный префикс
  (НЕ само значение); для cookie: имя флага; для tech: имя+мажор-версия.
- Значения секретов нигде не хранятся в открытом виде (как и в Scan Diff).

> Это самое важное решение эпика. Сначала согласовать схему fingerprint,
> потом всё остальное.

### Модель данных (SQLite)

Новый стор `core/findings_store.py` (поверх `utils/sqlite_store.py`).

```sql
-- findings: одна запись на уникальную проблему в рамках проекта
CREATE TABLE findings (
  id              TEXT PRIMARY KEY,     -- = fingerprint
  project         TEXT NOT NULL,
  category        TEXT NOT NULL,        -- secret|sourcemap|cookie|graphql|header|tech|endpoint|...
  rule_id         TEXT,
  title           TEXT NOT NULL,
  severity        TEXT NOT NULL,        -- critical|high|medium|low|info
  status          TEXT NOT NULL,        -- OPEN|IN_PROGRESS|FIXED|IGNORED|FALSE_POSITIVE
  evidence        TEXT,                 -- JSON (маскированное), location, ссылка на скан
  first_seen_at   TEXT NOT NULL,
  last_seen_at    TEXT NOT NULL,
  updated_at      TEXT NOT NULL,
  status_source   TEXT                  -- 'auto' | 'user'
);

-- история состояний (audit trail)
CREATE TABLE finding_events (
  id          INTEGER PRIMARY KEY AUTOINCREMENT,
  finding_id  TEXT NOT NULL,
  scan_id     TEXT,
  type        TEXT NOT NULL,            -- CREATED|SEEN|STATUS_CHANGED|REOPENED|RESOLVED_AUTO
  from_status TEXT,
  to_status   TEXT,
  note        TEXT,
  at          TEXT NOT NULL
);
CREATE INDEX ix_findings_project ON findings(project);
CREATE INDEX ix_finding_events_fid ON finding_events(finding_id);
```

### Правила жизненного цикла (correctness)

- Новый отпечаток в скане → `CREATED`, статus `OPEN`.
- Существующий снова виден → `SEEN`, `last_seen_at` обновляется, статус НЕ трогаем.
- Был `OPEN`/`IN_PROGRESS`, в новом скане отсутствует → авто-перевод в `FIXED`
  (событие `RESOLVED_AUTO`), но только если фаза-источник успешно отработала
  (иначе «упавшая фаза» != «исправлено» — как уже сделано в Scan Diff).
- **`IGNORED` / `FALSE_POSITIVE` — липкие.** Если такая находка снова видна,
  она остаётся подавленной и **не реоупенится и не алертит**. Это ключ к
  снижению ложного шума (идея из TruffleHog/DefectDojo).
- Статусы, выставленные пользователем (`status_source='user'`), авто-логика не
  перетирает.

### Точки интеграции

- `core/collection_runner.py` / risk-движок: после прогона нормализует все
  находки → `FindingsStore.sync(project, scan_id, findings)` (upsert +
  возврат diff: новые/повторные/исчезнувшие).
- Risk score читает из findings (исключая IGNORED/FALSE_POSITIVE).
- `core/scan_diff.py` уже умеет сравнивать report.json — переиспользуем его
  логику нормализации, не дублируем.
- `remote/web_app.py`: `GET /findings`, `POST /findings/{id}/status` (паритет).

### Tasks

- T1.1 Спроектировать и согласовать fingerprint (документ + тесты на стабильность).
- T1.2 `findings_store.py` + миграция схемы (idempotent, не ломает старые БД).
- T1.3 Адаптеры: привести вывод каждого сканера к единому `Finding`-DTO.
- T1.4 `sync()` в CollectionRunner + правила lifecycle (включая липкость).
- T1.5 GUI-вкладка/панель Findings: таблица, фильтр по статусу/severity,
  смена статуса (через `_start_task` для записи в БД — но запись быстрая).
- T1.6 Web-консоль: findings endpoints.
- T1.7 Тесты: fingerprint-стабильность, lifecycle, липкость FP, авто-FIXED
  только при успешной фазе.

---

## F2 — Historical Timeline / Change Events

**Зачем:** показать историю проекта: `+3 endpoints`, `+1 secret`, `+GraphQL`,
`Risk +12` по датам сканов.

### Модель данных

```sql
CREATE TABLE timeline_events (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  project   TEXT NOT NULL,
  scan_id   TEXT NOT NULL,
  at        TEXT NOT NULL,
  type      TEXT NOT NULL,   -- NEW_ENDPOINT|NEW_SECRET|NEW_SUBDOMAIN|NEW_TECH|TECH_VERSION_CHANGE|GRAPHQL_FOUND|RISK_CHANGE|FINDING_RESOLVED
  summary   TEXT NOT NULL,
  delta     TEXT             -- JSON: {risk_from, risk_to} | {count} | ...
);
CREATE INDEX ix_timeline_project ON timeline_events(project, at);
```

### Реализация

- Источник событий = результат `FindingsStore.sync()` (новые/исчезнувшие) +
  существующий `scan_diff` (страницы/tech/версии/заголовки) + дельта риска из
  `metadata.json` (он уже хранит risk score на скан — **переиспользуем, не
  заводим вторую историю риска**).
- Risk/Findings/Secrets/Attack-Surface History — это просто временные ряды,
  собранные из `metadata.json` всех сканов проекта + агрегатов из findings.

### Tasks

- T2.1 `core/timeline.py`: построение событий из sync-diff + scan_diff + metadata.
- T2.2 Запись событий после каждого Full Collection.
- T2.3 GUI: timeline-лента на проект + ряды для графиков (data-провайдер).
- T2.4 Тесты на корректность дельт и отсутствие дублей.

---

## F3 — Continuous Monitoring (Scheduler)

**Зачем:** ASM без постоянного мониторинга почти бесполезен. Daily / Weekly /
Monthly сканы с сохранением истории.

### Проектное решение — где крутится планировщик

Десктоп-приложение не работает 24/7, поэтому:

- **Движок расписаний — в `core/`** (модель cadence, расчёт `next_run_at`,
  headless-триггер через существующий `CollectionRunner`). Один источник правды.
- **Два адаптера запуска** поверх одного движка:
  - *In-app* — пока приложение открыто (QTimer/легкий планировщик): удобно,
    но не «фоном».
  - *OS-level* — `main_orchestrator.py` получает подкоманду `schedule run`,
    которую вызывает Windows Task Scheduler / cron; приложение подхватывает
    новые сканы при следующем открытии. Это даёт настоящий фоновый мониторинг.
- Решение «какой адаптер по умолчанию» — согласовать перед T3.x. По умолчанию
  предлагаю in-app + опциональная генерация задания OS-планировщика.

### Модель данных

```sql
CREATE TABLE monitor_jobs (
  id           TEXT PRIMARY KEY,
  project      TEXT NOT NULL,
  cadence      TEXT NOT NULL,   -- daily|weekly|monthly|cron
  cron_expr    TEXT,
  options      TEXT,            -- JSON: профиль, --dynamic/--vulns и т.п.
  enabled      INTEGER NOT NULL DEFAULT 1,
  next_run_at  TEXT,
  last_run_at  TEXT,
  last_status  TEXT             -- ok|failed|running
);
```

### Tasks

- T3.1 `core/scheduler.py`: модель cadence + расчёт next_run + headless-раннер
  (вызывает CollectionRunner, пишет скан как обычный Full Collection).
- T3.2 In-app адаптер (поверх раннера задач, не блокирует UI).
- T3.3 CLI-подкоманда для OS-планировщика + (опц.) генератор задания.
- T3.4 GUI: список задач мониторинга, вкл/выкл, «запустить сейчас».
- T3.5 Тесты: расчёт next_run, idempotent-запуск, отметка last_status.

---

## F4 — Alert Center

**Зачем:** уведомлять о значимых событиях (новый секрет, рост риска, новый
такеовер-кандидат).

### Модель данных

```sql
CREATE TABLE alert_channels (
  id      TEXT PRIMARY KEY,
  type    TEXT NOT NULL,    -- telegram|discord|email|webhook
  config  TEXT NOT NULL,    -- JSON (токены/URL/SMTP) — НЕ коммитить, хранить в settings
  enabled INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE alert_rules (
  id        TEXT PRIMARY KEY,
  trigger   TEXT NOT NULL,  -- NEW_FINDING|SEVERITY_GTE|RISK_DELTA_GTE|NEW_TAKEOVER
  threshold TEXT,           -- JSON: {severity:'high'} | {delta:10}
  channels  TEXT NOT NULL,  -- JSON list channel_id
  enabled   INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE alert_log (
  id        INTEGER PRIMARY KEY AUTOINCREMENT,
  rule_id   TEXT, channel_id TEXT, event_ref TEXT,
  at        TEXT NOT NULL, status TEXT          -- sent|failed
);
```

### Реализация

- `core/alerts/` с диспетчером и сендерами `telegram.py`, `discord.py`,
  `email.py` (smtplib), `webhook.py`. Каждый — мягкая деградация при отсутствии
  конфига/сети; ничего не роняет.
- Триггерится **из событий F2** (а не из сырых сканов) → нет двойной логики
  «что считать новым».
- **Анти-шум:** не алертить по находкам со статусом IGNORED/FALSE_POSITIVE;
  дедуп по `(rule_id, finding_id)` за окно; resp/backoff на ошибках канала.

### Безопасность

- Токены/секреты каналов **не хранить в репозитории и не логировать**. Только
  в локальном `settings.json`/конфиге пользователя. В отчётах — маскировать.

### Tasks

- T4.1 Диспетчер + интерфейс Sender + Telegram (самый простой first).
- T4.2 Discord / Email / Webhook.
- T4.3 Правила + дедуп + липкость подавления.
- T4.4 GUI: каналы, правила, тест-отправка, журнал доставки.
- T4.5 Тесты: рендер сообщения, маршрутизация по правилам, сендеры застаблены.

---

## F5 — Executive Dashboard + Heatmaps

**Зачем:** профессиональная сводка для «руководящего» взгляда.

- **Карточки:** Risk Score, Attack Surface, Findings (по статусам), Secrets,
  Endpoints, Subdomains, Technologies.
- **Графики (тренды):** Risk / Findings / Secrets / Attack-Surface History
  (ряды из F2).
- **Heatmaps:** API / Secret / SourceMap / Cookie / GraphQL exposure.
- **Инфраструктурный граф:** Domain → Subdomains → IP → ASN → CDN → APIs
  (расширение существующего attack-surface графа).

### Реализация графики

- В PyQt5 удобнее всего рендерить через `QWebEngineView` + **ECharts**
  (тренды/heatmaps) и **Cytoscape.js** (инфраграф) — offline-бандлом ассетов,
  без внешних CDN (важно для `.exe`). Это переиспользует подход уже
  существующего offline-графа (CSS `:target`), но даёт интерактив.
- Данные дашборд берёт из готовых сторов (findings, timeline, metadata) —
  **никакой новой бизнес-логики в дашборде**, он только визуализирует.

### Tasks

- T5.1 Data-провайдеры (агрегаты из F1/F2/metadata).
- T5.2 Карточки + тренд-графики (ECharts, offline-ассеты).
- T5.3 Heatmaps.
- T5.4 Инфраструктурный граф (Cytoscape.js, offline).
- T5.5 Тесты на провайдеры данных (рендер не тестируем, данные — да).

---

## F6 — GUI Redesign (ОТДЕЛЬНЫЙ, опциональный трек)

**Внимание (приоритет №1 = стабильность):** миграция PyQt5 → PySide6 +
qfluentwidgets — реальная миграция (другой биндинг, scoped-enums в Qt6,
перемещение QAction, отличия API). Это **самый рискованный пункт**. Поэтому:

- **Вариант A (низкий риск, рекомендуется первым):** остаёмся на PyQt5, делаем
  **рестайл** — тёмная тема через QSS + карточные виджеты. Даёт ~80%
  «профессионального вида» без миграции.
- **Вариант B (высокий риск, позже):** миграция на PySide6 + qfluentwidgets
  (стиль Windows 11 / Defender). Делать **только после** того, как F1–F5
  стабильны, и **инкрементально**, опираясь на уже сделанную развязку
  Signals/Slots и mixin/plugin-архитектуру.

Решение A vs B — отдельно согласовать. Не начинать миграцию в одном Epic'е с
данными.

---

## Дальний горизонт (после 2.0, отдельными Epic'ами)

CVE Correlation (NVD) · Technology Risk Scoring · Dependency Risk · Compare
Projects · DNS/WHOIS Timeline · Advanced OSINT (GitHub/GitLab/PyPI/DockerHub/
Wayback/robots/sitemap/favicon-similarity). Каждый — отдельный план, по той же
цепочке Epic→Feature→Task.

---

## Сводка рисков

| Риск | Где | Митигация |
|---|---|---|
| Нестабильный fingerprint → дубли/ложные алерты | F1 | Согласовать схему первым шагом, тесты на стабильность |
| «Упавшая фаза» принята за «исправлено» | F1/F2 | Авто-FIXED только при успешной фазе (как в Scan Diff) |
| Алерт-шум | F4 | Липкость IGNORED/FP, дедуп, backoff |
| Утечка токенов каналов | F4 | Не коммитить/не логировать, маскировать |
| Планировщик не работает «фоном» | F3 | Движок в core + OS-адаптер (cron/Task Scheduler) |
| Поломка `.exe`-путей | все | Все пути через PathManager, проверять frozen-сборку |
| Регресс при миграции GUI | F6 | Сначала рестайл (A); миграция (B) — отдельно и инкрементально |
| Двойная история риска | F2 | Переиспользовать metadata.json, не заводить вторую |

---

## Идеи-доноры (что подсмотреть, не копировать)

- **DefectDojo** — модель статусов находок и lifecycle (F1).
- **TruffleHog** — снижение false-positive, липкость подавления (F1/F4).
- **OWASP Amass** — граф Domain→Subdomain→IP→ASN→Org, хранение истории (F5).
- **SpiderFoot** — модульность и шина событий (общая архитектура).
- **Uptime Kuma** — модель расписаний и уведомлений (F3/F4).
- **Prometheus** — идея временных рядов (F2/F5), не тащить целиком.
- **Cytoscape.js / ECharts** — визуализация графа и трендов offline (F5).
- **Nuclei / NVD** — структура findings и CVE-корреляция (дальний горизонт).
---

## EPIC 14 - Scope & Evidence Foundation

**Goal:** make active operations safer and make collected data auditable. Do not
add scanners and do not work on GUI/design in this epic. Focus on project scope,
evidence traceability, integrity checks, and backend/reporting surfaces.

**Status:** CLOSED on 2026-06-20. Final verification: full ruff clean and full
pytest green at 1460 passed, 1 existing Starlette/httpx warning.

### Completed Scope

- E14.1 Scope Guard v1 - project-level scope in `Projects/<slug>/metadata.json`,
  safe defaults for new projects, legacy-compatible missing scope, and active
  phase gating in `CollectionRunner`.
- E14.2 Evidence Manifest v1 - scan-local `evidence_manifest.json` with
  sha256/size/phase/path metadata and `report['evidence']`.
- E14.3 Evidence Integrity Hook - `core.evidence.audit_scan()` and
  `evidence_cli.py verify/json`.
- E14.4 Finding Evidence Persistence v1 - finding `evidence_refs` persist through
  `findings_adapter` into `FindingsStore.evidence` JSON.
- E14.5 Scope CLI / Project Scope Management - `scope_cli.py` plus
  `core.scope_management` for show/set/clear of allow/deny domains,
  `active_scan_enabled`, `passive_only`, and `rate_limit`.
- E14.6 Evidence Refs Coverage Expansion - category/title/source mappings cover
  native cookie/header/transport/tech/dependency/graphql/sourcemap findings when
  existing artifacts prove them.
- E14.7 Report / Export Traceability - finding evidence refs are visible in
  report.html and findings CSV as compact artifact path/hash pointers.
- E14.8 Scope Guard Coverage Audit - `ACTIVE_SCOPE_GUARDED_PHASES` and offline
  regression tests prove all active opt-in phase callables are skipped under
  `active_scan_enabled=False` and `passive_only=True`; nuclei is covered before
  invoking the external runner.
- E14.9 Evidence Integrity Integration With Monitor/Export - diff reports,
  monitor summaries/events, and export helpers can surface non-blocking evidence
  integrity warnings from `audit_scan()`.
- E14.10 Roadmap / Status Cleanup - roadmap/status/report/kickoff handoff docs
  aligned after closure.

### Compatibility Decisions Kept

- Scope remains project-level metadata in `Projects/<slug>/metadata.json`.
- New projects are safe by default; old projects with missing scope keep legacy
  active opt-in behavior until a scope is explicitly set.
- Evidence manifests are scan-local; evidence refs stay flat
  (`artifact_id`, `path`, `phase`) and never include raw secret values.
- Integrity failures warn by default and do not block scans, diff, monitor,
  alerts, or exports.
- Passive/base collection phases remain unblocked in Scope Guard v1.

### Next Work

Epic 14 is complete. Choose the next epic/task explicitly before coding; do not
continue adding scanners or GUI/design work under Epic 14.

---

## EPIC EXT-OSINT — External Recon & Document Intelligence Expansion

> **Статус: ПЛАНИРОВАНИЕ (код не писан).** Это стратегический план следующего
> горизонта, а НЕ реализованный эпик. Ничего из перечисленного ниже ещё не
> существует в коде. Реализация — строго по цепочке Epic → Feature → Task →
> Implementation → Testing → Review, по одной задаче, после утверждения плана
> конкретной фичи.

### Зачем (цель эпика)

Расширить Advanced Site Analyzer с **web-only ASM/CSM** до более широкой
**OSINT/ASM-платформы**, не меняя назначения (авторизованное тестирование,
исследования, обучение) и не нарушая инвариантов:

- внешнее recon-обогащение через **BBOT** (как опциональный внешний движок);
- **Document Intelligence** — извлечение структурированных данных из PDF /
  изображений / документов (опциональный адаптер, тяжёлые модели не бандлятся);
- **AI OSINT workflow-каталог** — нормализованный набор схем/воркфлоу-идей
  (источник: Awesome-AI-OSINT) поверх существующего data lifecycle;
- усиление продуктовых принципов **privacy-first / offline-first / no-signup**
  (идея-донор: fcksignups.com) как набор гарантий, а не зависимость.

### Принципы-доноры (что подсмотреть, НЕ копировать)

- **BBOT** (blacklanternsecurity, GitHub) — модель recon-модулей и событийная
  шина результатов. **Лицензия AGPL-3.0 → код НЕ копировать ни строки.**
  Использовать только как внешний инструмент через subprocess + его машинный
  (NDJSON/JSON) вывод. По документации, не по исходникам.
- **lift / datalab-to** (GitHub + HuggingFace `datalab-to/lift`) — document
  intelligence. Тяжёлые `torch`/`vLLM`/HF-модели **не бандлить в `.exe`**;
  только опциональная зависимость / внешний адаптер с мягкой деградацией.
- **Awesome-AI-OSINT** (ubikron, GitHub) — НЕ библиотека, а каталог идей.
  Источник бэклога воркфлоу, не зависимость.
- **fcksignups.com** — продуктовая идея privacy-first/no-signup/offline-first.
  НЕ кодовая зависимость без отдельного анализа.

### Жёсткие границы эпика (НЕ нарушать)

- **AGPL-чистота:** ни строки кода BBOT (или иного AGPL/GPL источника) в репозиторий.
  Только запуск внешнего бинаря и парсинг его вывода в наши модели.
- **Опциональность:** ни один новый инструмент/модель не становится обязательной
  зависимостью; `requirements.txt` для базового запуска не растёт; в `.exe`
  тяжёлые деп не попадают (правило сохраняем).
- **Никакой обязательной сети.** Все новые сетевые/активные действия — **opt-in**
  и проходят через **Scope Guard** (EPIC 14): вне разрешённого scope — пропуск.
- **Не сканеры ради сканеров.** Любой новый ввод обязан питать **существующий
  data lifecycle**, без второй модели данных:
  `Project metadata` · `AssetStore` · `FindingsStore` · `Timeline` ·
  `Overview/Portfolio` · `report.html/json/md` · `operations.db` ·
  warnings lifecycle.
- **UI тонкий**, бизнес-логика только в `core/`; адаптеры — мягкая деградация при
  отсутствии инструмента (паттерн `core/external_tools.py` + `core/features.py`).
- **Все тесты offline/headless**; внешние бинари и сеть в тестах застаблены
  (инъекция `run_command`/транспорта, фикстуры с сохранённым выводом).

### Критерии готовности эпика (Definition of Done)

- BBOT/Document/AI-OSINT входы при отсутствии инструмента **молча деградируют**
  (фича выключена с подсказкой, приложение не падает, тесты зелёные).
- Каждый новый ввод нормализуется в существующие сущности (assets/findings) и
  виден в Timeline / Overview / report без отдельной БД-таблицы там, где можно
  derive-on-read.
- `.exe`-сборка не раздувается тяжёлыми деп; `--self-check` зелёный.
- Backward-compat: старые проекты/`metadata.json`/`report.json` читаются без потерь.

---

### F1 — BBOT External Adapter

**Цель:** подключить BBOT как внешний опциональный recon/ASM enrichment-движок;
его находки/активы вливаются в `AssetStore`/`FindingsStore` через существующие
адаптеры.

**Запрещено:** копировать код BBOT; делать его обязательной зависимостью;
бандлить в `.exe`; запускать агрессивные presets по умолчанию.

**Где живёт (планируемые модули — НЕ существуют):**
- `core/features.py` += `has_bbot()` (детект бинаря на PATH, паттерн `has_nuclei`).
- `core/bbot_adapter.py` (planned) — тонкий subprocess-обёртка поверх
  `external_tools.run_command`: запускает выбранный безопасный preset, читает
  NDJSON-вывод, нормализует события BBOT → наши `Asset`/`Finding`-DTO. Никогда
  не падает (мягкая деградация), инъектируемый runner для тестов.
- Проводка: opt-in фаза `bbot` в `core/collection_runner.py` (паттерн `_phase_osv`/
  `_phase_asn`), monitor-паритет (`monitor._build_run_fn`), карточка отчёта,
  чекбокс в Collection. Scope Guard гейтит активный запуск.

**Tasks:**
- T1.1 Research & Contract — изучить BBOT CLI/JSON-вывод **только по документации**;
  зафиксировать контракт «событие BBOT → наш Asset/Finding»; выбрать безопасные
  пассивные presets; согласовать scope-маппинг. Документ, без кода.
- T1.2 `features.has_bbot()` + детект версии/доступности (мягко).
- T1.3 `core/bbot_adapter.py` — запуск + парсинг NDJSON → нормализованные DTO
  (дедуп через существующие fingerprint/identity, без новой identity-схемы).
- T1.4 Проводка opt-in фазы в CollectionRunner + Scope Guard + карточка отчёта.
- T1.5 Monitor/web-паритет (read-поверхности уже общие через assets/findings).
- T1.6 Тесты offline — фикстуры с сохранённым NDJSON, инъекция runner; проверка
  мягкой деградации при отсутствии бинаря и при выходе вне scope.

---

### F2 — Document Intelligence (PDF / images / docs)

**Цель:** извлекать структурированные данные из документов, найденных в ходе
анализа (PDF/изображения/офисные файлы), и вливать находки/активы (контакты,
утечки, метаданные, ключи) в существующий lifecycle.

**Запрещено:** бандлить `torch`/`vLLM`/HF-модели в `.exe`; делать lift
обязательной зависимостью; обещать, что lift/Gemini уже интегрированы.

**Где живёт (планируемые модули — НЕ существуют):**
- `core/document_intelligence.py` (planned) — **ядро**: offline-first контракт
  «документ → структурированные поля → наши DTO»; провайдер выбирается на чтении,
  при отсутствии — мягкая деградация (stdlib-минимум: метаданные/текст без AI).
- `core/document_providers/` (planned) — опциональные провайдеры за единым
  интерфейсом: `lift_adapter` (datalab-to/lift, опц. зависимость/внешний адаптер),
  возможные локальные OCR. Тяжёлый провайдер активен только если установлен.
- `core/features.py` += детект провайдеров (по модулю/бинарю), summary().
- Проводка: opt-in фаза `documents`, нормализация в `FindingsStore`/`AssetStore`,
  карточка отчёта, чекбокс Collection, monitor-паритет.

**Tasks:**
- T2.1 Research & Contract — изучить lift по документации/HF-карточке; определить
  минимальный offline-fallback (без AI) и расширенный провайдер (с моделью);
  контракт «извлечённое поле → Finding/Asset». Документ, без кода.
- T2.2 `features` детект провайдеров + summary в health.
- T2.3 `core/document_intelligence.py` — ядро + провайдер-интерфейс + offline-fallback.
- T2.4 `document_providers/lift_adapter` (planned, опц.) — изоляция тяжёлых импортов.
- T2.5 Проводка opt-in фазы + нормализация в lifecycle + карточка отчёта.
- T2.6 Тесты offline — провайдер застаблен; проверка деградации без модели/деп.

---

### F3 — AI OSINT Workflow Catalog

**Цель:** нормализованный, offline-каталог OSINT-воркфлоу/схем (источник идей —
Awesome-AI-OSINT) поверх существующих сущностей — «какие связки разведки имеет
смысл прогонять», без новых сканеров и без обязательной сети.

**Где живёт (планируемые модули — НЕ существуют):**
- `core/osint_catalog.py` (planned) — чистый derive-on-read каталог
  воркфлоу/схем (как `finding_knowledge`/`compliance`): декларативное описание
  шагов поверх уже существующих движков (recon/dns/email/employee/ct/asn),
  без копирования внешнего кода. Никаких новых сетевых вызовов сам по себе.

**Tasks:**
- T3.1 Research & Curation — отобрать из Awesome-AI-OSINT воркфлоу, ложащиеся на
  существующие движки; зафиксировать схему каталога. Документ, без кода.
- T3.2 `core/osint_catalog.py` — декларативный каталог + резолв в существующие фазы.
- T3.3 Поверхности (report-карточка / web read-эндпоинт) — паритет с прочими
  derive-вью; GUI опционально (память `feedback-internals-first-no-gui`).
- T3.4 Тесты offline на каталог/резолв.

---

### F4 — Privacy-first / Offline-first Hardening

**Цель:** превратить продуктовый принцип (идея-донор fcksignups.com) в проверяемые
гарантии: no-signup, offline-first, прозрачность сетевых/активных действий.

**Где живёт (расширение существующего, НЕ новые тяжёлые модули):**
- Опора на **Scope Guard** (EPIC 14): любой новый внешний ввод (F1/F2) уважает
  allow/deny, `active_scan_enabled`, `passive_only`, `rate_limit`.
- Опора на **features.summary()** / health — явно показывать, что выключено и
  почему; ничего не включать молча.

**Tasks:**
- T4.1 Аудит-контракт «что приложение делает по сети и когда» (документ): все
  новые действия opt-in, ни одного скрытого вызова; сверка с инвариантами.
- T4.2 Проверочные тесты-инварианты (offline): новые фазы выключены при
  `active_scan_enabled=False`/`passive_only=True` (расширение
  `ACTIVE_SCOPE_GUARDED_PHASES`).
- T4.3 Документирование гарантий в README **только после** реальной реализации
  (не описывать как сделанное заранее).

---

### Сводка рисков (EXT-OSINT)

| Риск | Где | Митигация |
|---|---|---|
| Заражение AGPL-кодом | F1 | Только subprocess + парсинг вывода; ни строки чужого кода; ревью на отсутствие копипаста |
| Раздувание `.exe` тяжёлыми деп | F2 | Провайдеры опциональны, импорт изолирован, в `.exe` не входят; замер размера до/после |
| Скрытые сетевые/активные действия | F1/F2 | Всё opt-in + Scope Guard; тесты-инварианты на пропуск вне scope |
| «Сканер ради сканера», вторая модель данных | все | Любой ввод нормализуется в AssetStore/FindingsStore; derive-on-read где можно |
| Тесты требуют сети/бинарей/моделей | все | Инъекция runner/транспорта, фикстуры с сохранённым выводом, мягкая деградация |
| Завышенные обещания (lift/Gemini «готовы») | F2 | README/доки правим только по факту реализации |

### Точки интеграции (существующие, переиспользовать)

- `core/features.py` — детект опциональных инструментов (`has_bbot` и провайдеры).
- `core/external_tools.py` — `run_command` (never-raise subprocess) для BBOT.
- `core/findings_adapter.py` + `findings_store.py` — нормализация/lifecycle находок.
- `core/asset_adapter.py` + `asset_store.py` — нормализация/lifecycle активов.
- `core/collection_runner.py` — проводка opt-in фаз (паттерн `_phase_osv/_phase_asn`).
- `core/monitor.py` (`_build_run_fn`) — monitor-паритет.
- `core/scope_management` / Scope Guard (EPIC 14) — гейт активных действий.
- `remote/web_app.py` — read-поверхности (паритет с GUI).

---
