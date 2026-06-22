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

> **Статус: BASELINE РЕАЛИЗОВАН (F1–F4, 2026-06-21).** Эпик был спланирован здесь,
> а затем доведён до рабочего baseline. Модули **существуют** и проведены через
> общий lifecycle: `core/bbot_adapter.py`, `core/document_intelligence.py`,
> `core/document_providers/lift_adapter.py`, `core/osint_catalog.py` (см. отметки
> `[ВЫПОЛНЕНО 2026-06-21]` в задачах ниже). Историю задач НЕ переписываем — она
> остаётся как лог реализации. **Остаток — точечные расширения baseline, НЕ
> новый слой и НЕ переписывание.** Следующий горизонт (business-risk слой поверх
> уже готовых attack-paths/exposure/criticality/OSINT) вынесен в отдельный
> **EPIC NEXT** (в конце файла, статус ПЛАНИРОВАНИЕ — код не писан). Любое
> расширение — строго по цепочке Epic → Feature → Task → Implementation →
> Testing → Review, по одной задаче, после утверждения.

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

**Где живёт (baseline РЕАЛИЗОВАН — см. задачи ниже):**
- `core/features.py` += `has_bbot()` (детект бинаря на PATH, паттерн `has_nuclei`).
- `core/bbot_adapter.py` **[BASELINE РЕАЛИЗОВАН]** — тонкий subprocess-обёртка поверх
  `external_tools.run_command`: запускает выбранный безопасный preset, читает
  NDJSON-вывод, нормализует события BBOT → наши `Asset`/`Finding`-DTO. Никогда
  не падает (мягкая деградация), инъектируемый runner для тестов.
- Проводка: opt-in фаза `bbot` в `core/collection_runner.py` (паттерн `_phase_osv`/
  `_phase_asn`), monitor-паритет (`monitor._build_run_fn`), карточка отчёта,
  чекбокс в Collection. Scope Guard гейтит активный запуск.

**Tasks:**
- T1.1 Research & Contract — **[ВЫПОЛНЕНО 2026-06-21]** изучить BBOT CLI/JSON-вывод
  **только по документации**; зафиксировать контракт «событие BBOT → наш
  Asset/Finding»; выбрать безопасные пассивные presets; согласовать scope-маппинг.
  Документ, без кода. → результат ниже («T1.1 — Research & Contract (результат)»).
- T1.2 `features.has_bbot()` + детект версии/доступности (мягко). **[ВЫПОЛНЕНО
  2026-06-21]** — `core/features.py` += `has_bbot()` (PATH-детект бинаря, паттерн
  `has_nuclei`; никогда не импортируем — AGPL) + регистрация в `OPTIONAL_FEATURES`
  (виден в health/`features.summary()`); `core/launcher.py` += `bbot` в
  `_BINARY_HELP` → классифицируется как `manual` (внешний инструмент, не
  pip-зависимость). Покрыто `tests/test_features.py`.
- T1.3 `core/bbot_adapter.py` — запуск + парсинг NDJSON → нормализованные DTO
  (дедуп через существующие fingerprint/identity, без новой identity-схемы).
  **[ВЫПОЛНЕНО 2026-06-21]** — pure `parse_bbot_jsonl` (бакетит in-scope события в
  hosts/ips/asns/netblocks/endpoints/technologies/findings; защитное чтение `data`,
  scope-фильтр, severity-тиры VULNERABILITY/FINDING) + `build_command` (безопасный
  пассив: `-rf passive --strict-scope -om json --silent`, без guessed-флагов) +
  `BBOTRunner` (never-raise, инъектируемые `runner`/`detector` → оффлайн-тесты).
  Findings эмитятся «сырыми» dict'ами `source='bbot'` → проходят
  `findings_adapter.from_raw` без правок (CVE авто-мёрджится). Покрыто
  `tests/test_bbot_adapter.py` (11). Фолд в lifecycle/derive_assets — T1.4.
- T1.4 Проводка opt-in фазы в CollectionRunner + Scope Guard + карточка отчёта.
  **[ВЫПОЛНЕНО 2026-06-21]** — флаг `bbot` в `CollectionRunner.__init__`/`configure`,
  фаза 7l `_phase_bbot` (запуск `BBOTRunner`, артефакт `bbot/bbot.json`, фолд
  findings в vulns как `_phase_security`; severity → 3-бакетная шкала VulnScanner,
  как nuclei/OSV), `bbot` в `ACTIVE_SCOPE_GUARDED_PHASES` (гейт Scope Guard) и в
  auto-FIX scope-guard `_sync_findings` (`source='bbot'→phase_ok('bbot')`); BBOT-
  экстрактор в `asset_adapter.derive_assets` (типизирует hosts/ips/asns/netblocks/
  endpoints/technologies с `source='bbot'`, апекс-фильтр как cert/CT, last → native
  wins on overlap; per-source GONE-гейтинг через существующий `source_in_scope`,
  правок `asset_store` не потребовалось); карточка «External Recon (BBOT)» в
  report.html. Покрыто `test_collection_runner`(+4)/`test_asset_adapter`(+3).
  Monitor/web/GUI-паритет — T1.5.
- T1.5 Monitor/web-паритет (read-поверхности уже общие через assets/findings).
  **[ВЫПОЛНЕНО 2026-06-21]** — monitor-паритет: `monitor._build_run_fn` += `bbot=
  opts.get('bbot', False)` (как osv/asn/security — в `default_monitor_options` не
  добавляем, дефолт off); GUI-чекбокс «BBOT (внешний recon)» в Collection (FlowLayout
  opt-row, тултип про AGPL/внешний процесс/пассив/мягкую деградацию) + `'bbot'` в
  `_collection_options` (тот же словарь питает Full Collection и monitor-enable).
  Web-консоль намеренно гоняет базовый пайплайн (opt-in off), как osv/asn → web-
  правок нет. Read-поверхности (Findings/Assets/Timeline/Overview/web) получают
  BBOT-данные автоматом через общий lifecycle. Покрыто `test_monitor`(+2)/
  `test_monitor_gui`(+1); self-check 25 вкладок зелёный.
- T1.6 Тесты offline — фикстуры с сохранённым NDJSON, инъекция runner; проверка
  мягкой деградации при отсутствии бинаря и при выходе вне scope.

---

#### T1.1 — Research & Contract (результат)

> Источник фактов — **только официальная документация BBOT** (не исходники):
> [Output](https://www.blacklanternsecurity.com/bbot/Stable/scanning/output/),
> [Events](https://www.blacklanternsecurity.com/bbot/Stable/scanning/events/),
> [Presets](https://www.blacklanternsecurity.com/bbot/Stable/scanning/presets/).
> Контракт сверен с реальными DTO нашего кода (`core/findings_adapter.py`,
> `core/asset_adapter.py`, `core/finding_fingerprint.py`) и с паттерном
> нормализации внешнего инструмента (`core/external_tools.py` — nuclei/katana).
> **AGPL-чистота:** ни строки кода BBOT не копируется; интеграция = запуск бинаря
> + парсинг машинного вывода в наши модели.

**A. Как запускаем (invocation contract).**
- BBOT выдаёт **NDJSON** (один JSON-объект на строку) в stdout через `-om json` —
  парсится построчно ровно как `parse_nuclei_jsonl`/`parse_katana_lines`
  (никаких temp-файлов; читаем stdout через `external_tools.run_command`).
- **Дефолт — безопасный пассив:** пресет + рестрикт по флагу `passive`
  (`-rf passive`) + строгий scope (`--strict-scope`), `--silent`. Иллюстративно:
  `bbot -t <target> -p subdomain-enum -rf passive --strict-scope -om json --silent`.
  Никаких агрессивных пресетов/брутфорса по умолчанию. Расширенные пресеты — только
  явный opt-in пользователя.
- Точные флаги (подавление интерактивного dep-промпта на первом запуске, имя
  пресета) **подтвердить в T1.3** прогоном реального бинаря; адаптер не должен
  зависеть от конкретного пресета (пресет — конфиг, не контракт).
- Даже пассивный BBOT делает DNS/API-запросы (сеть) → фаза **opt-in** и гейтится
  Scope Guard (EPIC 14): вне `active_scan_enabled`/scope — фаза пропускается.

**B. Структура события (по докам).** Поля верхнего уровня:
`type`, `id` (= тип + SHA1 от data), `data` (строка для простых типов вроде
`DNS_NAME`/`IP_ADDRESS`; dict для сложных), `host`, `scope_distance`
(0 = in-scope), `scope_description` (in-scope/affiliate/distance-N), `tags`,
`module`, `resolved_hosts`, `parent`, `scan`, `timestamp`.

**C. Маппинг тип события → наша сущность** (ингестим только то, что питает
существующий lifecycle; никаких новых типов активов/моделей в фазе 1):

| BBOT event | Наша сущность | Тип/категория | Примечание |
|---|---|---|---|
| `DNS_NAME` (== apex цели) | Asset | `domain` | сам таргет |
| `DNS_NAME` (`*.apex`, in-scope) | Asset | `subdomain` | как cert/CT-имена (F-A1) |
| `IP_ADDRESS` | Asset | `ip` | `host`/`data` |
| `IP_RANGE` | Asset | `netblock` | `kind='range'` |
| `ASN` | Asset | `asn` | |
| `URL` | Asset | `endpoint` | `normalize_location` |
| `URL_UNVERIFIED` | Asset | `endpoint` | пометить attr `unverified` (ниже доверие) |
| `TECHNOLOGY` | Asset | `technology` | имя=identity, версия=attr |
| `VULNERABILITY` | Finding | `vuln` | severity из data (см. D) |
| `FINDING` | Finding | `vuln` | менее подтверждено → severity `info` |
| `OPEN_TCP_PORT`/`OPEN_UDP_PORT`/`PROTOCOL`/`WAF` | (attr) | — | обогащают attrs IP/endpoint, **не** новый тип |
| `EMAIL_ADDRESS`/`SOCIAL`/`USERNAME`/`ORG_STUB`/`CODE_REPOSITORY`/`AZURE_TENANT`/`MOBILE_APP`/`STORAGE_BUCKET`/`HASHED_PASSWORD`/`GEOLOCATION` | — | — | **НЕ ингестим в фазе 1** (нет соответствующего типа актива/находки; кандидаты в F3 AI-OSINT каталог / будущие типы) |

**D. Severity.** BBOT `VULNERABILITY` несёт `CRITICAL/HIGH/MEDIUM/LOW`; `FINDING`
severity не несёт. Наш `findings_adapter.normalize_severity` уже знает эти слова
→ `critical/high/medium/low`; `FINDING` → `info`. Отдельная таблица не нужна.

**E. Идентичность и дедуп (переиспользуем, без новой схемы).** BBOT-находки
эмитятся как «сырые» dict'ы `{severity, title, detail, source:'bbot', location?}` →
проходят `findings_adapter.from_raw` **без изменений**:
- если в тексте есть `CVE-####-…` → `extract_cve` канонизирует identity
  (`category='vuln'`, `rule_id=cve`) → одна и та же CVE от BBOT+nuclei+OSV
  **схлопывается автоматически** (DefectDojo-дедуп уже работает);
- иначе `category='vuln'`, `rule_id` = slug заголовка, `location` нормализуется.
- Маленькая аддитивная правка в T1.4: `_SOURCE_CATEGORY['bbot']='vuln'` (явность;
  поведение и так корректно через fallback).

BBOT-активы получают `attrs['source']='bbot'`; AssetStore гейтит GONE **по source**
(F-A2) → `source_in_scope('bbot')=phase_ok('bbot')`, поэтому пропуск BBOT-фазы не
флапает активы GONE. Identity активов — существующая `asset_fingerprint(type,value)`
(ноль churn при пересечении с recon/subdomains: `_dedup` first-wins).

**F. Scope-маппинг (privacy/безопасность, связка с F4).**
- Запуск фазы вообще — только если Scope Guard разрешает активные действия и
  таргет в allow-scope; `--strict-scope` не даёт BBOT уходить за периметр.
- `scope_distance == 0` (in-scope) → актив **owned** → в AssetStore/FindingsStore.
- `scope_distance >= 1` (affiliate/distance-N) → **внешний контекст**, в стор НЕ
  промоутим (зеркало решения по co-hosted в `asn_intel.py`: не наш актив →
  ложные ownership/takeover-сигналы недопустимы). Опционально — как `related`
  узлы в `asset_graph` (паттерн co-hosted), но это **за рамками фазы 1**.

**G. Интеграция (одна фаза, один lifecycle).** Фаза `bbot` в `CollectionRunner`
(паттерн `_phase_osv`/`_phase_asn`): `bbot_adapter` нормализует stdout →
`report['phases']['bbot']['data'] = {assets:[...], findings:[...]}` в НАШИХ формах;
findings фолдятся в `vulns['findings']` (как `_phase_dns`) → F1-sync + risk;
assets подбираются `asset_adapter.derive_assets` тонким guarded-экстрактором
(как `katana`/`security`). Read-поверхности (Timeline/Overview/web) включаются
автоматически. Карточка отчёта «External Recon (BBOT)».

**H. Открытые вопросы → подтвердить в T1.3 (на реальном выводе, не выдумывать).**
1. Точные подполя `data` у `VULNERABILITY`/`FINDING` (имена `description`/`url`/
   `host`/`severity`) — доки их не специфицируют; адаптер читает **защитно**
   (any-of, мягкая деградация), точные имена фиксируем по сохранённому `output.json`.
2. Точный флаг подавления интерактивного dep-промпта первого запуска.
3. Формат `data` у `TECHNOLOGY`/`ASN`/`IP_RANGE` (строка vs dict) — нормализовать
   к нашему `value`/`attrs`.
4. Сопоставление BBOT `scope_distance`/`tags` с нашим owned/affiliate-решением.

**I. Зафиксированные «нет» (anti-scope-creep).** Без новых типов активов в фазе 1;
без новых SQLite-таблиц; без агрессивных пресетов по умолчанию; без обязательной
зависимости/бандла в `.exe`; OSINT-сущности (email/social/repo/bucket) — не сейчас.

---

### F2 — Document Intelligence (PDF / images / docs)

**Цель:** извлекать структурированные данные из документов, найденных в ходе
анализа (PDF/изображения/офисные файлы), и вливать находки/активы (контакты,
утечки, метаданные, ключи) в существующий lifecycle.

**Запрещено:** бандлить `torch`/`vLLM`/HF-модели в `.exe`; делать lift
обязательной зависимостью; обещать, что lift/Gemini уже интегрированы.

**Где живёт (baseline РЕАЛИЗОВАН — см. задачи ниже):**
- `core/document_intelligence.py` **[BASELINE РЕАЛИЗОВАН]** — **ядро**: offline-first контракт
  «документ → структурированные поля → наши DTO»; провайдер выбирается на чтении,
  при отсутствии — мягкая деградация (stdlib-минимум: метаданные/текст без AI).
- `core/document_providers/` **[BASELINE РЕАЛИЗОВАН]** — опциональные провайдеры за единым
  интерфейсом: `lift_adapter` (datalab-to/lift, опц. зависимость/внешний адаптер),
  возможные локальные OCR. Тяжёлый провайдер активен только если установлен.
- `core/features.py` += детект провайдеров (по модулю/бинарю), summary().
- Проводка: opt-in фаза `documents`, нормализация в `FindingsStore`/`AssetStore`,
  карточка отчёта, чекбокс Collection, monitor-паритет.

**Tasks:**
- T2.1 Research & Contract — изучить lift по документации/HF-карточке; определить
  минимальный offline-fallback (без AI) и расширенный провайдер (с моделью);
  контракт «извлечённое поле → Finding/Asset». Документ, без кода. **[ВЫПОЛНЕНО
  2026-06-21]** → результат ниже («T2.1 — Research & Contract (результат)»).
- T2.2 `features` детект провайдеров + summary в health. **[ВЫПОЛНЕНО
  2026-06-21]** — `core/features.py` += `has_pdf_text()` (любой лёгкий PDF-парсер:
  pypdf/pdfminer/fitz), `has_ocr()` (pytesseract-модуль + бинарь tesseract),
  `has_lift()` (CLI `lift_extract` на PATH — subprocess, модель не импортируем) +
  регистрация трёх тиров в `OPTIONAL_FEATURES` (видны в `features.summary()`/health).
  Лаунчер их пока не предлагает ставить (выбор lib финализируется в T2.3 → install-
  guidance позже); детект-only. Покрыто `tests/test_features.py`.
- T2.3 `core/document_intelligence.py` — ядро + провайдер-интерфейс + offline-fallback.
  **[ВЫПОЛНЕНО 2026-06-21]** — pure/offline/never-raise оркестратор: `file_metadata`
  (имя/ext/размер/sha256/mtime, tier-0 всегда), `extract_text` (лестница тиров:
  stdlib для текстовых форматов + HTML-strip; pdf-text/ocr — ленивый импорт, гейт
  `has_pdf_text`/`has_ocr`, мягкая деградация `unavailable`/`unsupported`),
  `secret_findings_from_text` (через **SSOT** `secret_scanner.scan_text` + отбраковка
  плейсхолдеров по `validation.status==INVALID`; находка `category='secret'`,
  `source='document'`, маска вместо plaintext — форма как `_secret_finding`),
  `analyze_document`/`analyze_documents` (метаданные+текст+находки, батч+summary).
  Тяжёлый lift (тир 3) — отдельно в T2.4 (не импортируется здесь). Покрыто
  `tests/test_document_intelligence.py` (12).
- T2.4 `document_providers/lift_adapter` (опц.) — изоляция тяжёлых импортов.
  **[ВЫПОЛНЕНО 2026-06-21]** — пакет `core/document_providers/` + `lift_adapter.py`:
  lift запускается ТОЛЬКО как subprocess `lift_extract` (никогда не импортируется →
  torch/vLLM не грузятся, модель не бандлится); `DEFAULT_SCHEMA` (наш контракт
  вывода: secrets[]/sensitive_data[]); `parse_output` нормализует → secret-находки
  (через общий `document_intelligence.secret_finding`, плейсхолдеры отброшены) +
  generic `vuln` «Sensitive data in document»; `LiftRunner` (never-raise,
  инъектируемые runner/detector). **Privacy:** lift пишет в TemporaryDirectory,
  удаляемую после парсинга → plaintext не персистится, в находках только маска.
  Покрыто `tests/test_lift_adapter.py` (9). Конструктор secret-находки вынесен в
  общий `secret_finding` (без третьей копии).
- T2.5 Проводка opt-in фазы + нормализация в lifecycle + карточка отчёта.
  **[ВЫПОЛНЕНО 2026-06-21]** — флаг `documents` в `CollectionRunner.__init__`/
  `configure`; фаза 7m `_phase_documents` (перечислялка `iter_candidate_documents`
  по capture/clone/images, исключая markup/наши артефакты; `analyze_documents`
  тиры 0-2 + `lift` если установлен — только PDF/изображения; фолд находок в vulns;
  артефакт `documents/documents.json`, маскированный); **локально/пассивно → НЕ
  scope-gated** (capture/clone уже были); auto-FIX scope-guard `source='document'→
  phase_ok('documents')`; карточка «Document Intelligence»; monitor-паритет
  (`_build_run_fn` += `documents`); GUI-чекбокс «Документы (secrets/PII)» +
  `_collection_options`. Web — базовый пайплайн (как osv/bbot). Покрыто
  `test_collection_runner`(+4)/`test_monitor`(+1)/`test_monitor_gui`(+1).
- T2.6 Тесты offline — провайдер застаблен; проверка деградации без модели/деп.
  **[ВЫПОЛНЕНО 2026-06-21]** — `test_document_intelligence`(15: метаданные/
  extract-тиры/деградация/секреты+маска/плейсхолдеры/батч/перечислялка),
  `test_lift_adapter`(9: инъекция subprocess/парсинг/temp-cleanup/деградация),
  плюс phase/monitor/GUI-тесты T2.5. Все offline/headless; self-check 25 вкладок.

---

#### T2.1 — Research & Contract (результат)

> Источник фактов — **только документация lift** (GitHub `datalab-to/lift` + HF-
> карточка `datalab-to/lift`), не исходники. Контракт сверен с реальными SSOT
> нашего кода: `core/secret_scanner.py` (`scan_text`/`RULES`), `core/secret_
> validator.py` (`validate`/`INVALID`), `core/findings_adapter.py`,
> `core/finding_fingerprint.py`, `core/features.py`, и evidence-слой EPIC 14
> (`evidence_manifest`/`evidence_refs`).

**A. Что такое lift (по докам).** `lift` (`pip install lift-pdf`) извлекает
**структурированный JSON из PDF/изображений по заданной JSON-схеме**: 9B vision-
модель со schema-constrained декодированием (гарантированно валидный JSON,
мультистраничные значения). Бэкенды: vLLM (база) или HuggingFace (torch+
transformers); **GPU рекомендован**. Вызов: CLI `lift_extract input.pdf ./out
--schema schema.json`, Python API `extract(...)`, либо удалённый vLLM-сервер.
Лицензия: **код Apache-2.0**, **модель — modified OpenRAIL-M** (бесплатно для
research/personal/стартапов <$5M; коммерч. — отдельно). Оффлайн после загрузки
весов.

**B. Главный вывод для архитектуры.** lift — **тяжёлый** (9B-модель + torch/vLLM,
GPU). Поэтому: **никогда не бандлить в `.exe`**, **не делать обязательной
зависимостью**, не качать модель автоматически. lift — **опциональный провайдер
верхнего тира** с мягкой деградацией; платформа обязана давать полезный результат
и без него. Лицензия модели (OpenRAIL-M) — ещё одна причина оставить её как
устанавливаемую пользователем опцию, а не часть поставки.

**C. Тиры провайдеров (выбор на чтении; отсутствие → деградация вниз).** Document
Intelligence — это не один движок, а лестница «что доступно прямо сейчас»:

| Тир | Провайдер | Зависимость | Вход → выход |
|---|---|---|---|
| 0 (всегда) | `stdlib` | нет | текстовые док-ты (txt/html/json/xml/csv) → текст; ЛЮБОЙ файл → метаданные (имя/тип/размер/sha256) |
| 1 (опц., лёгкий) | `pdf-text` | напр. `pypdf`, если установлен | PDF → извлечённый текст |
| 2 (опц.) | `ocr` | напр. `pytesseract`+бинарь, если есть | изображение → текст (OCR) |
| 3 (опц., тяжёлый) | `lift` | `lift-pdf` (+torch/vLLM, модель) | PDF/изображение + схема → структурированный JSON |

Тиры 1–3 **опциональны**; без них тир 0 всё равно даёт метаданные + текст
текстовых форматов. Тир 3 (lift) — единственный «AI», и он строго opt-in.

**D. Что считаем находкой/активом (питаем существующий lifecycle, без новой
модели данных).**
- **Секреты/ключи в тексте документа** → прогон через **SSOT** `secret_scanner.
  scan_text(text, source=<doc>)` + отбраковка плейсхолдеров `secret_validator.
  validate` (тот же путь, что `_secret_finding`) → находка `category='secret'`,
  `source='document'`, `location=<artifact path/URL>`, неутекающий
  `discriminator` (vendor+маска). Дедуп по fingerprint автоматом.
- **Чувствительные структурированные поля от lift** (по схеме: явные
  credentials/tokens/PII-поля) → находка `category='secret'` (для ключей) или
  обобщённая `category='vuln'` «Sensitive data in document» (для PII/утечки),
  `source='document'`. Точную схему-как-контракт фиксируем в T2.3/T2.5.
- **Метаданные документа** (author/producer/software/created) — **display**, не
  находка по умолчанию (метаданные сами по себе не уязвимость); могут стать
  Info-находкой «Document metadata exposure» только при явном решении (отложено).
- **Документ-как-актив** — **НЕ вводим новый тип актива в фазе 1** (зеркало F1);
  документ привязывается к находке через `evidence_refs` (артефакт из
  evidence-манифеста EPIC 14), а не как отдельный Asset. (Кандидат на будущий тип.)
- **Emails/люди из документов** → **отложено** (нет email/employee-типа актива;
  маппинг в существующие email/employee-поверхности — отдельное решение, как в F1
  для OSINT-сущностей BBOT).

**E. Источник документов (что сканируем).** Кандидаты = артефакты, уже собранные
в ходе скана (PDF/office/изображения), обнаруживаемые через **evidence-манифест /
рабочую папку скана** (EPIC 14), плюс опциональный путь, указанный пользователем.
Фаза `documents` сама **ничего не качает из сети** по умолчанию — работает по уже
полученным файлам (offline-first). Точную перечислялку артефактов фиксируем в T2.5.

**F. Ядро и интерфейс (планируемое, НЕ существует).**
- `core/document_intelligence.py` — pure-оркестратор: `extract(path|bytes, *,
  schema=None, provider=None) → {fields, text?, metadata, provider, status}`;
  выбирает доступный тир (3→0), при отсутствии — деградация; **never-raise**
  (паттерн `external_tools`/`bbot_adapter`).
- `core/document_providers/` — провайдеры за единым интерфейсом
  `extract(path, schema) → dict`; тяжёлые импорты (torch/vLLM/lift) **изолированы
  внутри** `lift_adapter` и грузятся лениво (как scrapy/llm), чтобы GUI-процесс их
  не тянул.
- `core/features.py` += детект провайдеров (`has_pdf_text`/`has_ocr`/`has_lift`
  через `find_spec`/`which`) + в `summary()` (health показывает, что доступно).

**G. Проводка (как BBOT/security — одна opt-in фаза, один lifecycle).** Фаза
`documents` в `CollectionRunner` (флаг off by default, гейт Scope Guard если
читаем что-то за пределами локальных артефактов): нормализованные находки фолдятся
в `vulns['findings']` (через `_secret_finding`/raw-dict), идут в F1-sync/risk;
карточка отчёта «Document Intelligence»; monitor-паритет
(`_build_run_fn` += `documents`); web — базовый пайплайн (как osv/asn). GUI-чекбокс
в Collection.

**H. Открытые вопросы → решить в T2.3/T2.5 (не выдумывать).**
1. Точный формат вывода lift для нашей схемы (имена полей credentials/PII) —
   фиксируем по реальному прогону/доке схемы; адаптер читает защитно.
2. Какой лёгкий PDF-текст-провайдер брать (pypdf vs pdfminer) и брать ли OCR в
   фазе 1 — выбрать минимально-инвазивный, опциональный.
3. Перечислялка кандидат-документов из evidence-манифеста (расширения, лимиты
   размера/числа).
4. Дефолтная JSON-схема lift «секреты/чувствительные данные» как контракт.

**I. Зафиксированные «нет» (anti-scope-creep, зеркало F1).** Без новых типов
активов в фазе 1; без новых SQLite-таблиц; без бандла torch/vLLM/модели в `.exe`;
без обязательной зависимости; без обязательной сети (работаем по уже собранным
файлам); emails/PII-as-asset и document-metadata-as-finding — отложены.

---

### F3 — AI OSINT Workflow Catalog

**Цель:** нормализованный, offline-каталог OSINT-воркфлоу/схем (источник идей —
Awesome-AI-OSINT) поверх существующих сущностей — «какие связки разведки имеет
смысл прогонять», без новых сканеров и без обязательной сети.

**Где живёт (baseline РЕАЛИЗОВАН — см. задачи ниже):**
- `core/osint_catalog.py` **[BASELINE РЕАЛИЗОВАН]** — чистый derive-on-read каталог
  воркфлоу/схем (как `finding_knowledge`/`compliance`): декларативное описание
  шагов поверх уже существующих движков (recon/dns/email/employee/ct/asn),
  без копирования внешнего кода. Никаких новых сетевых вызовов сам по себе.

**Tasks:**
- T3.1 Research & Curation — отобрать из Awesome-AI-OSINT воркфлоу, ложащиеся на
  существующие движки; зафиксировать схему каталога. Документ, без кода.
  **[ВЫПОЛНЕНО 2026-06-21]** → результат ниже («T3.1 — Research & Curation (результат)»).
- T3.2 `core/osint_catalog.py` — декларативный каталог + резолв в существующие фазы.
  **[ВЫПОЛНЕНО 2026-06-21]** — pure/offline модуль: `WORKFLOWS` (10 курированных
  воркфлоу по схеме T3.1), `_ENGINE_PHASE` (engine-токен → report-фаза; recon-
  производные → 'recon', osv/cve_intel → 'osv', monitor/timeline/scan_diff → None =
  платформенная способность), `catalog()` (deepcopy), `assess(report)`
  (covered/partial/not_run + ran/missing/optional_ran по `phases[*].status`),
  `available(detectors=)` (внешне-гейтнутые bbot/lift/pdf-text/ocr через features,
  инъекция в тестах), `summary(report=)`. Не влияет на risk. Покрыто
  `tests/test_osint_catalog.py` (10).
- T3.3 Поверхности (report-карточка / web read-эндпоинт) — паритет с прочими
  derive-вью; GUI опционально (память `feedback-internals-first-no-gui`).
  **[ВЫПОЛНЕНО 2026-06-21]** — `osint_catalog.load_catalog(project)` (тонкий report-
  based ридер, зеркало `tech_risk.load_technology_risk`); `collection_runner.
  _build_osint_catalog` → `report['osint_catalog']` (summary+workflows) + карточка
  «OSINT Workflow Coverage» (`_render_osint_catalog_card`, covered/partial/not_run
  с цветом); web `_osint_catalog_view` + `GET /osint-catalog` + кнопка «OSINT
  Catalog»/`showOsintCatalog()` в консоли (паритет с accuracy/technology-risk).
  Не влияет на risk. GUI отложен. Покрыто `test_osint_catalog`(+2)/
  `test_collection_runner`(+2)/`test_web_intelligence`(+4).
- T3.4 Тесты offline на каталог/резолв.

---

#### T3.1 — Research & Curation (результат)

> Источник идей — таксономия **Awesome-AI-OSINT** (ubikron, GitHub); это
> **каталог идей, не зависимость** (никакого кода не копируем/не тянем). Воркфлоу
> отобраны по принципу: **включаем только то, что уже бэкается реальным движком в
> нашем коде** (без новых сканеров, без обязательной сети). Каталог — чистый
> derive-on-read (как `finding_knowledge`/`compliance`).

**A. Что это и зачем.** Не сканер, а **декларативный каталог recon-воркфлоу**:
«какие связки разведки имеют смысл и какими нашими движками они закрываются».
Ценность в продукте — гайд/покрытие: при наличии `report` каталог аннотирует
каждый воркфлоу статусом (какие его фазы реально отработали в скане → covered/
partial/not-run) и доступностью движков. Ничего не запускает сам.

**B. Маппинг таксономии Awesome-AI-OSINT → наши движки** (берём только покрытое):

| Категория (Awesome-AI-OSINT) | Берём? | Наши движки/фазы |
|---|---|---|
| Digital Infrastructure (IP/subdomain/hosted infra) | ✅ | recon, subdomains, ct, asn_intel, infrastructure, bbot |
| Human-Centric (email / contact / people) | ✅ (частично) | emails, employees, dns (email-auth) |
| Information Monitoring (threat/change tracking) | ✅ | monitor, timeline, scan_diff, osv, cve_intel |
| Integrated Platforms (CLI/frameworks) | ✅ (как enrichment) | bbot, documents |
| Visual Intelligence (reverse-image/face/geoloc/GEOINT) | ❌ | нет движка; вне продукта (тяжёлый AI/сеть) |
| Ethnicity/face analysis, dark-web monitoring | ❌ | вне scope/этики; нет движка |

**C. Курированный набор воркфлоу (фаза 1, все бэкаются реальными движками):**
1. **Infrastructure Recon** → `recon, subdomains, ct, asn_intel, infrastructure`
   (+опц. `bbot`); даёт активы domain/subdomain/ip/asn/netblock + attack-surface.
2. **Subdomain & Takeover Surface** → `subdomains` (active), `ct`, `dns`.
3. **Email & People Surface** → `emails, employees, dns` (SPF/DMARC).
4. **Technology & Dependency Risk** → `recon` (tech_fingerprint), `dependency_audit`,
   `osv`, `cve_intel`.
5. **Web Exposure Audit** → `security` (source maps/GraphQL), `cookies`,
   `api` (secrets), `documents`.
6. **Historical & Archive Recon** → `historical`, `ct`.
7. **CVE / Threat Correlation** → `osv`, `cve_intel`, `dependency_audit`.
8. **Continuous Monitoring & Change Tracking** → `monitor`, `timeline`, `scan_diff`.
9. **External Recon Enrichment (BBOT)** → `bbot`.
10. **Document Intelligence** → `documents`.

**D. Схема записи каталога (контракт `core/osint_catalog.py`, T3.2).** Чистые dict'ы:
```
WORKFLOW = {
  'id': 'infrastructure-recon',          # стабильный slug
  'name': 'Infrastructure Recon',
  'category': 'Digital Infrastructure',  # из таксономии Awesome-AI-OSINT
  'goal': '…',                           # что выясняем
  'engines': ['recon','subdomains','ct','asn_intel'],   # ОБЯЗАТЕЛЬНЫЕ наши фазы/движки
  'optional': ['bbot'],                  # усиливающие, не обязательные
  'produces': ['assets','attack_surface'],  # что появляется в lifecycle
  'network': 'passive' | 'active',       # honest-флаг (active = нужен Scope Guard/opt-in)
}
```
Резолвер (derive-on-read): `catalog()` → список воркфлоу; `assess(report)` →
на каждый воркфлоу `{status: covered|partial|not_run, ran:[…], missing:[…]}` по
`report['phases'][engine].status=='Success'`; `available(features)` — какие движки
существуют (через `features.summary()` для опц. внешних: bbot/lift). Источник
статуса фаз — тот же `report['phases']`, что читают exec_summary/scan_diff (I3).

**E. Поверхности (T3.3).** report-карточка «OSINT Workflow Coverage» (что покрыто/
частично/не запущено в этом скане) + web `GET /osint-catalog` (паритет с прочими
read-вью). GUI — опционально/позже (память `feedback-internals-first-no-gui`).
Каталог НЕ влияет на risk-score (чистый guide/coverage — display).

**F. Зафиксированные «нет».** Каталог ничего не сканирует и не ходит в сеть сам;
не вводит новых движков/сканеров; не копирует код/данные из Awesome-AI-OSINT
(только идеи таксономии); Visual/face/geoloc/dark-web — вне scope (нет движка,
тяжёлый AI/этич. ограничения); не влияет на risk-вердикт.

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
  **[ВЫПОЛНЕНО 2026-06-21]** → результат ниже («T4.1 — Network/Privacy Audit»).
- T4.2 Проверочные тесты-инварианты (offline): новые фазы выключены при
  `active_scan_enabled=False`/`passive_only=True` (расширение
  `ACTIVE_SCOPE_GUARDED_PHASES`). **[ВЫПОЛНЕНО 2026-06-21]** — `bbot` добавлен в
  набор `run_flags` теста `test_scope_guard_blocks_all_run_active_phase_callables`
  (доказано: фаза-callable пропускается при `active_scan_enabled=False` и
  `passive_only=True`); новый позитивный тест
  `test_documents_phase_is_local_not_scope_gated` (локальная фаза исполняется при
  `passive_only=True`, отсутствует в guard-списке). Скрытых активных фаз нет.
- T4.3 Документирование гарантий в README **только после** реальной реализации
  (не описывать как сделанное заранее). **[ВЫПОЛНЕНО 2026-06-21]** — секция
  «Приватность и сетевое поведение» (offline-first/no-signup, 3 класса сетевого
  поведения, safe-by-default, прозрачность через `scope_guard.skipped_active_phases`
  + features) + bbot/lift в опц.-install блоке. Описано только реально работающее.

---

#### T4.1 — Network / Privacy Audit (результат)

> Аудит реального кода: что и когда ходит в сеть, и доказательство, что каждое
> новое (EXT-OSINT) действие — opt-in и/или локально. Сверено с
> `core/collection_runner.py` (`ACTIVE_SCOPE_GUARDED_PHASES`, `_scope_skip_active`,
> порядок фаз), `core/scope_guard.py` (`active_phase_decision`),
> `core/bbot_adapter.py`, `core/document_intelligence.py`, `core/osint_catalog.py`.

**A. Таксономия сетевого поведения (3 класса).**
1. **Базовый fetch цели** (всегда): `recon`, `api`, `capture`, `clone`, `images`,
   `cookies`, `vulns` — обращаются к **самому таргету** (авторизованное ядро
   анализа). `default_scope_for_target` для НОВЫХ проектов = `active_scan_enabled
   =False`, `passive_only=True` → даже базовый профиль не делает активных лишних
   действий, пока scope не разрешён (safe-by-default).
2. **Opt-in активные фазы** (доп. сеть сверх таргета / агрессивно): все имеют флаг
   (off by default) **И** входят в `ACTIVE_SCOPE_GUARDED_PHASES` → `_scope_skip_
   active` гейтит их через `active_phase_decision` (allow/deny-домены,
   `active_scan_enabled`, `passive_only`). Сейчас: `security, subdomains,
   certificate, openapi, historical, dns, emails, employees, ct, asn_intel, osv,
   bbot, katana, screenshot, nuclei`.
3. **Локальный/пассивный анализ** (НЕ сеть): `documents` (читает уже захваченные
   файлы), плюс все derive-on-read (`osint_catalog`, correlation, intelligence,
   timeline, exec_summary и т.д.). Эти **намеренно НЕ в** `ACTIVE_SCOPE_GUARDED_
   PHASES` — гейтить локальное чтение незачем.

**B. Аудит EXT-OSINT-добавлений (вывод: всё compliant).**

| Компонент | Сеть? | Opt-in? | Scope-gated? | Вывод |
|---|---|---|---|---|
| `bbot` фаза | да (recon-движок) | да (флаг `bbot`) | да (в списке + `_scope_skip_active`) | ✅ соответствует классу 2 |
| `documents` фаза | нет (локальные файлы) | да (флаг `documents`) | н/п (локально) | ✅ класс 3 |
| `lift` (внутри documents) | локальный subprocess (по умолч.); удалённый vLLM — только если пользователь сам настроит | да (нужен бинарь + флаг documents) | наследует documents | ✅ по умолчанию локально |
| `osint_catalog` | нет (derive) | н/п | н/п | ✅ класс 3 |

**C. Гарантии (проверяемые).**
- **No-signup / offline-first:** ни одного обязательного аккаунта/облака; тяжёлые
  деп (Playwright/lift/torch/bbot) — опциональны, не в `.exe`; отсутствие → мягкая
  деградация (доказано тестами F1/F2).
- **Никаких скрытых вызовов:** каждое сетевое действие сверх базового fetch цели —
  это **фаза с флагом**, видимая в Collection/`_collection_options`/monitor-опциях.
- **Прозрачность:** `features.summary()`/health показывает, что доступно/выключено;
  Scope Guard пишет `report['scope_guard'].skipped_active_phases` (что пропущено и
  почему).
- **Safe-by-default:** новый проект = `passive_only` до явного расширения scope.

**D. Найденный пробел (закрывается в T4.2).** `bbot` добавлен в
`ACTIVE_SCOPE_GUARDED_PHASES`, но регрессионный тест
`test_scope_guard_blocks_all_run_active_phase_callables` (E14.8) его в наборе
`run_flags` НЕ проверял → нужно добавить `bbot` (доказать, что его фаза-callable
реально пропускается при `active_scan_enabled=False`/`passive_only=True`).
Параллельно — позитивный тест: `documents` (локальная) **исполняется** даже при
`passive_only=True` (не гейтится, по дизайну класса 3).

**E. Зафиксированные «нет».** Не гейтить локальные/derive-фазы (это не сеть);
README-гарантии писать только по факту (T4.3), без оверселла; `documents` НЕ
добавлять в `ACTIVE_SCOPE_GUARDED_PHASES`.

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

---

## EPIC NEXT — Attack Path & Business Risk Intelligence Platform

> **Статус: ПЛАНИРОВАНИЕ.** **Implementation: NOT STARTED для NEXT-слоя.**
> Это стратегический план следующего горизонта, НЕ реализованный эпик. Ничего из
> NEXT-слоя ещё не написано. Реализация — строго по цепочке Epic → Feature → Task →
> Implementation → Testing → Review, по одной задаче, после утверждения плана
> конкретной фичи (см. CLAUDE.md §6).
>
> **Важно (baseline, на котором строим — уже есть, НЕ переписываем):** attack-paths
> (EPIC 11, `intelligence.build_attack_paths` + diff/monitoring EPIC 13),
> exposure (likelihood-ось), asset criticality (EPIC 9), priority (EPIC 7/10),
> scan accuracy, technology risk (EPIC 15), compliance OWASP/CWE (EPIC 16),
> EXT-OSINT (BBOT/Document Intelligence/OSINT-каталог). NEXT добавляет **бизнес-
> риск-слой ПОВЕРХ** них, переиспользуя те же движки и сторы.

### Зачем (цель эпика)

Сдвиг приоритизации с **severity-driven** на **business-risk-driven**: «что чинить
первым» учитывает не только техническую серьёзность, но и бизнес-важность актива,
чувствительность данных и контекст угроз; attack-paths становятся детерминированными
маршрутами «внешняя точка → критичный актив»; для топ-находок/путей заводятся
remediation-задачи; мониторинг ловит **семантический drift** (значимое изменение
позы), а не только появление актора; compliance расширяется до auditor-friendly
маппинга сверх OWASP/CWE; cloud/container/IaC-конфиги дают активы/находки **без
cloud-API** на первом этапе.

### Definition of Done

- Пользователь может задать **бизнес-контекст** активов (criticality, data sensitivity).
- Приоритет находок учитывает severity, confidence, exposure, business criticality,
  data sensitivity и threat context.
- Система строит **deterministic attack paths** от внешней точки до критичного актива.
- Для top findings/paths создаются **remediation tasks**.
- Monitoring умеет **semantic drift / change events**.
- Compliance умеет **auditor-friendly mapping** beyond OWASP/CWE.
- Cloud/container/IaC configs дают assets/findings **без cloud API** на первом этапе.
- Все поверхности: **core → report → GUI/web/export**, без дублирования модели.
- Все тесты **offline/headless**.

### Инварианты NEXT (поверх общих из CLAUDE.md §4–§5)

- **Никакой второй модели данных.** Бизнес-контекст = аддитивные `attrs`/ключи в
  `metadata.json` (паттерн Company-tier F-C1) и derive-on-read; запрещено заводить
  второй `AssetStore`/`FindingsStore`/`Timeline`.
- **Business risk — display/derive слой** (как priority/exposure/criticality):
  `_risk_level`/`risk_100` НЕ трогаем без отдельного явного согласования.
- **Cloud/IaC фаза 1 — БЕЗ cloud API.** Только парсинг локальных IaC/конфиг-файлов;
  любое сетевое — opt-in + Scope Guard. Тяжёлые парсеры — feature-gate + мягкая
  деградация.
- **Только authorized, evidence-based validation.** Никакого exploitation, brute
  force, auto-login, payload execution.
- **AGPL/GPL-чистота** сохраняется (как EXT-OSINT).

---

### F0 — Platform Trust Hardening

**Цель:** сначала укрепить фундамент, чтобы следующий слой не разъехался.

- **T0.1 SQLite migration framework.** **[ВЫПОЛНЕНО 2026-06-22]** — паттерн
  `FindingsStore._migrate_to_v2` поднят в базовый `utils/sqlite_store.SQLiteStore`:
  стор декларирует `SCHEMA_VERSION` (дефолт 1) + опц. `MIGRATIONS`
  (`{target_version: fn(conn)}`); `_apply_migrations` гоняет недостающие шаги по
  возрастанию, **forward-only** (не понижает версию), затем проставляет
  `user_version`. Добавлены `schema_version()` (диагностика/тесты) и идемпотентный
  `_add_column()` (безопасный аддитивный ALTER для будущих миграций). `cve_store`/
  `asset_store` сбросили своё version-stamping; `findings_store` убрал
  `_init_schema`-override и регистрирует `_migrate_to_v2` декларативно
  (`MIGRATIONS = {2: ...}`). Поведение байт-в-байт для всех трёх (старые тесты
  сторов/миграции не тронуты). Покрыто `tests/test_sqlite_migrations.py`
  (fresh/upgrade-order/partial/idempotent/no-downgrade/`_add_column`). Без слома
  существующих БД и контрактов.
- **T0.2 Contract-тесты ключей.** **[ВЫПОЛНЕНО 2026-06-22]** —
  `tests/test_contracts.py` фиксирует текущие наборы ключей всех структур, что
  читают несколько поверхностей: `report.json` (top-level + `scope_guard`),
  `metadata.json` (проект + scan-entry), executive_summary (+ метрики, что
  денормализуются в scan-entry/тренды), findings (DTO→stored row→events→summary/
  projects + lifecycle-словарь STATUSES/EVENT_TYPES), assets (то же), timeline
  (series-точка + change-event). Ассерты **subset** (`required <= produced`):
  NEXT-фичи могут ДОБАВЛЯТЬ ключи, но удаление/переименование падает loudly до
  того, как сломает GUI/web/export/scan-diff (страховка §4.7). Каждый `_KEYS`-
  константа = живая документация контракта. Pure/offline; единственный e2e-кейс
  гоняет полную коллекцию со стабом сетевых фаз и проверяет записанный
  `report.json` + metadata scan-entry.

### F1 — Business Context Model (asset criticality + data sensitivity)

**Цель:** пользователь задаёт бизнес-контекст активов.
**Где живёт:** аддитивный ключ в `metadata.json` проекта (паттерн Company-tier
membership F-C1), **без новой таблицы**.

**[ВЫПОЛНЕНО 2026-06-22]** (решение пользователя: project default + per-asset;
core+derive+report+web+CLI, GUI позже — память `feedback-internals-first-no-gui`).
- **Модель** `core/business_context.py` (pure/SSOT): вокаб `CRITICALITY_TIERS`
  (critical/high/medium/low) + `DATA_SENSITIVITY` (restricted/confidential/internal/
  public), RU-лейблы, аддитивные веса (critical 30 / high 20 / medium 10; restricted
  20 / confidential 12 / internal 5), `normalize_*`/`normalize_root`, pure-edиты
  `set_default`/`set_asset`, `resolve` (per-asset override поверх project default,
  field-by-field), `business_weight`/`business_factors`/`describe` + management-
  хелперы show/set/clear.
- **Хранение** — `Project.get/set_business_context` (RMW в `metadata.json`, как
  company/monitor/scope; нормализованный `{default?, assets?}`, ключ актива =
  bare `asset_fingerprint(type,value)`; пустой → ключ дропается, pre-F1 байт-в-байт).
  `ProjectStore.resolve(target, create=)` — общий резолвер slug/URL (для CLI/web).
- **Derive** — `intelligence.asset_criticality(..., business=)` добавляет
  business-факторы (augment type-веса, не замена); `build_asset_criticality`/
  `load_asset_criticality` принимают `business` root; **display-only** (risk-вердикт
  не тронут). Без business → байт-в-байт.
- **Поверхности** — `collection_runner._build_asset_criticality` прокидывает
  `project.get_business_context()` + кладёт `business_default` в report-карточку;
  web `_criticality_view` фолдит business из `ProjectStore(_REPORT_BASE)`; CLI
  `business_cli.py` (show/set/clear, default и per-asset через `--asset-type`/`--asset`).
- **GUI-ввод — отложен** (internals-first); чтение бизнес-контекста уже видно в
  Criticality-факторах/карточке/web. Покрыто `tests/test_business_context.py`
  (вокаб/resolve/веса/Project RMW/ProjectStore.resolve/derive boost+per-asset/
  management/CLI/web-parity).

**Tasks (выполнены):** enum-модель в `core/` ✓; set/get-примитивы ✓; derive в
`asset_criticality` ✓; report+web+CLI ✓; GUI-ввод — отложен.

### F2 — Business-Aware Prioritization

**Цель:** priority учитывает severity + confidence + exposure + business criticality
+ data sensitivity + threat context.
**Где живёт:** расширение `intelligence.priority`/`build_intelligence` (как EPIC 10
вплёл criticality-band) — **аддитивные опц. аргументы**, поведение без контекста
байт-в-байт.

**[ВЫПОЛНЕНО 2026-06-22]** (без двойного счёта — решение):
- **Business criticality + data sensitivity → priority через criticality-band.**
  F1 уже сложил их в `asset_criticality` (impact-ось); F2 прокинул `business` в
  `load_intelligence` → `build_asset_criticality(business=)`, поэтому band находки
  (и её priority-бонус «Критичный/Важный актив») теперь business-aware. Один путь,
  без отдельного аддитивного фактора → нет двойного счёта.
- **Threat context (фаза 1, статический).** Новый `intelligence._threat_tier(finding)`
  — likelihood-сигнал, отличный от severity: high = активно-эксплуатируемый класс
  (takeover/secret/инъекция-RCE-правило), medium = exposure/known-vuln (graphql/
  sourcemap/CVE-несущая либа). `priority(..., threat_tier=)` добавляет именованный
  бонус (high +10 / medium +5); `build_intelligence` считает tier на находку,
  прокидывает и кладёт `threat` в item. Live KEV/EPSS — opt-in follow-up, НЕ фаза 1.
- **Проводка:** `collection_runner._build_intelligence` и web `_intelligence_view`
  передают `project.get_business_context()`. Priority — **display** (risk-вердикт не
  тронут); без business/threat → байт-в-байт. Покрыто `tests/test_intelligence.py`
  (threat-классификация/бонус/byte-identical-без-tier; business поднимает priority
  через band end-to-end).

### F3 — Deterministic Attack Paths (external → critical asset)

**Цель:** маршрут от внешней точки входа до критичного актива.
**Где живёт:** углубление `intelligence.build_attack_paths` (EPIC 11).

**[ВЫПОЛНЕНО 2026-06-22]** (аддитивное углубление поверх кластерной модели EPIC 11,
без шумного rewrite графа):
- **Детерминированный маршрут external → critical.** Каждый путь теперь несёт явный
  **`goal`** (единственный самый ценный достижимый актив = лучший criticality-band,
  business-aware, ties по имени) + **`hops`** — спелл-аут цепочки
  `entry (foothold) → pivot (общий infra-узел) → goal (critical asset)`
  (`[{node, kind: entry|pivot|target}]`). Старые ключи (entry/pivot/targets/
  critical_targets/score/band) целы → существующие тесты/score байт-в-байт.
- **Business-aware target criticality.** `load_attack_paths(project, business=)`
  прокидывает `project.get_business_context()` в `build_asset_criticality`, поэтому
  `goal`/`critical_targets` (и какие пути «дотягиваются до критичного актива»)
  учитывают бизнес-важность (F1/F2 параллель, которую F2 для attack-paths не трогал).
- **CDN-edge кластеры пропускаются** — co-location за CDN это артефакт, не реальный
  lateral-pivot (использует существующий `shared_infra[].cdn`-флаг). Точность ↑.
- **Поверхности:** `collection_runner._build_attack_paths` + web `_attack_paths_view`
  передают business; report-карточка показывает детерминированный endpoint (колонка
  «Goal» = `goal [band]` + счётчик targets). GUI не перестраивался (новые ключи
  аддитивны; память `feedback-internals-first-no-gui`). Мониторинг (EPIC 13 диффит
  attack-paths по pivot-identity) ловит новые пути автоматом. Display-only (risk-
  вердикт не тронут). Покрыто `tests/test_intelligence.py` (goal/hops/CDN-skip/
  goal-selection по band+имени).

### F4 — Remediation Tasks

**Цель:** для top findings/paths создаются remediation-задачи (status/owner/due).
**Где живёт:** lifecycle поверх существующей `finding_events` (паттерн
`github_issues` ISSUE_CREATED маркер / SLA one-shot) — **без новой таблицы**.
core → report-карточка → GUI/web/export/CLI (паттерн issues/compliance).

### F5 — Semantic Drift Monitoring

**Цель:** monitoring ловит значимое изменение позы, а не только появление актора.
**Где живёт:** поверх `scan_diff`/`diff_events`/`timeline` — новый класс событий
«drift» (значимое смещение exposure/criticality/attack-path band между сканами),
alertable через существующий Alert Center. Derive, web-паритет автоматом.

### F6 — Auditor-Friendly Compliance

**Цель:** маппинг beyond OWASP/CWE (PCI-DSS / ISO 27001 / NIST CSF / SOC2).
**Где живёт:** расширение `core/compliance.py` (один SSOT `classify` →
доп. фреймворк-маппинг); auditor-friendly export через уже готовые
Markdown/CSV/SARIF-поверхности. Без новой системы маппинга.

### F7 — Cloud / Container / IaC Config Ingestion (фаза 1, без cloud API)

**Цель:** локальные IaC/конфиги (Terraform / CloudFormation / k8s manifests /
Dockerfile / docker-compose) → активы/находки.
**Где живёт:** opt-in фаза в `CollectionRunner` (паттерн `_phase_*`), парсинг
**локальных файлов** (нет cloud-API в фазе 1; любое будущее API — Scope Guard +
отдельный Task); нормализация через существующие `asset_adapter`/`findings_adapter`.
Тяжёлые парсеры — feature-gate + мягкая деградация (паттерн document_providers).

### Точки интеграции (существующие — переиспользовать, НЕ дублировать)

- `core/intelligence.py` — priority / criticality / exposure / attack_paths.
- `core/correlation.py` + `core/asset_graph.py` — отношения активов/инфры.
- `core/compliance.py` — единый SSOT маппинга (F6).
- `core/findings_store.py` (`finding_events`) — remediation/issue/one-shot маркеры (F4).
- `core/scan_diff.py` + `core/timeline.py` + `core/alerts.py` — drift-события (F5).
- `core/scope_guard` (EPIC 14) — гейт любых активных/сетевых действий (F7).
- `core/asset_adapter.py` + `asset_store.py` + `metadata.json` — business-context attrs (F1, паттерн Company-tier).
- `remote/web_app.py` — read-поверхности (паритет с GUI).

### Зафиксированные «нет»

- Не дублировать модель данных (второй AssetStore/FindingsStore/Timeline — запрещено).
- Не вводить cloud-API в фазе 1 F7.
- Не добавлять exploitation / brute force / auto-login / payload execution.
- Не менять risk-вердикт (`_risk_level`/`risk_100`) без отдельного согласования.
- Не копировать AGPL/GPL-код.
- README не описывать как готовое до факта реализации.
- `core/collection_runner.py` — проводка opt-in фаз (паттерн `_phase_osv/_phase_asn`).
- `core/monitor.py` (`_build_run_fn`) — monitor-паритет.
- `core/scope_management` / Scope Guard (EPIC 14) — гейт активных действий.
- `remote/web_app.py` — read-поверхности (паритет с GUI).

---
