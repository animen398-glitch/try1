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

> **Статус: ЗАКРЫТ (2026-06-22; GUI-хвосты 2026-06-23).** F0–F7 реализованы —
> подробный итог см. в закрывающем блоке в конце эпика. Раздел сохранён как
> проектное обоснование и контракт реализованного слоя; новые задачи ведём
> строго по цепочке Epic → Feature → Task → Implementation → Testing → Review,
> по одной задаче, после утверждения плана конкретной фичи (см. CLAUDE.md §6).
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
- **GUI-ввод — `[ВЫПОЛНЕНО 2026-06-23]`** (снят отложенный по запросу): редактор
  бизнес-контекста проекта в Criticality-вкладке (`gui/tab_criticality.py`) — два
  комбо (критичность бизнеса + чувствительность данных) с «—»=unset + кнопка
  «Применить к проекту»; запись off-thread через `business_context.
  set_business_context`, затем пересчёт критичности. Заодно закрыт пробел: вкладка
  теперь грузит criticality **с** business (`_query_crit_table` тянет
  `Project.get_business_context()` → `load_asset_criticality(business=)`), комбо
  пресетятся из сохранённого default. Per-asset override остаётся на CLI
  (`business_cli.py`) — в таблице показывается display-label, неоднозначный для
  ключа asset-fingerprint. Покрыто `tests/test_criticality_tab.py` (combo/populate/
  write-persist-boost/apply-writes-metadata). Покрытие core — `tests/
  test_business_context.py`.

**Tasks (выполнены):** enum-модель в `core/` ✓; set/get-примитивы ✓; derive в
`asset_criticality` ✓; report+web+CLI ✓; **GUI-ввод project default ✓**
(per-asset GUI — отложен, есть в CLI).

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
**Где живёт:** lifecycle поверх существующей `finding_events` — **без новой таблицы**.

**[ВЫПОЛНЕНО 2026-06-22]** (event-sourced, решение: core+report+web+CLI, GUI позже):
- **Модель/персист** — задача = work-item на находке (status `open`/`in_progress`/
  `done` + опц. owner/due/note), **event-sourced** поверх `finding_events`: один
  `REMEDIATION`-event на изменение, текущее состояние = последний event (note=JSON),
  без второй таблицы (паттерн `ISSUE_CREATED`-маппинга). `FindingsStore.set_remediation`/
  `get_remediation`/`remediations(project)` (`EVENT_TYPES += 'REMEDIATION'`).
- **Логика** `core/remediation.py` (pure SSOT): вокаб+RU-лейблы, `normalize_task`/
  `merge_task` (partial update; пустая строка очищает поле), `is_overdue` (due в
  прошлом и не done; date-only = конец дня), `set_task`, `auto_create_tasks`
  (идемпотентный seed `open`), `seed_from_intelligence` (top-N по priority — находка
  на критичном пути уже высокоприоритетна F2/F3, так что «top findings/paths»
  покрыто без fuzzy path→finding маппинга), `load_remediation` (rollup: overdue-
  first сортировка + summary total/open/in_progress/done/overdue).
- **Поверхности** — `collection_runner._build_remediation` (**read-only**: скан НЕ
  авто-создаёт задачи, они user/CLI-owned) + карточка «Remediation»; web
  `_remediation_view` + `GET /remediation` + кнопка/`showRemediation()`; CLI
  `remediation_cli.py` (`list`/`auto`/`set`).
  Workflow-state, **не** risk-сигнал (вердикт не тронут). Покрыто
  `tests/test_remediation.py` (merge/overdue/event-sourced latest-wins/auto-idemp/
  load summary/seed_from_intelligence/web/CLI).
- **GUI-вкладка — `[ВЫПОЛНЕНО 2026-06-23]`** (снят отложенный): `gui/tab_remediation.py`
  (`RemediationTabMixin`, секция «Управление» после Findings) — per-project селектор
  (`FindingsStore.projects()`), rollup-карты (всего/открыто/в работе/просрочено),
  таблица задач (статус/severity/находка/owner/срок, просрочка подсвечена), редактор
  выбранной задачи (status-комбо + owner + due → `set_task` off-thread) и кнопка
  «Создать для топ-находок» (`seed_from_intelligence` top-10). Зеркало
  editable-Findings; lazy-load в `tab_history`. Покрыто `tests/test_remediation_tab.py`.
- **Attack-path remediation** идёт через priority-seed (находка-entry критичного пути
  ранжируется высоко) — прямой path→task маппинг отложен (нет стабильного id у пути).

### F5 — Semantic Drift Monitoring

**Цель:** monitoring ловит значимое изменение позы, а не только появление актора.
**Где живёт:** поверх `scan_diff`/`diff_events`/`timeline`.

**[ВЫПОЛНЕНО 2026-06-22]** (derive, web/timeline/alerts-паритет автоматом):
- **Posture-блок в Scan Diff.** `scan_diff.diff` рядом с `risk`-блоком кладёт
  `posture: {a, b}` из `executive_summary.metrics` (`_posture_metrics`) — агрегатные
  intelligence-числа (attack_surface_score / exposed_assets / critical_assets).
  Безусловно (как `risk`), не section (не в `SECTION_PHASES`).
- **Drift-события.** `diff_events` эмитит `attack_surface_drift` / `exposure_drift` /
  `criticality_drift` (все medium) при **значимом росте** метрики (`_POSTURE_DRIFT`-
  пороги: surface +8 / exposed +3 / critical +2). **Гейт `a>0 and b>0`** — первое
  измерение / только-что-включённая фаза не считается дрейфом (discrete `new_*`-
  события уже покрывают первое появление). Только worsening (рост); снижение — не
  событие.
- **Alertable** (CSM «поза деградирует»): три типа в `alerts.ALERT_TYPES`; метки в
  `gui/tab_timeline._EVENT_LABELS` + Settings (`gui/dialogs`, покрыто alert-label
  тестом). Web/`/timeline`/Alert Center получают их автоматом (общий `diff_events`).
- **Attack-path band НЕ дублируется** — уже мониторится EPIC 13
  (`new_attack_path`/`attack_path_escalated`); F5 покрывает остальные intelligence-оси.
  Pure derive, без новых данных/таблиц, risk-вердикт не тронут. Покрыто
  `tests/test_diff_events.py` (классификация+alertable / ниже порога+снижение молчат /
  first-measurement guard) и `tests/test_scan_diff.py` (posture-блок + end-to-end).

### F6 — Auditor-Friendly Compliance

**Цель:** маппинг beyond OWASP/CWE (PCI-DSS / ISO 27001 / NIST CSF / SOC2).
**Где живёт:** расширение `core/compliance.py` (один SSOT `classify`).

**[ВЫПОЛНЕНО 2026-06-22]** (derive над OWASP-классом — без второй системы маппинга):
- **Crosswalk** `core/compliance.py`: `AUDITOR_FRAMEWORKS`+`FRAMEWORK_LABELS` (PCI DSS
  v4.0 / ISO/IEC 27001:2022 / NIST CSF 2.0 / SOC 2 TSC) + `_OWASP_FRAMEWORKS`
  (каждая OWASP Top-10 2021 категория → репрезентативный контрол каждого
  фреймворка) + `frameworks_for(owasp)`. `classify()` += ключ `frameworks` (derive
  из owasp; unmapped → `{}`; owasp/owasp_name/cwe не тронуты → аддитивно).
  `build_compliance` кладёт `frameworks` в каждый bucket.
- **Auditor-поверхности** (готовые экспорты, без новых): `report_export.
  compliance_markdown` += таблица «Framework crosswalk» (категории с находками →
  PCI/ISO/NIST/SOC2); `_sarif_tags` += теги `PCI-DSS:…`/`ISO-27001:…`/`NIST-CSF:…`/
  `SOC2:…` (тот же SSOT → SARIF несёт полную таксономию). `monitor_cli compliance`
  получает crosswalk автоматом (зовёт `compliance_markdown`).
- Представительные ссылки для triage/coverage (не замена формального аудита). Pure
  derive, без схемы/новых данных, risk не тронут. Покрыто `tests/test_compliance.py`
  (frameworks в classify/bucket / unmapped→пусто / полнота по всем 10) и
  `tests/test_report_export.py` (crosswalk-таблица + SARIF framework-теги).

### F7 — Cloud / Container / IaC Config Ingestion (фаза 1, без cloud API)

**Цель:** локальные IaC/конфиги (Terraform / CloudFormation / k8s manifests /
Dockerfile / docker-compose) → активы/находки.
**Где живёт:** opt-in фаза в `CollectionRunner`, парсинг **локальных файлов**.

**[ВЫПОЛНЕНО 2026-06-22]** (фаза 1, без cloud API; core+phase+CLI, GUI позже):
- **Движок** `core/iac_scanner.py` (pure/offline/never-raise): `scan_path(path)` →
  `{findings, technologies, summary}`. Парсеры (консервативные, high-signal):
  Dockerfile (stdlib: root-контейнер / unpinned-образ / ADD remote-URL), Terraform
  `.tf` (stdlib regex: `0.0.0.0/0` / public-read ACL), CloudFormation JSON (stdlib:
  открытый SG / публичный бакет), docker-compose / k8s / CloudFormation-YAML
  (опц. PyYAML — `features.has_yaml`; нет → мягкий skip, stdlib-форматы работают).
  Секреты — через SSOT `secret_scanner.scan_text` (`document_intelligence.
  secret_findings_from_text` получил `source=`-параметр → `source='iac'`, маска,
  валидатор). Находки: `category='iac'` (misconfig) / `'secret'`, `source='iac'`,
  `location`=repo-relative; образы → technologies (assets).
- **Канон-вокаб**: `'iac'` в `finding_fingerprint.CATEGORIES`,
  `finding_knowledge['iac']` (description/impact/remediation), `compliance.
  _CATEGORY_MAP['iac']` → A05/CWE-1032 (+F6 framework-crosswalk автоматом).
- **Проводка** `CollectionRunner`: флаги `iac`/`iac_path` (__init__/configure),
  `_phase_iac` (фолд находок в vulns как `_phase_documents`; **локально → НЕ в**
  `ACTIVE_SCOPE_GUARDED_PHASES`), `in_scope` `'iac'→phase_ok('iac')`, карточка
  «IaC Config». `asset_adapter`: образы из `phases.iac.data.technologies` →
  technology-активы (`source='iac'`; `ASSET_SOURCE_PHASES['technology'] += 'iac'`)
  → инвентарь/Timeline/web автоматом.
- **CLI** `iac_cli.py` (ad-hoc scan репозитория → находки/образы/JSON; без
  персиста — lifecycle идёт через фазу). Monitor — отложен (фаза path-based,
  не URL-based). Покрыто `tests/test_iac_scanner.py` (5 форматов + секреты +
  robustness + YAML-gate + фолд в vulns + промоут активов + таксономия).
- **GUI-вкладка — `[ВЫПОЛНЕНО 2026-06-23]`**: `gui/tab_iac.py`
  (`IaC Config`, секция «Управление») — ad-hoc локальный scan path/file/folder
  через `core.iac_scanner.scan_path`, rollup-карты (files/findings/images/YAML
  skipped), таблица findings, таблица container images, detail panel и JSON export.
  Вкладка intentionally read-only для lifecycle: она не пишет findings/assets в
  store; персистентный lifecycle остаётся у opt-in `CollectionRunner(iac=True,
  iac_path=...)`. Покрыто `tests/test_iac_tab.py`.

---

> **EPIC NEXT — ЗАКРЫТ (2026-06-22).** F0–F7 реализованы: Platform Trust Hardening
> (миграции+contract-тесты), Business Context Model, Business-Aware Prioritization,
> Deterministic Attack Paths, Remediation Tasks, Semantic Drift Monitoring,
> Auditor-Friendly Compliance, Cloud/Container/IaC Ingestion. Все — core→report→
> web/CLI, offline/headless тесты, без второй модели данных, risk-вердикт не
> перестроен. **GUI business-контекста (project default) — добавлен 2026-06-23**
> в Criticality-вкладку (project default + per-asset override, добавлен per-asset
> 2026-06-23). **Remediation GUI-вкладка — добавлена 2026-06-23.**
> **IaC Config GUI-вкладка — добавлена 2026-06-23.**
> **Отложено (осознанно, не блокеры):** live threat-feed (KEV/EPSS) для F2;
> live cloud-API для F7; прямой path→task маппинг для F4.

---

## EPIC CLOSED — Client-Safe Pentest Workbench

> Status 2026-06-28: implemented locally and release-checked. Final checkpoint:
> `ruff check .` clean; full pytest 2020 passed with 1 existing Starlette/httpx
> warning; `python main.py --self-check` = 29 tabs; PyInstaller build with
> `QT_API=pyside6` passed; frozen `dist/SiteAnalyzer.exe --self-check` exited 0.
> Remote git actions were not performed.

Implemented surface:
- Core contracts: `audit_workflow`, `scope_policy`, `action_policy`,
  `finding_validation`, `finding_quality`, `audit_schema` and
  `schemas/asa_*.schema.json`.
- Persistence: `AuditRunStore` with `audit_runs` / `audit_events`, row-level
  project export/import via `project_io` (`audit_runs.json`).
- Reports: deterministic audit JSON, Markdown and HTML views over the canonical
  audit-run payload.
- GUI: thin `gui/tab_audit_runs.py` tab with project selector, ROE controls,
  safe-check selection, phase progress, history/open, evidence refs and exports.
- Integration: timeline audit-run events, granular finding/quality/confidence
  audit events, independent evidence ref verification.
- Safety: client_safe policy blocks destructive/bruteforce/stealth/exploit
  actions; active checks are ROE/scope-gated, opt-in and offline-testable.

> Цель: расширить ASA из ASM/CSM-платформы в **client-safe Authorized Pentest
> Workbench**: управляемый, доказательный, повторяемый процесс аудита, который
> можно показывать клиентам, CISO и аудиторам. Это не автономный exploit-toolkit:
> активные действия только в заданном scope, destructive/bruteforce/stealth/payload
> execution запрещены.

### Продуктовая рамка

- **Client-safe by default.** Safe active checks, evidence collection, validation,
  reports, remediation, audit log. Любая потенциально шумная/активная проверка
  должна быть opt-in, rate-limited и scope-gated.
- **Не копировать scanner/prompts из Cloudflare security-audit-skill.** Берём
  методологию процесса: Collect/Recon → Hunt → Validate → Prioritize → Report →
  Verify, адаптируя под desktop/local ASM.
- **SQLite lifecycle остаётся source of truth.** JSON/schema — контракт экспорта
  и машинной проверки, а не новое главное хранилище findings.
- **Human-in-the-loop.** Workbench помогает оператору проводить легальный аудит,
  но не делает stealth exploitation, credential attacks, brute force, auto-login,
  persistence или payload execution.

### Фазы Audit Run

1. **Recon Snapshot** — зафиксировать входной срез проекта: assets, latest scans,
   findings, scope/ROE, business context, existing unresolved issues.
2. **Finding Hunt** — собрать кандидаты из существующих фаз ASA и safe active
   checks; не дублировать существующие scanners.
3. **Validation / False Positive Check** — отдельный validator проверяет evidence,
   affected asset/location, reachability/context и снижает confidence при слабых
   доказательствах.
4. **Risk + Business Impact** — приоритизация через severity, confidence,
   exposure, criticality, business context, remediation cost/urgency.
5. **Structured Output** — audit_run JSON + findings JSON по схемам, плюс HTML/MD
   report как view над теми же данными.
6. **Independent Verification / Evidence Check** — финальная проверка, что заявленные
   evidence_refs существуют в captured artifacts / project tree / findings store.

### Новые core-контракты

Предлагаемые файлы:

- `core/audit_workflow.py` — Audit Run lifecycle, phases, additive runs.
- `core/scope_policy.py` — scope/ROE, allowed targets, forbidden paths, rate limits.
- `core/action_policy.py` — policy profiles (`client_safe`, later `operator_manual`).
- `core/finding_validation.py` — deterministic/offline validation and confidence
  adjustment.
- `core/finding_quality.py` — quality gate before critical/client report.
- `core/audit_schema.py` — JSON schema loading/validation helpers.
- `schemas/asa_audit_run.schema.json`
- `schemas/asa_finding.schema.json`
- `schemas/asa_validation.schema.json`

Минимальный API:

```python
create_audit_run(project: str, phases: list[str] | None = None, *, run_id: str | None = None) -> dict
advance_audit_phase(run: dict, phase: str, result: dict | None = None) -> dict
validate_finding(finding: dict, evidence: dict | None = None) -> dict
apply_quality_gate(finding: dict, *, min_confidence: int = 70) -> dict
audit_run_to_json(run: dict) -> dict
validate_audit_payload(payload: dict, schema_name: str) -> dict
```

Минимальные статусы:

- audit run: `pending` / `running` / `completed` / `failed`
- phase: `pending` / `running` / `completed` / `failed` / `skipped`
- validation: `unverified` / `verified` / `rejected` / `needs_review`
- quality gate: `passed` / `failed`

### Quality Gate

Finding попадает в client-facing critical report только если:

- есть affected asset/location;
- есть evidence или evidence_refs;
- есть impact/business impact;
- есть remediation;
- есть reachability/context или явное объяснение почему это конфигурационный риск;
- `confidence >= threshold`;
- `validation_status != rejected`.

Defense-in-depth gaps и чистая теория не должны автоматически становиться
vulnerability: они могут идти как informational / recommendation.

### Additive Audit Runs

- Повторные Audit Runs дополняют друг друга, а не перетирают lifecycle.
- Known unresolved findings могут валидироваться повторно.
- Новые runs должны уметь ссылаться на existing `finding_id`.
- Timeline получает события audit-run уровня: run started/completed, finding
  verified/rejected, confidence changed, quality-gate failed/passed.

### GUI: Audit Runs

Status 2026-06-28: implemented as `gui/tab_audit_runs.py`; registered in the
main GUI, covered by headless tests, and verified by `main.py --self-check`.

Будущая вкладка `gui/tab_audit_runs.py`:

- selector project/scope profile;
- Start Audit Run;
- phase progress по 6 этапам;
- verified / rejected / needs_review findings;
- confidence + quality gate status;
- evidence refs;
- export audit JSON/HTML;
- все long-running actions через `_run_async` / `_start_task`;
- GUI тонкий: без бизнес-логики, только вызовы core API.

### Safe Active Checks (после базового workflow)

Разрешённый client-safe контур:

- headers/cookies/security config;
- exposed files/source maps;
- GraphQL introspection detection;
- dependency/CVE correlation;
- TLS/config checks;
- non-destructive endpoint probing;
- IaC/local config checks.

Запрещено в client-safe profile:

- brute force / credential attacks;
- stealth/evasion;
- exploit execution;
- destructive payloads;
- auto-login / auth bypass;
- persistence;
- запуск вне scope/ROE.

### Разделение работ Claude Code / Codex

**Claude Code** делает core contract и архитектуру:

- `core/audit_workflow.py`
- `core/scope_policy.py`
- `core/action_policy.py`
- `core/finding_validation.py`
- `core/finding_quality.py`
- `core/audit_schema.py`
- `schemas/*.schema.json`
- базовые contract tests.

**Codex** делает hardening, tests, release-readiness и GUI после стабилизации
контракта:

- edge-case tests;
- schema invalid-payload tests;
- offline/headless regressions;
- GUI `tab_audit_runs.py`;
- self-check / full pytest / frozen smoke.

Если core API недостаточен, Codex не импровизирует, а запрашивает контракт:
какой файл нужен, зачем, минимальный API/структура данных, какие тесты должны
подтвердить контракт.

### Definition of Done

Status 2026-06-28: all items below are satisfied in the local worktree. The
final verification checkpoint is recorded above; the remaining work is external
review / user-side remote publication, not code completion.

- Audit Run создаётся и проходит фазы offline/deterministic.
- Validation может подтвердить, отклонить или отправить finding в needs_review.
- Quality Gate не пропускает finding без evidence/impact/remediation.
- JSON exports валидируются схемами.
- Повторный run additive и не ломает Findings lifecycle.
- Timeline/report surfaces получают audit-run status без новой второй системы
  findings.
- GUI Audit Runs thin, headless tests зелёные.
- `ruff`, targeted pytest, full pytest и `main.py --self-check` зелёные.

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

## EPIC CLOSED — Workbench v2 (Audit Scenarios, Re-validation & A/B Comparison)

> Status 2026-06-28: core contract implemented locally and verified. Checkpoint:
> `ruff` clean on the changed set; full `pytest` = 2064 passed, 1 existing
> Starlette/httpx warning; `python main.py --self-check` = 29 tabs. Remote git
> actions were not performed. GUI/web parity is contract-only (left to Codex).

Extends the closed Client-Safe Pentest Workbench; reuses its contracts, never
duplicates them. Single `FindingsStore` source of truth kept; all new payloads
derive from it; schema growth is additive/optional; everything client-safe,
pure, deterministic and offline.

**F1 — Audit scenario templates** (`core/audit_templates.py`): pure registry of
four scenarios (`light_client_safe`, `authenticated_review`, `evidence_refresh`,
`release_regression`). `create_audit_run` gains keyword-only
`template`/`roe`/`baseline_run_id`; a bare call stays byte-identical to v1. A
template selects an ordered phase subset, a safe-check subset, a ROE-template
name, a confidence floor and client-safe flags. `auth_context` means an
operator-supplied authorized session — never credential acquisition.

**F2 — ROE/scope templates** (`core/audit_scope.py`): `ROE_TEMPLATES`
(`passive_external`, `authenticated_internal`, `evidence_only`, `release_gate`)
+ `list_roe_templates`/`roe_template`/`apply_roe_template`. Passive templates
validate clean; `authenticated_internal` stays invalid until the operator fills
allowed_domains + authorized_by. `create_audit_run` resolves a scenario's
roe_template into a normalized ROE when no explicit roe is passed.

**F3 — Re-validation of unresolved findings** (`core/audit_revalidation.py`):
re-checks OPEN/IN_PROGRESS findings via `FindingsStore.active_findings`
(FIXED/IGNORED/FALSE_POSITIVE excluded → sticky suppression holds), reusing
`finding_validation` + `finding_quality`. Output is a validation overlay shaped
for `advance_audit_phase(run, "validation", result)`; lifecycle status in the
store is never mutated.

**F4 — Audit Run A/B comparison** (`core/audit_compare.py` +
`schemas/asa_audit_compare.schema.json`): compares two run payloads by
`finding_id` into new/resolved/regressed/improved/unchanged with severity and
validation movement; deterministic `compare_gate`. A failed candidate phase is
inconclusive and never fails the gate alone (mirrors Scan Diff). Derive-on-read;
no new table; `compare_stored` resolves runs from `AuditRunStore`.

**F5 — Report surfaces** (`core/audit_report.py`): run JSON/MD/HTML show an
additive scenario block (template/auth/baseline/ROE) only when present; new
`render_compare_json/markdown/html` are views over the compare payload — no
second findings source.

### Decisions locked (2026-06-28)

1. Bare `create_audit_run` keeps v1 behavior (full 6 phases); templates opt-in.
2. `authenticated_review` enables only safe active checks; zero credential work;
   operator brings the session out-of-band.
3. A/B compare is derive-on-read (no new table); only a `compared` event may be
   logged for the audit trail.
4. A failed candidate phase = inconclusive, not regression; the release gate
   never fails on that alone.

### Deferred (not blockers, contract-only here)

GUI selectors/buttons in `gui/tab_audit_runs.py` (template + ROE-template,
Re-validate unresolved, Compare with…), `remote/web_app.py` read parity, and an
optional opt-in `compared` event persisted on the run. Left to Codex after the
contract stabilizes.

---

## EPIC CLOSED — KEV/EPSS Threat Intelligence Feed

> Status 2026-06-28: implemented locally and verified. Checkpoint: `ruff` clean
> on the changed set; full `pytest` = 2101 passed, 1 existing Starlette/httpx
> warning; `python main.py --self-check` = 29 tabs. Remote git not performed.

Rank findings by real-world exploitability, not just severity. Findings carrying
a CVE are enriched from two keyless public feeds — CISA KEV (known-exploited) and
FIRST EPSS (exploitation probability) — and that signal feeds the existing
priority via `threat_tier`. No new data model: the cache extends `CVEStore`,
finding enrichment is derive-on-read; the priority/risk formula is unchanged.

**F1 — Feed parsers + cache** (`core/threat_feed.py` + `CVEStore.cve_threat`):
pure KEV/EPSS parsers + one injectable network seam (soft-degrade to empty); a
`cve_threat` table (kev/kev_date/epss/epss_percentile) added via the idempotent
schema, folded into clear/prune/stats.

**F2 — Orchestrator + annotation** (`core/threat_intel.py`): `enrich_cves`
(network: fetch KEV once + EPSS for stale CVEs, persist; soft-degrade when both
feeds are empty — never write false negatives) and `annotate` (offline
derive-on-read: attach a `threat` block + deterministic `tier`). Thresholds:
KEV→high; EPSS percentile ≥0.90→high, ≥0.50→medium (named constants).

**F3 — Priority seam** (`core/intelligence.py`): `_threat_tier` prefers the
enrichment block, falls back to the static heuristic (no regression);
`build_intelligence` gains a best-effort offline annotate (cold cache = no-op),
so a KEV finding outranks an equal non-KEV one through the unchanged formula.

**F4 — Opt-in phase + parity** (`core/collection_runner.py` `_phase_threat`,
`core/monitor.py`, `gui/tab_collection.py`): after cross-scanner dedup, warm the
threat cache for the scan's CVEs. Metadata about CVEs (no target traffic) → not
scope-gated; off by default; soft-degrades offline; monitor + GUI parity.

**F5 — Surfaces**: report.html "Exploitability (KEV/EPSS)" card, web
`/findings` threat block, findings CSV KEV/EPSS columns.

### Decisions locked (2026-06-28)

1. tier mapping: KEV→high; EPSS percentile ≥0.90→high, ≥0.50→medium; else static
   fallback. Thresholds are named constants.
2. MVP feeds priority only; KEV→SLA tightening deferred (touches the verdict).
3. `threat_feed` is opt-in network metadata (like osv/asn), not Scope-Guard
   active-gated (no target traffic).
4. Cache TTL 24h for KEV + EPSS, pruned by age in `CVEStore`.

### Follow-up — KEV→SLA tightening (CLOSED 2026-06-28)

> Approved as a separate unit (decision #2 above held it for explicit sign-off,
> which the user gave). Implemented in `core/findings_sla.py` (pure derive-on-read,
> no schema change) + one backend wiring in `core/collection_runner._sync_findings`.

A finding carrying a real KEV/EPSS ``threat`` block has its severity SLA window
**multiplied down** (a floor — it can only shrink): tier `high` (KEV or
EPSS≥0.90) ×0.25, tier `medium` (EPSS≥0.50) ×0.5 (`THREAT_SLA_MULTIPLIER`, named,
per-tier overridable via the new `threat_mult` param). `sla_status` now returns
the *effective* `sla_days` plus `base_sla_days` + `tightened_by`
(`kev`/`epss`/`None`), so every derived value (due/breach/days_left/bucket/summary)
reflects the shortened deadline. Self-gating: only the cached exploitability
signal tightens — the static priority heuristic deliberately does not, and a
finding with no `threat` block keeps its plain severity window (zero change for
un-enriched runs). Every breach surface annotates active findings from the
offline threat cache first (cold cache = no-op): the collection report's
`sla_summary`, the **Alert Center** `collect_sla_alerts` (a KEV finding fires its
breach alert on the shortened deadline), and the **Timeline** `sla_events` (the
`sla_breach` event lands at the tightened due date). The single best-effort
read-side wrapper is `threat_intel.annotate_offline` (SSOT — the SLA/alerts/
timeline/priority paths share it instead of each re-implementing the guard).

### Follow-up — NEW_KEV timeline event + KEV alert rule (CLOSED 2026-06-28)

Surface known-exploited findings as first-class change/alert signals, derive-on-read
from the offline threat cache (no second table):

* **Timeline `new_kev` event** — `threat_intel.kev_events(findings)` emits one
  timeline-shaped row per active finding whose CVE is KEV-listed (dated at the
  finding's `first_seen_at`, severity `high`, base severity in the title). Wired
  through `timeline.build_events` (new `kev_events` param) off the *same* annotated
  active-findings list already used for SLA (annotate once). De-dup/order via the
  existing builder.
* **KEV alert rule** — `alerts.collect_kev_alerts` + `notify_kev` (type `new_kev`
  added to `ALERT_TYPES`), a finding-based one-shot channel like SLA/secret/generic
  (`FindingsStore.record_kev_alerts`, marker `KEV_ALERTED`, reopen-resetting).
  Dispatched in `monitor._run` alongside the other finding-based channels; cold
  cache fires nothing. GUI labels added (`gui/dialogs`, `gui/tab_timeline`).

### Follow-up — KEV/EPSS badge in findings detail (CLOSED 2026-06-28)

`gui/tab_findings.py` now threat-annotates the loaded rows from the offline cache
(`threat_intel.annotate_offline`) *before* the SLA annotate, so the GUI SLA column
is tightened for known-exploited findings too (consistent with the report), and
the detail panel shows an **⚠ Exploitability** badge (single wording via
`threat_intel.threat_label` — KEV called out, EPSS percentile shown) plus an
explicit "ужесточено: KEV/EPSS, базовое Nд" note next to the shortened SLA. A KEV
row is also flagged in-list (critical-colour title + tooltip). No column-contract
change; cold cache / non-CVE findings render exactly as before. The LAN web
console (`remote/web_app._findings_list`) was reordered to match — threat-annotate
before SLA-annotate — so its `/findings` SLA is tightened for KEV too.

### Follow-up — EPSS daily-CSV bulk ingestion (CLOSED 2026-06-28)

Opt-in alternative EPSS source: instead of the per-CVE API, pull FIRST's full
daily dataset as one gzipped CSV. `core/threat_feed.py` adds `parse_epss_csv`
(pure; skips the `#`-comment + header lines) and `fetch_epss_csv` (one download;
`_get_text` gunzips transparently via the gzip magic number, so no separate bytes
seam). `threat_intel.enrich_cves(..., epss_csv=True, epss_csv_get=...)` fetches the
CSV once and picks the wanted CVEs from it; **only the wanted CVEs are persisted**
(identical cache footprint), and a CSV outage **falls back to the per-CVE API** so
EPSS never silently drops. Wired as an opt-in sub-flag `threat_epss_bulk`
(off by default) through `CollectionRunner` (ctor + `configure` + `_phase_threat`),
`monitor` opts, and a GUI sub-checkbox under the KEV/EPSS option. Default path
(per-CVE) unchanged.

### Deferred (not blockers)

*(KEV/EPSS epic fully closed across all surfaces.)*

---

## EPIC FUTURE — Mission Center / Authorized Pentest Multitool

> Strategic next layer (after KEV/EPSS): turn the mature ASM/CSM + Client-Safe
> Workbench into an operator-facing **Mission Center** — an authorized,
> evidence-first, client-safe pentest multitool. Built strictly on the existing
> machinery (Audit Runs / FindingsStore / Scope / ROE), never a second store.

### M1 — Mission core contract (CLOSED 2026-06-28)

A deterministic, offline **core contract** for a "mission" — the envelope that
ties an authorized objective to the existing client-safe machinery — modelled on
`core/audit_workflow.py` (pure payload, no state, no I/O, no FindingsStore
writes, no network/subprocess).

- **`core/pentest_mission.py`** (new, pure): a mission dict carries `mission_id`
  (stable sha1 of project|objective), `project`, `objective`, fixed
  `profile=client_safe`, optional scenario `template`, a normalized `roe` (the
  **single source of truth that already embeds scope** — no separate scope
  field), client-safe `allowed_actions`, `status`, `report_orientation`
  (`evidence_first`), and `linked_audit_run_ids` / `linked_finding_ids`. API:
  `create_mission`, `normalize_mission` (idempotent canonical form),
  `validate_mission`, `advance_mission_status`, `link_audit_run`, `link_finding`,
  `mission_to_json`.
- **Status lifecycle** (deterministic state machine): `draft → {ready, archived}`,
  `ready → {running, draft, archived}`, `running → {completed, failed, archived}`,
  `completed → {archived}`, `failed → {ready, archived}`, `archived` terminal;
  moving to `ready` requires a valid mission.
- **Guardrails reused, not re-implemented**: ROE via `core/audit_scope`
  (`normalize_roe`/`validate_roe`/`apply_roe_template`), scenario via
  `core/audit_templates` (`get_template`), and every `allowed_actions` entry is
  gated by `core/action_policy` — so exploit / bruteforce / stealth / auto-login /
  auth-bypass / persistence are forbidden **by class**, not by name.
- **`schemas/asa_pentest_mission.schema.json`** (new) + a one-line
  `asa_pentest_mission` alias in `core/audit_schema.SCHEMA_ALIASES`;
  `mission_to_json` validates the canonical export against it.
- Tests: `tests/test_pentest_mission.py` (offline/headless): shape, normalize
  idempotence, forbidden-action-class rejection, ROE propagation, the status
  state machine, linking de-dup/purity, and schema-validated export.

**Decisions (M1):** D1 pure-contract only — **no** MissionStore/SQLite, GUI, web
or timeline (deferred to M2+); D2 the transition map above; D3 scope lives inside
ROE (SSOT); D4 `link_finding` stores a reference only (no FindingsStore existence
check in M1); D5 module name `core/pentest_mission.py`.

### M2 — MissionStore persistence + project bundle export (CLOSED 2026-06-28)

Persist missions and carry them in the portable project bundle, with **no second
findings/asset/timeline source**:

- **`core/mission_store.py`** (new): `MissionStore(SQLiteStore)` mirroring
  `AuditRunStore` but **single-table** (a mission has no event log in the M1
  contract) — a `missions` table (`id/project/profile/status/payload/created_at/
  updated_at`). `save_mission` normalizes + schema-validates via
  `pentest_mission.mission_to_json` before persisting (idempotent, `created_at`
  preserved); `get_mission`/`list_missions`/`delete_mission`/`export_mission`.
- **`utils/sqlite_store.py`**: project-scoped export/import generalized to accept
  an **events-less** `PROJECT_EXPORT` (`events_table=None`) so a single-table
  store participates in bundles without a phantom events table; the 3-tuple path
  (findings/assets/audit) is unchanged.
- **`core/project_io.py`**: bundle gains `missions.json` (mirrors
  `audit_runs.json`) + a `missions` count. `FORMAT_VERSION` stays **1** —
  additive: an older bundle without `missions.json` imports cleanly (0 missions).
- Tests: `tests/test_mission_store.py` (CRUD, idempotent save, schema-validated
  export, events-less project slice), `tests/test_project_io.py` (mission
  round-trip + legacy-bundle tolerance), `tests/conftest.py` isolates `missions.db`.

**Decisions (M2):** D1 single-table store (no events); D2 generalize the base for
events-less `PROJECT_EXPORT` (not a phantom table, not duplicated export logic);
D3 `FORMAT_VERSION` stays 1; D4 columns mirror audit (`+profile`, always
client_safe); D5 GUI Overview Export/Import untouched (summary gains an additive
`missions` key).

### M3 — Operator read/parity surfaces (CLOSED 2026-06-29)

Thin operator-facing surfaces over the persisted missions, with **no new store or
state** — every mutation flows through the pure `pentest_mission` contract and
`MissionStore.save_mission`:

- **`gui/tab_missions.py`** (new, `MissionsTabMixin`, modeled on
  `tab_audit_runs`): project selector → missions table (`MissionStore.list_missions`)
  + detail panel (objective / ROE / allowed_actions / linked runs+findings).
  **View + status-advance** — a combo of legal targets from
  `pentest_mission.MISSION_TRANSITIONS`, advanced via `advance_mission_status` →
  `save_mission`. **Add-links selectors** — attach an existing audit run / finding
  via `link_audit_run` / `link_finding` → `save_mission`. All blocking work via
  `_run_async`/`_set_busy`; lazy-loaded through `_missions_widget` in
  `tab_history._on_tab_changed`. Registered in `plugin_manager.BUILTIN_TABS` +
  `main_window.py` (30 tabs).
- **`remote/web_app.py`**: read-parity `_missions_list`/`_mission_view` +
  `/missions`, `/missions/{id}` (404 on unknown) — mirrors `/audit-runs`.
- **`core/timeline.py`**: `build_events(..., missions=)` derives `mission_created`
  (from `created_at`) and one status event (from `updated_at`, when past `draft`)
  on read, section `missions` — **no second table**; `build_timeline` loads
  `MissionStore().list_missions(slug)` best-effort.
- Tests: `tests/test_missions_tab.py` (build/register/query/advance/link),
  `tests/test_web_missions.py` (list/view/404 + TestClient), mission cases added
  to `tests/test_timeline.py`; `tests/gui_test_helpers.py` gains `MissionsHost`.

**Decisions (M3, locked):** D1 GUI depth = view + status-advance (no in-GUI
create form — creation stays in the core/store layer); D2 surfaces = web
read-parity **and** timeline events; D3 linking = add-links selectors (attach
existing runs/findings). No second findings/asset/timeline source.

### M4 — Mission execution (CLOSED 2026-06-29)

Run an authorized mission as a concrete, evidence-first **Audit Run** — turning
the mission envelope into evidence — with **no second store** (the run lands in
`AuditRunStore`, linked back via the pure `link_audit_run` contract):

- **`core/audit_runner.py`** (new): the audit-run orchestration extracted from
  the GUI's inline `tab_audit_runs._query_audit_run` into one reusable seam —
  `build_audit_run(project, *, run_id, roe, checks, template, evidence, fetcher)`
  → `{project, run, rows, saved}`, plus helpers (`target_from_roe`,
  `audit_candidate`, `build_audit_rows`, `rollup`, `rows_from_run`,
  `record_audit_events`). The Audit Runs tab is now a thin delegator (its
  static-method surface preserved for backward-compat/tests).
- **`core/mission_runner.py`** (new): `run_mission(mission, *, now, run_id,
  evidence, fetcher)` — validates the mission (ROE + client-safe actions),
  requires `ready`, advances `ready → running` (persisted), builds + saves the
  audit run via `audit_runner` (safe checks = `allowed_actions ∩
  audit_checks.SAFE_CHECKS`; ROE-gated; no network unless a `fetcher` is
  injected), links the run and advances `running → completed`. On orchestration
  error the mission is persisted `failed` and the original error re-raised (a
  save failure never masks it).
- **Surfaces:** GUI "Run mission" button on the Missions tab (enabled only for a
  `ready` mission); web `POST /missions/{id}/run` — a synchronous per-resource
  mutation like `/findings/{id}/status` (bounded + offline), **not** the
  named-phase JOBS registry; 404 unknown / 400 not-ready.
- Tests: `tests/test_mission_runner.py` (complete/link, ready-gate, fail+reraise,
  allowed-actions gating), plus GUI run-button cases in
  `tests/test_missions_tab.py` and web run cases in `tests/test_web_missions.py`;
  `core/audit_runner` is exercised through the Audit Runs delegators +
  `mission_runner`.

**Decisions (M4, locked):** D1 extract the orchestration to `core/audit_runner`
and share it (no duplication; GUI becomes a thin caller); D2 surfaces = GUI Run
button **and** web execution endpoint; D3 `completed` if orchestration finishes
(any finding count), `failed` only on exception; D4 offline-safe default (no
fetcher → probe is a no-op). No second findings/asset/timeline source.

### M5 — Mission report (CLOSED 2026-06-29)

The operator's evidence-first takeaway: aggregate a mission with the evidence it
produced, as a **view** over the existing stores (no second source):

- **`core/mission_report.py`** (new): `build_mission_report(mission, *,
  audit_store, findings_store)` assembles a canonical report dict — the envelope
  (objective / ROE / allowed_actions / status / report_orientation), the linked
  audit runs (each contributing `client_findings` / `review_findings` /
  `audit_summary`, reused verbatim from `core.audit_report`; a missing run is
  flagged, never faked), an appendix of explicitly linked findings (resolved via
  `FindingsStore.get`; stale ids kept as stubs), and a summary. Pure
  deterministic renderers `render_json` (sort_keys), `render_markdown` (Linked
  Audit Runs + Linked Findings appendix sections), `render_html` (escaped +
  `markdown-sha`, mirroring `audit_report`).
- **Surfaces:** GUI Export JSON / MD / HTML buttons on the Missions tab (enabled
  for the selected mission; rendered via `_render_mission_report`); web read-only
  `GET /missions/{id}/report` (JSON) + `/missions/{id}/report.md` (markdown; 404
  unknown).
- Tests: `tests/test_mission_report.py` (aggregation, stale-link honesty,
  deterministic JSON, MD/HTML sections), plus GUI export cases in
  `tests/test_missions_tab.py` and web report cases in
  `tests/test_web_missions.py`.

**Decisions (M5, locked):** D1 content = linked runs' evidence + an appendix of
explicitly linked findings; D2 surfaces = GUI export (JSON/MD/HTML) **and** web
(MD + JSON); D3 no schema — a derived report view, not a stored contract; the
assembler reads stores, the renderers stay pure. No second findings/asset/
timeline source.

### M6 — Mission creation UI (CLOSED 2026-06-29)

Let an operator create a mission from the surfaces (the gap deferred at M3/M5) —
reusing the M1 contract, no new core:

- **GUI** (`gui/tab_missions.py`): a "Create mission (client-safe)" panel on the
  Missions tab — project + objective fields, a scenario combo
  (`audit_templates.list_templates`), ROE controls (allowed domains / active /
  passive / rate, mirroring the Audit Runs tab) and `allowed_actions` checkboxes
  drawn from `audit_checks.SAFE_CHECKS` (client-safe actions only). The worker
  `_do_create_mission` calls `pentest_mission.create_mission` →
  `validate_mission` (client-safe + ROE gate) → `MissionStore.save_mission`,
  then refreshes and auto-selects the created project.
- **Web** (`remote/web_app.py`): `POST /missions` (`MissionRequest`:
  project/objective/template/roe/allowed_actions) → `_mission_create` → 200
  `{mission_id, status}`; 400 on an invalid mission (e.g. a non-client-safe
  action).
- Tests: GUI create cases in `tests/test_missions_tab.py` (persist, reject
  non-client-safe action, panel builds the SAFE_CHECKS checkboxes) and web cases
  in `tests/test_web_missions.py` (`_mission_create` helper + `POST /missions`
  200/400).

**Decisions (M6, locked):** D1 surfaces = GUI create panel **and** web `POST
/missions`; D2 the client-safe gate is `validate_mission` *before* save (the
schema validates structure/enums, not action policy); D3 creation reuses the M1
contract — no new core module. No second findings/asset/timeline source.

### M7 — Mission overview/dashboard (CLOSED 2026-06-29)

Portfolio visibility now that the lifecycle is complete — a derive-on-read view,
no new state:

- **`core/mission_overview.py`** (new): `build_mission_overview(*, mission_store,
  audit_store, project)` → `{total, counts: {status: n}, client_facing,
  missions: [row]}`. Per mission it resolves the most-recently-updated linked
  Audit Run and its client-facing finding count (via
  `core.audit_report.client_findings`); missing runs are skipped. A view over
  `MissionStore` + `AuditRunStore`, never a second source.
- **GUI** (`gui/tab_overview.py`): a "Миссии (Mission Center)" card on the
  Overview tab — stat cards (total / ready / running / completed / failed /
  client-facing) + a "last mission" line. Woven into the existing
  `_query_overview` worker (best-effort — the portfolio still renders if missions
  fail) and `_populate_overview_missions`.
- **Web** (`remote/web_app.py`): read-only `GET /missions/overview` (the literal
  route is declared before `/missions/{id}` so it resolves first).
- Tests: `tests/test_mission_overview.py` (counts, last-run outcome, project
  scope, empty), GUI cards in `tests/test_overview_tab.py`, web in
  `tests/test_web_missions.py`.

**Decisions (M7, locked):** D1 a derive-on-read view (no cadence/no new state);
D2 surfaces = Overview tab card **and** web `GET /missions/overview`; D3 last-run
outcome via `audit_report.client_findings` over the latest linked run. No second
findings/asset/timeline source.

### M8 — Timeline run events (CLOSED 2026-06-29)

Deepen the timeline with mission *execution* events, completing the M4 story —
derive-on-read, no new state and no surface changes:

- **`core/timeline.py`**: `build_events` gains a `mission_runs` parameter (a list
  of already-resolved `{mission_id, objective, run_id, status, created_at,
  updated_at}` rows). Each yields a `mission_run_started` event (from the run's
  `created_at`) and, when terminal, a `mission_run_completed` /
  `mission_run_failed` event (from `updated_at`; failed → medium), in the
  `missions` section — complementing the M3 mission-status events (distinct
  type/title, so dedup keeps both). `build_timeline` assembles `mission_runs` by
  resolving each mission's `linked_audit_run_ids` against the already-loaded
  `audit_runs`, so `build_events` stays a pure shaper (no store lookups).
- **Surfaces:** none changed — the `missions` section already renders generically
  in the Timeline tab and web `/timeline` (since M3).
- Tests: `tests/test_timeline.py` — a pure `build_events(mission_runs=...)` case
  and a `build_timeline` integration (execute a mission → started + completed
  events appear).

**Decisions (M8, locked):** D1 derive-on-read, no new state; D2 `build_timeline`
resolves linked runs so `build_events` stays pure; D3 run events live in the
`missions` section alongside (not replacing) the mission-status events. No second
findings/asset/timeline source.

### M9 — Recurring scheduling (CLOSED 2026-06-29)

Re-run an authorized mission on a cadence, reusing the monitor's cadence
primitives — never a second scheduler:

- **Recurring model (key decision):** a scheduled tick does **not** drive the
  one-shot mission status machine (`ready → running → completed`, which has no
  `completed → ready`). Instead `mission_schedule.run_mission_audit` builds the
  mission's audit run via `audit_runner.build_audit_run` (checks =
  `allowed_actions ∩ SAFE_CHECKS`, ROE-gated) and links it (`link_audit_run` →
  `save_mission`, status preserved) — the status-neutral counterpart of
  `mission_runner.run_mission`.
- **State:** a new `schedule` JSON column on the `missions` table (`MissionStore`
  SCHEMA_VERSION 1→2 via the idempotent `_add_column`; `JSON_FIELDS += schedule`),
  kept **separate from the canonical `payload`** so the M1 contract stays pure;
  `save_mission` never overwrites it. MissionStore gains `set_schedule` /
  `get_schedule` / `list_scheduled`.
- **`core/mission_schedule.py`** (new): `make_mission_schedule` /
  `set_mission_schedule` / `disable_mission_schedule` (reuse
  `monitor.compute_next_run`), and `run_due_missions(*, store, now, run)` — walks
  `list_scheduled`, runs enabled+due missions (`monitor.is_due`), advances
  `last_run` / `next_run` / `last_status`; a single mission's failure is recorded,
  never aborts the sweep.
- **Surfaces:** GUI on the Missions tab — interval combo + Enable/Disable schedule
  + "Run due now", schedule shown in the detail; web `POST
  /missions/{id}/schedule` (`ScheduleRequest`; 404/400) + `POST /missions/run-due`.
- Tests: `tests/test_mission_schedule.py` (roundtrip, bad interval, due/enabled
  filtering, failure recording, status-neutral run) + GUI/web cases.

**Decisions (M9, locked):** D1 periodic run with **no status churn** (recurring
execution stays off the one-shot lifecycle); D2 standalone tick (`run_due_missions`)
surfaced by a GUI button + web `POST /missions/run-due` — an OS-level/cron
auto-tick is a deferred follow-up; D3 schedule state is a `missions` column,
separate from the payload. No second findings/asset/timeline source.

### M10 — Scheduling auto-tick (CLOSED 2026-06-29)

Completes M9's deferred follow-up: due missions run automatically on the monitor
tick, wired at the **driver** level so the monitor engine stays decoupled from
missions:

- **`core/monitor.py`**: `MonitorScheduler` gains a generic `extra_tick(now)`
  callback, run after the project sweep on every `tick()` (a failure there is
  reported via `on_event`, never sinks the loop); `monitor.py` never imports the
  mission layer. `format_event` renders a `mission_run` line (shared by the web
  feed + in-app indicator).
- **`core/mission_schedule.py`**: `run_due_missions` gains `on_event=`, emitting a
  `{'type': 'mission_run', 'slug': project, mission_id, run_id, status}` event per
  run.
- **Drivers inject the tick:** the in-app `MonitorRunnerMixin._tick_due_missions`
  (runs on the daemon thread, emits marshalled to the GUI thread by the existing
  bridge signal) is passed as `extra_tick`; `monitor_cli` `run` also sweeps due
  missions (`cmd_run_missions`), `watch` passes `extra_tick`, and `_print_event`
  renders `mission_run`. Opt-in like project monitoring (`monitor_autostart`); a
  mission runs only when its schedule is enabled.
- Tests: `tests/test_monitor.py` (extra_tick runs + failure reported +
  format_event), `tests/test_mission_schedule.py` (on_event emit),
  `tests/test_monitor_cli.py` (`cmd_run_missions`).

**Decisions (M10, locked):** D1 wire at the driver level via a generic
`extra_tick` — the monitor engine stays decoupled (no mission import); D2 reuse
the existing event bridge / shared `format_event` so mission runs surface like
project monitors; D3 opt-in (only enabled schedules run). No second
findings/asset/timeline source.

### M11 — Link integrity (CLOSED 2026-06-29) — closes M1 D4

Validate mission links against the stores **without** breaking the M1 invariant
that `pentest_mission` is pure:

- The pure `pentest_mission.link_audit_run` / `link_finding` are untouched (still
  link without any I/O — guarded by `test_pentest_mission_link_stays_pure`).
- **`core/mission_links.py`** (new): the store-aware, opt-in layer the surfaces
  use — `link_audit_run_checked(mission, run_id, *, audit_store)` /
  `link_finding_checked(mission, finding_id, *, findings_store)` validate the id
  exists (raise `ValueError` otherwise) before delegating to the pure linker; and
  `resolve_links(mission, *, audit_store, findings_store)` →
  `{present_runs, stale_runs, present_findings, stale_findings}` (a stale id
  references a since-deleted run/finding — named, never silently dropped).
- **GUI** (`gui/tab_missions.py`): the add-links handlers now call the checked
  variants (so an id deleted between populate and click is refused); `_query_missions`
  annotates each mission with its `_links` partition (resolved off-thread) and the
  detail panel flags "⚠ Stale links". Web/report already surface stale references
  (M5's `build_mission_report` marks missing runs/findings) — no new endpoint.
- Tests: `tests/test_mission_links.py` (checked accept/reject, present/stale
  partition, purity invariant) + GUI cases (reject nonexistent, stale flagged).

**Decisions (M11, locked):** D1 keep `pentest_mission` pure — the existence check
is an opt-in surface layer (`mission_links`), not the contract; D2 stale links are
named/flagged, never auto-removed (cleanup stays the operator's call); D3 reuse
the M5 report for the web/report stale surface (no new endpoint). No second
findings/asset/timeline source.

### M12 — Demo seed (CLOSED 2026-06-29)

Make the whole M1–M11 Mission Center visible in the demo workspace
(release-readiness):

- **`demo_seed.py`**: a new `_seed_missions(missions_store, slug, audit_run_id,
  finding_id)` seeds three missions on the richest (first) project — (1) a
  `ready` mission with a weekly schedule (`set_mission_schedule`), so the schedule
  controls / auto-tick are visible; (2) an executed mission
  (`draft→ready→running→completed`) linking the project's existing demo audit run
  + a real finding, so the report / overview last-run outcome populate; (3) a
  legacy mission carrying a stale link (`audit-demo-removed`) to show the M11
  flag. `seed()` builds `MissionStore(pm.get_db_path('missions.db'))`, captures the
  run id from `_seed_audit_run`, calls `_seed_missions` once, and adds a
  `missions` count to the summary/printout.
- Tests: `tests/test_demo_seed.py` — the summary count + a check that one mission
  is scheduled, one executed with linked run+finding, and one carries a stale link.

**Decisions (M12, locked):** D1 seed on the first project only (richest, has an
audit run); D2 cover all the headline states (scheduled / executed / stale) in a
few missions; D3 reuse the existing contract + schedule + link APIs — no demo-only
code paths. No second findings/asset/timeline source.

### M13 — Mission CSV export (CLOSED 2026-06-29)

Surface parity with the findings / portfolio CSV exports:

- **`core/report_export.py`**: a new `missions_csv(overview)` over the shared
  `_rows_to_csv` + `_MISSIONS_COLUMNS` (mission_id / project / objective / status /
  last_run_id / last_run_status / client_facing / updated_at). It accepts either
  the `mission_overview.build_mission_overview()` dict (`{'missions': [...]}`) or a
  bare row list (same shape as `portfolio_csv`), preserving the exporter purity
  invariant (a string from already-loaded rows, no I/O).
- **GUI** (`gui/tab_missions.py`): an "Export CSV" button in the Missions tab
  control row (`_export_missions_csv` → `_missions_csv_text(project)` builds the
  overview for the current project and renders it).
- **Web** (`remote/web_app.py`): `GET /missions.csv` (`_missions_csv`, media type
  `text/csv`), mirroring `/findings.sarif` and `/report.md`.
- Tests: `tests/test_report_export.py` (header/row from overview dict + bare list +
  empty), GUI in `tests/test_missions_tab.py`, web helper + endpoint in
  `tests/test_web_missions.py`.

**Decisions (M13, locked):** D1 reuse the shared `_rows_to_csv` exporter (no new
CSV machinery); D2 the rows are the `mission_overview` rows (one source for the
card + the export); D3 mirror the existing CSV surface conventions (GUI button +
`GET /missions.csv`). No second findings/asset/timeline source.

### M14 — Stale-link cleanup (CLOSED 2026-06-29)

Operator-driven cleanup that completes the M11 link-integrity story:

- **`core/mission_links.py`**: a new `prune_stale_links(mission, *, audit_store,
  findings_store)` that, over `resolve_links`, rebuilds the mission keeping only
  the present run/finding links — via the pure `pentest_mission.normalize_mission`
  (input never mutated; a mission with no stale links comes back unchanged).
  Returns `{mission, removed_runs, removed_findings}`. `pentest_mission` stays
  pure — pruning lives in the opt-in surface layer.
- **GUI** (`gui/tab_missions.py`): a "Remove stale" button in the link row,
  enabled only when the selected mission has stale links (from its `_links`
  partition); `_do_prune_links` → `save_mission` → refresh.
- **Web** (`remote/web_app.py`): `POST /missions/{id}/links/prune`
  (`_mission_prune_links`; 404 unknown / 400 error; the push carries the removed
  count).
- Tests: `tests/test_mission_links.py` (prune keeps present / drops stale,
  no-op when all present, input purity) + GUI/web cases.

**Decisions (M14, locked):** D1 prune is opt-in and operator-driven (never
automatic); D2 keep `pentest_mission` pure — the rebuild is in `mission_links`;
D3 surfaces = GUI button + web `POST .../links/prune`. No second
findings/asset/timeline source.

### M15 — Mission run trend (CLOSED 2026-06-29)

The last grounded analytics item — a per-mission run history, derive-on-read:

- **`core/mission_overview.py`**: a new `mission_run_trend(mission, *,
  audit_store)` → one row per linked audit run `{run_id, at, status,
  client_facing}` (client-facing count via `audit_report.client_findings`),
  time-ordered; missing runs are skipped, never faked. No new state.
- **GUI** (`gui/tab_missions.py`): `_query_missions` annotates each mission with
  its `_trend` (off-thread, shared audit store); the detail panel shows a "Run
  history (client-facing)" list (last 5 runs).
- **Web** (`remote/web_app.py`): read-only `GET /missions/{id}/runs`
  (`_mission_runs`; 404 unknown).
- Tests: `tests/test_mission_overview.py` (time-ordered trend + client-facing
  counts, missing runs skipped) + GUI/web cases.

**Decisions (M15, locked):** D1 derive-on-read (no new state/store); D2 reuse
`audit_report.client_findings` for the per-run count; D3 surfaces = GUI detail
list + web `GET /missions/{id}/runs`. No second findings/asset/timeline source.

This closes the planned Mission Center arc (M1–M15). Further milestones would be
scope creep against the project's "value/stability over feature count" priority.

---

### Tool Adapter Contract Foundation (CLOSED 2026-06-30)

A pure/offline **contract layer** for later plugging external recon/audit tools
(nuclei, nmap, katana, httpx, …) into a pentest mission — **without running them**,
no network, and **no store writes**:

- **`core/tool_adapter.py`** (new): `ToolCapability` (+ a registry of client-safe
  tools), `ToolRunRequest`, `ToolRunResult`, `ToolFinding`, `ToolAsset`;
  `normalize_tool_name`, `build_tool_request`, `evaluate_tool_allowed_for_mission`,
  `map_tool_result_to_findings`, `tool_result_to_json`. Deterministic canonical
  payloads; unknown/empty tool rejected; a request binds the mission's
  id/project/target/profile/**ROE** (the scope SSOT). `evaluate_tool_allowed_for_mission`
  adds **no policy of its own** — it maps the tool to its action class and defers
  to the existing `scope_policy.evaluate_scope_policy` (→ `action_policy` +
  `scope_guard`), passing the mission's ROE as scope: forbidden actions blocked,
  passive-default blocks active, active in-scope safe action allowed only when the
  ROE sets `active_scan_enabled` and `passive_only=False`. No
  exploit/bruteforce/stealth/payload. `map_tool_result_to_findings` normalizes
  already-parsed output into DTOs and **never writes a store**.
- **`schemas/asa_tool_run.schema.json`** (new) + `asa_tool_run` alias in
  `core/audit_schema.SCHEMA_ALIASES`; `tool_result_to_json` exports a
  schema-valid payload.
- Tests: `tests/test_tool_adapter.py` (canonical determinism, unknown/empty
  rejection, request identity/ROE binding, policy reuse, forbidden/passive/active
  gating, schema-valid export, parser→DTO mapping with no store writes).

**Decisions (locked):** contract layer only — **no external tool execution**, no
network, no store writes, no risk-verdict change; the gate reuses the existing
action/scope policy rather than introducing its own; the mission's ROE is the
scope source (target derived from `allowed_domains` when not given explicitly).

---

### Per-Tool Offline Parsers (CLOSED 2026-06-30)

The safe layer above the Tool Adapter Contract: turn a tool's *already-captured*
evidence into the generic `{findings, assets}` shape the M3 adapter consumes —
still **no tool execution, no network, no store writes**:

- **`core/tool_parsers.py`** (new): a parser per M3 tool (keyed by
  `tool_adapter.TOOL_CAPABILITIES` name) — `parse_header_audit`,
  `parse_cookie_audit`, `parse_source_map_finder` (detection **reused** from
  `core.audit_checks`, not re-implemented) and `parse_safe_active_prober` (the
  asset/enumeration parser). `parse_tool_output(tool, evidence)` dispatches and
  returns the generic shape ready for `map_tool_result_to_findings`; an
  empty/unknown tool, or a registered tool with no parser yet, is rejected
  (`has_parser` reports availability). Scope/ROE gating is **not** the parser's
  job — that already happened in `evaluate_tool_allowed_for_mission`; a parser
  runs its reused check under a permissive in-scope ROE only to bypass the
  check's own gate.
- Input is **structured captured evidence** (`{headers}` / `{cookies}` /
  `{urls}` / `{urls, hosts, subdomains}`) — offline, deterministic, fully
  testable; no version-coupling to real binaries.
- Tests: `tests/test_tool_parsers.py` (each parser reuses audit_checks / emits
  assets, dispatch rejection for empty/unknown/unparsed tools, parser → M3
  `map_tool_result_to_findings` integration, determinism).

**Decisions (locked):** parsers consume captured evidence (not live runs / not
raw binary stdout); reuse `audit_checks` for header/cookie/source-map (no
duplication); a focused first set (3 reuse-backed + 1 asset parser) with an
additive registry for the rest; no store writes, no network, no new dependencies.

**Follow-up (2026-06-30): all 8 registry tools covered.** Added parsers for the
remaining tools — `dependency_auditor` (reuse `core.dependency_audit.audit`),
`iac_config_auditor` (reuse `core.iac_scanner.scan_path`; the one parser whose
evidence is a local path — IaC analysis is inherently local-file, reads only the
operator-provided path, no network/store), `graphql_introspector` and `tls_audit`
(small pure detection over captured introspection / TLS evidence; no live
handshake or query). Every entry in `tool_adapter.TOOL_CAPABILITIES` now has a
parser; the pipeline's `skipped` status now only applies to custom
(non-registry) capabilities.

---

### Offline Tool-Evidence Pipeline (CLOSED 2026-06-30)

The compositional capstone of the tool layer: tie the M3 gate + the parsers into
one store-free call — still **no tool execution, no network, no store writes**:

- **`core/tool_pipeline.py`** (new): `assemble_tool_run(mission, tool, evidence,
  *, target)` builds the M3 request, gates the tool with
  `evaluate_tool_allowed_for_mission`, and — only if allowed — parses the
  already-captured evidence (`tool_parsers.parse_tool_output`) and normalizes it
  via `map_tool_result_to_findings`. Status reflects the path: `blocked` (policy/
  ROE denied — evidence never parsed), `skipped` (allowed but no parser yet), or
  `completed`. `evidence` is data the caller captured offline; nothing here runs
  a tool, opens a socket, or writes a store.
- Tests: `tests/test_tool_pipeline.py` (allowed→completed with findings/assets,
  blocked→empty, allowed-no-parser→skipped, asset parser through the pipeline,
  determinism).

**Decisions (locked):** composition only — reuse the M3 gate / parsers / mapper,
add no detection or policy logic; map the three outcomes onto the existing
`RESULT_STATUSES` (`blocked`/`skipped`/`completed`); evidence is captured input,
never fetched. No store writes, no network, no new dependencies.

---

### Tool→Canonical Finding/Asset Bridge (CLOSED 2026-06-30)

Connect the tool layer to the platform's finding model — still **no store
writes**:

- **`core/tool_ingest.py`** (new): `tool_result_to_findings(result)` maps a
  `ToolRunResult`'s findings onto the platform's identity-bearing
  `core.findings_adapter.Finding` DTOs via `from_raw` (so a tool finding gets the
  same fingerprint identity / category / severity normalization as a scanner
  finding; category mapped from the tool's action, default `vuln`; the tool's
  string evidence refs are carried in `detail` since they are not manifest
  artifacts). `tool_result_to_assets(result)` maps assets onto
  `core.asset_adapter.Asset` DTOs (the discovering tool in `attrs['source']`).
  Pure: writes to **no store**, no network — persistence stays an explicit,
  separate step the caller performs later. A `blocked`/`skipped`/empty result
  yields empty lists.
- Tests: `tests/test_tool_ingest.py` (canonical identity + category, dependency→
  `vuln`, asset mapping with source, blocked→empty, determinism/purity, type
  guards, empty result).

**Decisions (locked):** pure converter only — reuse `findings_adapter.from_raw` +
`asset_adapter.Asset` for canonical identity, add no new finding/asset model;
**no store writes** (ingestion into FindingsStore/AssetStore is a later, explicit
step, not this layer); no network, no new dependencies.

---

### Tool-Run Report Renderer (CLOSED 2026-06-30)

The presentation layer of the tool stack — pure, offline, **no store writes**:

- **`core/tool_report.py`** (new): `render_json` / `render_markdown` /
  `render_html` over a `ToolRunResult`'s canonical, schema-shaped payload
  (`tool_result_to_json`). Markdown carries the envelope (tool / action / mission
  / target / status + counts) and findings/assets tables; HTML is escaped and
  ends with a `markdown-sha` comment — mirroring `core.audit_report` /
  `mission_report`. A view, not storage: reads an already-assembled result and
  returns a string; deterministic, no network, no new dependencies.
- Tests: `tests/test_tool_report.py` (JSON == canonical payload + deterministic,
  MD header/tables + empty case, HTML escaped + markdown-sha, type guards).

**Decisions (locked):** presentation only — render the existing canonical payload,
add no detection / no policy / no new model; deterministic; no store writes, no
network, no new dependencies.

---

### Gated Tool-Run Ingestion (CLOSED 2026-06-30)

The **first store-writing step** of the tool layer — gated and idempotent, into
the *existing* stores (no second store):

- **`core/tool_ingest_store.py`** (new): `ingest_tool_run(result, project,
  scan_id, *, findings_store, asset_store)` persists a **completed**,
  already-authorized `ToolRunResult`'s findings/assets — via the canonical bridge
  (`tool_ingest`) — into `FindingsStore.upsert` (per finding) and
  `AssetStore.sync`. **Gated:** only `status == "completed"` writes; `blocked` /
  `skipped` / any other status is a no-op (authorization was decided upstream by
  `evaluate_tool_allowed_for_mission`; this never runs a tool, opens a socket, or
  re-checks policy). **Idempotent:** `upsert`/`sync` are identity-keyed, so
  re-ingesting the same result never duplicates. Returns `{status, written,
  findings, assets}`. No network, no new dependencies.
- Tests: `tests/test_tool_ingest_store.py` (completed persists findings+assets,
  idempotent re-ingest, blocked→no-op, skipped→no-op, type/project guards).

**Decisions (locked):** reuse the existing FindingsStore/AssetStore (no second
store) + the bridge DTOs; write **only** on `completed`; idempotent; the result is
already authorized (no policy re-check here) — and a tool is still never executed
(`evidence` was captured offline upstream). No network, no new dependencies.

This is the first layer to cross the no-store boundary; the pure tool stack
(contract → parsers → pipeline → bridge → report) stays unchanged beneath it.

---

### End-to-End Tool-Run Orchestrator (CLOSED 2026-06-30)

The **capstone** of the tool layer: tie the two halves of the stack — the
store-free pipeline and the gated ingestion — into one mission-scoped call.

- **`core/tool_runner.py`** (new): `run_tool_for_mission(mission, tool, evidence,
  *, scan_id, project=None, target=None, findings_store=None, asset_store=None)`
  composes `tool_pipeline.assemble_tool_run` (gate → parse captured evidence →
  map) with `tool_ingest_store.ingest_tool_run` (persist a **completed** result's
  findings/assets, gated + idempotent). `project` defaults to the mission's own
  `project`. Returns `{"result": ToolRunResult, "ingest": {status, written,
  findings, assets}}` — the result is the store-free run (render via
  `core.tool_report`), the ingest summary reports what was persisted. A
  `blocked` / `skipped` result flows through unchanged: assemble marks the
  status, ingestion is a no-op (`written` False).
- Mirrors `mission_runner.run_mission` wrapping `audit_runner.build_audit_run` +
  persist. **Pure composition** — no new detection or policy, no second store,
  no network, no new dependencies; a tool is still never executed (`evidence`
  was captured offline upstream).
- Tests: `tests/test_tool_runner.py` (completed persists + returns result,
  project defaults to mission, idempotent re-run, blocked → no-op, skipped →
  no-op).

**Decisions (locked):** the orchestrator only composes the existing two layers —
no new behavior; `project` defaults from the mission; return shape carries both
the renderable result and the ingestion summary. The pure stack and the
ingestion layer stay unchanged beneath it.

**GUI surface (2026-06-30):** the orchestrator is wired into the **Missions tab**
(`gui/tab_missions.py`) as a thin "Run tool (client-safe, evidence-driven)"
panel: a tool combo from `tool_adapter.TOOL_CAPABILITIES` + a JSON evidence
field + "Run tool". The button is gated by ROE (offered for any selected
mission while idle, not the lifecycle status). `_run_mission_tool` parses the
evidence JSON on the GUI thread (bad input fails fast), then the off-thread
`_do_run_mission_tool` calls `run_tool_for_mission` with a synthetic
`scan_id=tool-<name>-<ts>` and reports `status` + ingested finding/asset counts.
Faithful to the layer: the operator supplies already-captured evidence, the tool
is never executed, and a `blocked`/`skipped` run ingests nothing. Tests:
`tests/test_missions_tab.py` (panel builds from registry, enable-on-selection,
bad-JSON rejection, completed→ingested, blocked→not-ingested).

**Web parity (2026-06-30):** `remote/web_app.py` adds `_mission_run_tool` +
`POST /missions/{id}/tools/run` (body `{tool, evidence}`) mirroring the GUI
surface — synthetic `scan_id`, returns `{status, written, findings, assets}`;
404 for an unknown mission, 400 for a missing tool. `blocked`/`skipped` runs
return 200 with `written: false` (a gated outcome, not an error). Tests:
`tests/test_web_missions.py` (helper completed→ingested, blocked→not-ingested,
unknown→not-found, tool-required; TestClient endpoint completed + 404).

**Timeline event (2026-06-30):** a tool run is not persisted as its own entity
(no second store), so the timeline derives a `tool_run` event **on read** from
the ingested items' synthetic scan id. The convention is centralized in
`core/tool_runner.tool_scan_id` / `parse_tool_scan_id` (`tool-<tool>-<unix_ts>`,
now the single source of truth shared by the GUI + web run surfaces, replacing
the duplicated inline string). `timeline._derive_tool_runs` groups the ingested
CREATED finding/asset events by that scan id into one `{tool, scan_id, at,
findings, assets}` row per run (a run that ingested nothing leaves no events →
no row); `build_events` gains a `tool_runs` param emitting one `tool_run` event
(section `tools`, severity info) per row. GUI label added (`tab_timeline`);
no section-based rendering changes (the feed renders generically). Tests:
`tests/test_timeline.py` (event shaping, `_derive_tool_runs` grouping +
non-tool-id exclusion, end-to-end `build_timeline`), `tests/test_tool_runner.py`
(scan-id round-trip + rejection).

**CSV export (2026-06-30):** `build_timeline` now also returns the structured
`tool_runs` rows it derives (additive), so the export has one derivation path.
`report_export.tool_runs_csv(runs)` (columns When/Tool/Findings/Assets/Scan ID;
accepts the full dict or a bare list, like `portfolio_csv`/`missions_csv`)
renders them. Surfaced as an "Export tool runs" button on the Timeline tab
(`gui/tab_timeline.py`, alongside the events CSV) and a `GET /tool-runs.csv`
web endpoint mirroring `/missions.csv`. Tests: `tests/test_report_export.py`
(dict/list/empty), `tests/test_timeline.py` (structured rows returned),
`tests/test_timeline_tab.py` (loaded rows render), `tests/test_web_timeline.py`
(endpoint).

---

### Web Console Auth & Safe Bind (CLOSED 2026-06-30)

The LAN web console (`remote/web_app.py`) gained mutating endpoints (mission run,
tool-run → store ingestion) while still binding `0.0.0.0` with no authentication —
the highest-priority stability/safety gap. Closed safely, offline, no new deps:

- **Safe bind by default.** `resolve_web_console(host=None)` resolves (host, token)
  from `settings.json` `web_console` + env. Default host is **`127.0.0.1`** (not
  reachable from the LAN); a LAN bind is explicit opt-in via
  `web_console.allow_lan` (→ `0.0.0.0`) or an explicit non-loopback `host`.
  `start_server` default host changed `0.0.0.0` → settings-resolved loopback.
- **Token gate.** One app-wide dependency `require_token` (FastAPI
  `dependencies=[Depends(...)]`) — when a token is active, every request outside
  `_PUBLIC_PATHS` (just `/`, the static shell) must present it via
  `Authorization: Bearer` **or** `?token=` (so a browser EventSource/link works),
  constant-time compared (`hmac.compare_digest`). 401 on missing/invalid.
- **No-token rule.** Loopback + no token → open (single-user desktop). A **LAN**
  bind with no configured token **auto-generates** one (`secrets.token_urlsafe`)
  and prints it once → the console is never LAN-reachable unauthenticated. Token
  source: `web_console.token` or `ASA_WEB_TOKEN` env (never logged in full).
- **Dashboard.** A small JS shim attaches the token (localStorage; prompts once
  on a 401) to every `fetch` + the SSE URL.
- **Config:** `web_console: {host, allow_lan, token}` added to
  `core.config.DEFAULT_SETTINGS`.

**Decisions (locked):** D1 default loopback, LAN explicit opt-in; D2 Bearer +
`?token=`, one app-wide dependency; D3 loopback+no-token = open, LAN requires a
token (auto-generated if unset); D4 token in settings.json + `ASA_WEB_TOKEN`;
D5 stdlib `secrets`/`hmac`, no new deps. Tests: `tests/test_web_auth.py`
(host/token resolution, loopback open, LAN auto-token, env override, live gate:
public `/`, 401 without token, Bearer/`?token=` accept, mutating POST gated).

---

### Scan Retention — Phase 1 (CLOSED 2026-06-30)

For Continuous Security Monitoring the scan workspace grows unbounded. Retention
prunes the bulky scan *artifact* directories beyond a keep policy while keeping
the lightweight index — the lowest-risk design (chosen):

- **`core/retention.py`** (new): `plan_retention(project, *, keep_last, keep_days,
  now=None)` — pure planner; the newest scan is always kept, a scan survives if
  within the newest `keep_last` OR newer than `keep_days` days; no policy → keep
  all; an already-pruned entry is never re-listed. `apply_retention(project, plan)`
  deletes only the `scans/<id>/` directory (`shutil.rmtree`) and marks the metadata
  entry `artifacts_pruned` (additive) — the `metadata.json scans[]` index and the
  `history/<id>.json` snapshot stay, so the risk series/trend stay intact, the
  timeline degrades softly (a missing `report.json` is already skipped), and
  FindingsStore rows are never orphaned (`scan_id` is only a label). Idempotent.
  `policy_from_settings()` + `prune_project()` convenience.
- **Config:** `retention: {enabled, keep_last, keep_days}` in `DEFAULT_SETTINGS`,
  **disabled by default** (zero behaviour change).
- **Auto:** `collection_runner` prunes after a Full Collection when
  `retention.enabled` — best-effort, never fails a scan.
- **GUI:** Overview "Prune old scans" button (per selected project, confirms,
  off-thread; index/history kept).
- Tests: `tests/test_retention.py` (keep-last / keep-days / always-keep-newest,
  apply deletes dir + marks index + keeps history, idempotent, series survives),
  `tests/test_overview_tab.py` (prune worker).

**Decisions (locked):** prune artifacts only, keep the index (series intact, no
orphaned findings); disabled by default; opt-in auto-prune after a scan + manual
GUI prune. Phase 2 (full data-root backup) follows.

---

### Full Backup & Restore — Phase 2 (CLOSED 2026-06-30)

A timestamped `.zip` snapshot of the whole app state, restorable. State lives in
two places — the writable **data root** (SQLite stores under `data/`, config JSON
under `configs/`) and the **workspace** (`Projects/<slug>/` under the settings
`output_dir`, usually outside the data root) — so both are captured:

- **`core/backup.py`** (new): `create_backup(dest_zip, *, data_root=None,
  workspace=None)` — every `*.db` is snapshotted via SQLite's **online backup**
  API (consistent even while the app reads it; the stores use WAL; no `-wal`/
  `-shm` sidecars in the archive), every other data-root file is copied verbatim
  under `data_root/…`, and the workspace tree under `workspace/…` (skipped if
  nested inside the data root, to avoid double-capture). A failed online backup
  falls back to a raw copy + a manifest warning. `backup_info(src)` reads the
  manifest; `restore_backup(src, *, data_root=None, workspace=None,
  replace=False)` extracts back onto the target roots, **zip-slip guarded**, and
  **skips existing files unless `replace=True`** (a restore never silently
  clobbers live data). Stdlib only (`zipfile`/`sqlite3`).
- **GUI:** Overview "Backup all…" + "Restore…" buttons (off-thread; restore
  confirms overwrite vs missing-only).
- Tests: `tests/test_backup.py` (captures db/config/workspace, no WAL sidecars,
  manifest, round-trip restores a valid SQLite copy, skip-vs-replace, zip-slip
  guard, nested-workspace not double-captured), `tests/test_overview_tab.py`
  (restore worker error path).

**Decisions (locked):** online backup for DBs (WAL-safe), verbatim copy for the
rest; one archive covers data root + workspace; restore is non-clobbering by
default; stdlib only. Closes the Scan Retention & Backup epic.

---

### GUI Table Pagination (CLOSED 2026-06-30)

The heavy tables loaded every row into the widget at once, freezing the UI on a
large estate/history. Fixed with **UI windowing** (the slow part is populating
the widget, not holding the rows) — the data layer is untouched:

- **`gui/ui_components.TablePaginator`** (new): renders a large, already
  queried/filtered/sorted row list into a `QTableWidget` one page at a time via a
  per-row render callback. A control strip (First/◀/▶/Last + "page X/Y · showing
  a–b of N" + a page-size combo 100/200/500/1000) drives navigation;
  `record_at(table_row)` / `index_at(table_row)` map a table row back to the
  full-list record so selection/detail keep working; `on_page_changed` lets a tab
  clear stale detail. Pure UI — no store/query change.
- **Applied to** the three highest-volume tables: **Findings**, **Assets**,
  **Timeline** (the gap-analysis list). Each keeps its full list for selection +
  CSV export (`_findings_records` / `_assets_records` / `_timeline_events_data`)
  and renders only a page. The remaining ~17 table tabs are a trivial follow-up
  on the same helper.
- Tests: `tests/test_ui_pagination.py` (windowing math, nav, `record_at`
  mapping, page-size change keeps the first visible row, empty, callback),
  `tests/test_findings_tab.py` (250 rows → one page rendered, selection maps to
  the right full-list record across pages).

**Decisions (locked):** UI windowing (not store limit/offset — sorting/filtering/
CSV stay over the full list); reusable paginator; scope this iteration = Findings
+ Assets + Timeline, others follow on the same helper.

---

### Interactive Attack-Path Graph (CLOSED 2026-06-30)

The Attack Paths tab ranked paths as a table + detail; it lacked a visual graph.
**Important:** the requested "cloud classifier", "attack-path engine" and
"attack-surface tab" all already existed (`core/cloud_classifier.py`,
`core/intelligence.build_attack_paths` + `core/correlation.py`,
`gui/tab_attack_paths.py`) — so this added only the genuinely-missing piece (an
interactive graph view) over those engines, **without duplicating** them.

- **`gui/attack_graph_view.py`** (new): `AttackGraphView(QGraphicsView)` renders
  one ranked path record as a deterministic layered node-edge diagram —
  **Entry (вход) → Pivot (транзит) → Targets (цель)** — in a `QGraphicsScene`
  (stdlib Qt only, no graph library). Entry coloured by its finding severity, the
  ranked goal/critical targets highlighted (shared theme palette), target fan-out
  capped at `MAX_TARGETS` with a "+N more" overflow node. Nodes are clickable →
  `node_clicked(node_id, role)`. Pure presentation over an already-loaded record;
  headless-safe; never raises (a malformed record is logged).
- **`gui/tab_attack_paths.py`:** the graph is wired below the ranked table —
  selecting a path renders its chain; clicking a node highlights it in the detail
  panel; reloading clears it. Reuses the existing `load_attack_paths` data + the
  `_run_async` loader (no new data path).
- Tests: `tests/test_attack_graph_view.py` (entry/pivot/target nodes, target cap
  + overflow, empty/malformed clears, click signal, determinism),
  `tests/test_attack_paths_tab.py` (graph mirrors selection, node-click detail,
  reload clears).

**Decisions (locked):** reuse the existing cloud/attack-path/correlation engines —
build only the missing visual graph; layered (not force-directed) layout fits the
fixed 3-stage entry→pivot→target chain and is deterministic/testable; node click
feeds the existing detail panel (no 3-pane restructure).

---

### Finding Assignment & Comments Triage (CLOSED 2026-06-30)

DefectDojo-style triage on top of the existing lifecycle/SLA — **event-sourced**
over `finding_events` (the `REMEDIATION` feature is the exact template), so no
second store and no schema migration:

- **`core/findings_store.py`:** `EVENT_TYPES += 'ASSIGNED', 'COMMENT'`.
  `assign(finding_id, assignee)` / `get_assignee(finding_id)` (latest `ASSIGNED`
  event wins; `''` unassigns) / `assignees(project)` (latest-per-finding map for
  list annotation; cleared dropped). `add_comment(finding_id, text, author='')`
  (append-only `COMMENT` event, note = JSON `{author,text}`) / `comments(
  finding_id)` (thread, oldest first). All validate the finding exists
  (`KeyError`) and route through `_log_event` — full history stays in
  `finding_events`, carried by the project_io bundle automatically.
- **GUI Findings tab:** a "Триаж" row (Assignee field + Назначить, Comment field
  + Добавить) acting on the selected finding via `_run_async`; the detail panel
  shows the current assignee + a readable comment thread (raw `COMMENT` events
  hidden from the generic history to avoid the JSON note). Assignee field
  prefills with the current value.
- **Web parity (`remote/web_app.py`):** `POST /findings/{id}/assign`
  (`{assignee}`), `POST /findings/{id}/comment` (`{text, author?}`),
  `GET /findings/{id}/triage` (assignee + thread); 404 unknown / 400 empty
  comment, mirroring `/findings/{id}/status`.
- Tests: `tests/test_findings_store.py` (assign latest-wins/unassign, assignees
  map, comments order, empty/unknown guards), `tests/test_web_findings.py`
  (helpers + TestClient assign/comment/triage), `tests/test_findings_tab.py`
  (assign/comment workers).

**Decisions (locked):** event-sourced over `finding_events` (no second
store/migration); assignment = latest `ASSIGNED` wins, comments append-only;
surfaced in detail + web (no new findings-table column, per scope choice).

---

### Captured-Scan → Tool-Evidence Bridge (CLOSED 2026-06-30)

Tool runs took operator-pasted evidence JSON; this lets them be driven from data
a scan already captured (passively, offline). **`core/tool_evidence.py`** (new):

- `evidence_from_report(report, tool) -> dict` — maps a loaded scan
  ``report.json`` to the exact evidence shape the matching
  ``core.tool_parsers`` parser consumes (so it feeds straight into
  ``tool_pipeline.assemble_tool_run`` / ``parse_tool_output``). `{}` when the
  tool has no extractor or the report lacks its data; never raises.
  `available_tools(report)` lists what's bridgeable.
- **Additive per-tool extractor registry** (mirrors `tool_parsers.PARSERS`).
  Verified extractors this iteration: **`source_map_finder`** (from
  `recon.data.source_maps[].url`) and **`safe_active_prober`** (from the
  subdomains phase — enumerated results + takeover candidates, deduped). Other
  tools are absent (→ manual evidence) and are purely additive to add later.
- **Pure** dict→dict over an already-loaded report (caller uses
  `project.load_scan_report`); no I/O, network, store writes, or tool execution;
  reuses the report shapes `collection_runner` writes — no new data path.
- Tests: `tests/test_tool_evidence.py` (both extractor shapes, dedup, missing/
  unknown → `{}`, `available_tools`, and a round-trip proving the bridge output
  parses cleanly through `tool_parsers.parse_tool_output`).

**Decisions (locked):** pure report→evidence mapper + additive registry; bridge
only verified report shapes (source_map_finder + safe_active_prober), rest stay
manual; no surface wiring this iteration (Missions/web auto-evidence is an
additive follow-up).

**More extractors (2026-06-30):** added two verified extractors to the registry —
**`header_audit`** (from `recon.data.security_headers` — the security response
headers recon captured; `headers_check` flags the missing ones) and
**`cookie_audit`** (from the cookies phase — `CookieAuditor.audit` rows carry
name/secure/httponly, exactly what `cookie_flags_check` reads). **`dependency_auditor`
is deliberately not bridged**: recon stores only the audit *result*
(`recon.data.dependencies`), not the raw `scripts`/`html` the parser would
re-audit, and those dependency findings are already in FindingsStore via the
vuln phase — bridging would mean persisting raw HTML in `report.json` (scope
creep) for a redundant run. Tests extended (`tests/test_tool_evidence.py`): both
shapes, empty/un-fetched → `{}`, round-trip through `parse_tool_output`,
`available_tools`. Registry now: source_map_finder / safe_active_prober /
header_audit / cookie_audit (additive).

**Surface wiring (2026-06-30):** `tool_evidence.evidence_from_project_scan(project,
tool, *, base=None, scan_id=None)` — the thin I/O loader (mirrors
`timeline.build_timeline`): resolves a project's scan report (latest or given)
via `ProjectStore`/`load_scan_report` and delegates to the pure mapper; `{}` on a
missing project/scan, never raises. **GUI Missions** "Run tool" panel gains an
«Из скана» button — fills the evidence field from the mission's project scan
(off-thread; operator reviews/edits, then Run; the manual flow is untouched).
**Web** `POST /missions/{id}/tools/run` gains `from_scan: bool` (+ optional
`scan_id`): when set and no `evidence` is supplied, evidence is pulled from the
mission's project scan (`base=_REPORT_BASE`) before the run. Tests:
`tests/test_tool_evidence.py` (loader latest/explicit/missing),
`tests/test_missions_tab.py` (fill worker), `tests/test_web_missions.py`
(`from_scan` run pulls scan evidence → completed). No new data path; the run
flow (`run_tool_for_mission`) and the tool-never-executed invariant are unchanged.

---

### e2e / GUI-interaction Tests (CLOSED 2026-07-01)

The GUI suite tested handlers in isolation (`_run_async` stubbed to a no-op); it
did not exercise the real **click → handler → worker → callback → store/UI**
chain. Added a deterministic, headless e2e layer:

- **Harness (`tests/gui_test_helpers.py`):** `_SyncRunMixin` overrides
  `_run_async(work, on_done)` to run the worker **inline** and call the callback
  (the `TaskRunnerMixin` contract, synchronously — no QThread, deterministic) +
  reusable e2e hosts `FindingsE2EHost` / `MissionsE2EHost`. Existing hosts/tests
  untouched.
- **`tests/test_gui_e2e.py`:** genuine button activations (`QAbstractButton.click()`
  — respects enabled-state, fires the connected slot) over isolated stores:
  Findings — select a row then **assign / comment / change status** by click
  (asserts the store), plus the disabled-without-selection enable-state wiring;
  Missions — **run a tool** by click (header_audit → finding ingested into the
  project) and **«Из скана»** fill-evidence by click (subdomains scan → evidence
  field auto-filled). Offline / offscreen Qt.

**Decisions (locked):** synchronous `_run_async` for deterministic, thread-free
e2e; `.click()` activations (robust headless, still validates the full wiring);
representative scope (Findings + Missions mutating flows), other tabs follow on
the same harness.

---
