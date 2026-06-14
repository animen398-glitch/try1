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
