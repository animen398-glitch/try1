# Advanced Site Analyzer — Отчёт о состоянии проекта

> Снимок на 2026-06-13, обновлён 2026-06-23 (эпик ASM 2.0 F1–F6 + пост-эпик +
> Advanced Intelligence Framework EPIC 8–16 + EPIC NEXT business-risk слой).
> Update 2026-06-28: KEV/EPSS Threat Intelligence Feed (CISA KEV + FIRST EPSS
> per-CVE enrichment → priority via threat_tier; cache in CVEStore, derive-on-read
> annotation, opt-in collection phase, report/web/CSV surfaces) closed locally on
> top of Workbench v2; full pytest 2101 passed, ruff clean, GUI self-check 29
> tabs. The priority/risk formula was not changed.
> Update 2026-06-28 (KEV/EPSS follow-ups, epic fully closed): KEV→SLA tightening
> (exploitability shortens the remediation window; floor-only) wired into the
> report, Alert Center, Timeline, GUI and web; NEW_KEV timeline event + KEV alert
> rule; KEV/EPSS exploitability badge in the findings detail; opt-in EPSS
> daily-CSV bulk ingestion. Current scale: **full pytest 2127 passed**, ruff
> clean, 1 existing Starlette/httpx warning. Priority/risk formula still unchanged.
> Update 2026-06-28 (Mission Center M1): new strategic layer started — a pure,
> offline, deterministic mission core contract (`core/pentest_mission.py` +
> `schemas/asa_pentest_mission.schema.json`) over the existing Audit Runs /
> FindingsStore / Scope / ROE, with no second store and client-safe guardrails
> reused from `audit_scope`/`audit_templates`/`action_policy`. Persistence/GUI/web
> deferred to M2+. Current scale: **full pytest 2162 passed**, ruff clean,
> 1 existing Starlette/httpx warning.
> Update 2026-06-28 (Mission Center M2): mission persistence + project bundle —
> `core/mission_store.py` (`MissionStore`, single-table, no event log; mirrors
> `AuditRunStore`), an events-less `PROJECT_EXPORT` generalization in
> `utils/sqlite_store.py`, and `missions.json` in the `core/project_io` bundle
> (`FORMAT_VERSION` unchanged, backward-compatible). No second findings/asset/
> timeline source; GUI/web/timeline deferred to M3+. Current scale: **full pytest
> 2177 passed**, ruff clean, 1 existing Starlette/httpx warning.
> Это навигабельная «карта проекта»: здоровье, структура, найденные ошибки и с
> чего начинать работу. Подробный пофичный лог — в
> [`PROJECT_STATUS.txt`](PROJECT_STATUS.txt); авторитетный статус — CLAUDE.md §12.

---

## 1. Здоровье (health dashboard)

| Метрика | Значение |
|---|---|
| Тесты | **2101 собрано, зелёные** (0 FAILED/ERROR; offline/headless Qt; 1 Starlette/httpx deprecation-warning) |
| Линтер (ruff) | ✅ чисто |
| Компиляция всех модулей | ✅ 0 ошибок |
| `except:` без типа | 0 |
| Маркеры TODO/FIXME/XXX | 0 |
| Своих модулей / тест-файлов | 100+ модулей / 140+ test-файлов |
| CI | GitHub Actions: lint + test (3.11/3.12) + Windows .exe build **+ smoke-run собранного .exe (`--self-check`)** |
| Git | ветка `master`, синхронизирована с `origin/master` (push 2026-06-23, `21e88ac`); удалённые действия — только по явному разовому разрешению |
| Локальный checkpoint | 2026-06-28: `master` ahead 70 local commits; remote git actions were not performed |

Вывод: кодовая база в хорошем состоянии — статика чистая, тесты зелёные.
Весь реализуемый роадмап закрыт (P1–P12 + TIER S/A/B + C1/C2 в безопасных
оффлайн/localhost-вариантах); см. §6. Сверх того закрыт **эпик ASM 2.0**
(F1 Findings → F6 GUI-рестайл), пост-эпик (asn_intel, report_export,
Asset Inventory, CVE Intelligence, углубление detection) и **Advanced
Intelligence Framework (EPIC 8–13)**: единый confidence по всем сущностям
(MODULE 1 Scan Accuracy), Asset Criticality, Priority deepening, Attack Paths,
report/web-поверхности и мониторинг attack-path событий — всё derive-on-read,
display-метрики (риск-вердикт не тронут). Сверх того закрыт **EPIC NEXT**
(business-risk слой 2026-06-22): Business Context Model, business-aware
prioritization, deterministic attack paths, remediation tasks, semantic drift
monitoring, auditor-friendly compliance, Cloud/Container/IaC ingestion. GUI-
хвосты добавлены 2026-06-23: Remediation, IaC Config, бизнес-контекст в
Criticality-вкладке (**project default + per-asset override**). Пофичный статус
в CLAUDE.md §12.

---

## 2. Что это за проект

Десктопный инструмент (Python 3.11+/PySide6 через qtpy) для авторизованной разведки и
анализа веб-сайтов: пассивная разведка, субдомены, перехват API-трафика, обход
paywall, оффлайн-клон фронтенда, извлечение медиа, анализ дизайна, аудиты
безопасности (cookie, секреты, source-map, уязвимости).

**Точки входа:**
- `main.py` — GUI (PySide6/qfluent через qtpy), self-check: 29 вкладок.
- `main_orchestrator.py` — CLI-пайплайн из 6 фаз (флаги `--dynamic/--paywall/--vulns/--dump-api/--web/--profile/--delay`).
- `remote/web_app.py` — FastAPI LAN-консоль (:5000), 13 job'ов с паритетом GUI (+ отмена job'а, + управление мониторингом #8, + Alert Center #9).
- `monitor_cli.py` — Continuous Monitoring (#8): `enable/disable/status/run/watch` над расписанием проектов.
  (та же логика доступна в GUI — вкладка Collection — и в web-консоли.)

---

## 3. Архитектура и структура

### core/ — движки анализа
| Модуль | Назначение |
|---|---|
| recon_engine | GeoIP + CMS-фингерпринт + tech-fingerprint + dependency-audit + infra + фавиконы + PWA-манифест |
| tech_fingerprint | расширенный оффлайн tech-fingerprint (CDN/server/backend/analytics + версии) |
| infrastructure | ASN/инфра-интеллидженс: цепочка Domain → ASN → IP → Provider → **Cloud → Region** (cloud/region derive-on-read из уже собранных сигналов) |
| cloud_classifier | **нормализация хостинг-облака** (AWS/Cloudflare/Azure/GCP/Fastly/Akamai/…) из provider/ASN-строки + CDN-tech + takeover-CNAME; pure/offline/без deps, сильнейший сигнал (ASN>provider>tech>CNAME), unknown→{} (без догадок); НЕ в risk-score |
| dependency_audit | RetireJS-lite: детект JS-библиотек + версий и флаг известных уязвимых |
| graphql_discovery | probe /graphql* + introspection-проверка (Security Audit) |
| subdomain_scanner | пассив (crt.sh, HackerTarget, AlienVault, Anubis) + brute |
| subdomain_active | HTTP-liveness + детект takeover |
| dynamic_analyzer | перехват XHR/Fetch через Playwright |
| paywall_bypass | 6 стратегий обхода + reader view |
| content_capture | обход и сохранение HTML-страниц + site_map (статус/тип/глубина) |
| frontend_cloner | скачивание ассетов + переписывание ссылок → оффлайн-копия |
| design_analyzer | палитра/типографика + сравнение версий |
| secret_scanner | **единый** детектор секретов (источник правды); к каждой находке прикрепляет `validation` |
| secret_validator | **оффлайн** структурная валидация формата секретов (без сети): vendor-форматы, JWT/Basic-декод, отсев плейсхолдеров |
| source_map_parser | `.js.map` → исходники и утечки |
| security_auditor | оркестратор secret + source-map + GraphQL по странице и её JS; summary со счётом валидного формата |
| cookie_auditor | аудит флагов HttpOnly/Secure/SameSite |
| vuln_scanner / vuln_report | правила уязвимостей + экспорт HTML/JSON/PDF |
| api_key_extractor / api_dumper | поиск ключей / дамп API-ответов |
| project | Project workspace: Projects/<slug>/ (scans/reports/history/metadata.json); `load_scan_report` для diff |
| scan_diff | **оффлайн-diff двух сканов проекта** (страницы/субдомены/секреты/тех/зависимости/заголовки/TLS-сертификат/эндпоинты/findings + дельта риска + GraphQL/source-maps/cookies/DNS/exposure-кластеры/**attack paths**), HTML-отчёт. Единый классификатор `diff_events` → Alert Center (`alerts.ALERT_TYPES`) + Timeline; **EPIC 13**: `new_attack_path`/`attack_path_escalated` (high, alertable) |
| monitor | **Continuous Monitoring (P-роадмап #8)**: расписание (daily/weekly/monthly) в metadata.json; `run_due` гоняет Full Collection + авто-Scan Diff против прошлого скана; чистая логика (`compute_next_run`/`is_due`) и тонкий `MonitorScheduler`-тред отделены от инъектируемого раннера (тесты без сети); опц. триггерит alerts |
| alerts | **Alert Center (#9)**: из авто-diff'а извлекает события (new secret/subdomain/takeover/technology/cert change/risk↑) и шлёт в Telegram/Discord (urllib)/Email (smtplib); строго opt-in, stdlib-only, транспорт инъектируем (тесты без сети); секреты уже замаскированы в diff'е |
| cert_info | TLS-сертификат хоста (stdlib ssl): fetch + summarize (issuer/срок/SAN/SHA-256) для Scan Diff |
| openapi_discovery | **OpenAPI Discovery (#11)**: пробинг типовых путей спеки (swagger.json/openapi.json/…) + чистый парсер OpenAPI 3.x/Swagger 2.0 → карта эндпоинтов; фетч (инъектируемый) отделён от парсинга; питает отчёт, граф (категория APIs) и Scan Diff (секция apis) |
| historical_intel | **Historical Intelligence (#12)**: архивные URL домена из Wayback CDX + чистая классификация (admin/auth/api/config/upload/docs); фетч отделён от классификатора (инъектируемый); питает отчёт, граф (категория Historical) и Scan Diff (секция historical, интересное подмножество) |
| dns_intel | **DNS Intelligence (#13 OSINT)**: A/AAAA/MX/TXT/NS/CAA + email-auth (SPF/DMARC/DKIM) через DNS-over-HTTPS (без dnspython); чистый анализ → findings (нет SPF/DMARC, слабый DMARC, нет CAA), которые сворачиваются в риск-движок; питает отчёт и Scan Diff (секция dns) |
| email_intel | **Email Intelligence (#13 OSINT)**: сбор e-mail адресов из homepage/robots.txt/sitemap.xml (stdlib re); чистая экстракция/классификация (фильтр шума: ассеты, плейсхолдеры, version-строки) → группировка на домене/внешние + по ролям (security/admin/support/sales/…); фетч отделён от экстракции (инъектируемый) → тесты без сети; питает отчёт (карточка) и Scan Diff (секция emails) |
| employee_intel | **Employee Intelligence (#13 OSINT)**: имена сотрудников со страниц team/about/leadership из структурных источников (JSON-LD `Person` + личные `mailto`, role-фильтр через email_intel); по парам имя↔адрес выводит корпоративный формат e-mail ({first}.{last}, {f}{last}, …) и достраивает вероятные адреса (помечены `inferred`, без догадок без on-domain-доказательств); фетч отделён от чистого roster (инъектируемый) → тесты без сети; питает отчёт (карточка) и Scan Diff (секция employees) |
| ct_history | **Certificate Transparency History (#13 OSINT)**: история сертификатов домена из crt.sh (то, что subdomain-сканер выбрасывает — временна́я/issuer-метадата): центры сертификации (CA), окна валидности, первое/последнее появление в логах, недавние (≤90 дн.) и wildcard-сертификаты, активные/истёкшие; сетевой fetch отделён от чистого `analyze` (с инъектируемым `now`) → тесты без сети и детерминированы по времени; информационный (в риск-движок не идёт), питает отчёт (карточка) и Scan Diff (секция ct — новый сертификат по crt.sh id) |
| findings_store / findings_adapter / findings_sla | **Findings Management (ASM F1)**: SQLite `data/findings.db`, стабильный fingerprint + project-scoped id, lifecycle OPEN/IN_PROGRESS/FIXED/IGNORED/FALSE_POSITIVE, события `finding_events`, SLA derive-on-read, GUI/Web triage. Заменяет legacy `findings_status.py`/`findings.json`; inactive findings исключаются из risk. |
| asset_store / asset_adapter | **Asset Inventory**: персистентный реестр активов (domain/subdomain/ip/asn/netblock/endpoint/technology), аналог Findings, но для активов. `asset_adapter` — pure derive из report (identity sha1(type␟norm), endpoint через normalize_location, технология=имя без версии); `asset_store` — SQLite `data/assets.db`, scoped-id ключ, lifecycle ACTIVE⇄GONE→REAPPEARED со scope-guard по фазе-источнику, `projects()`/`project_events()`. Проводка: `_sync_assets`, вкладка «Assets» (read-only), web `GET /assets`, Timeline (asset-события), `assets_csv`. Оффлайн, stdlib+sqlite |
| collection_runner | «Full Collection» — все фазы в один скан проекта Projects/<slug>/scans/<id>/; HTML/JSON/Markdown отчёты, warning lifecycle (`warnings`, `warning_count`, `warning_summary`) в report/metadata/portfolio/history, запись запуска в `operations.db`; опц. фазы: screenshot/nuclei/katana/**subdomains**/LLM |
| site_map | дерево путей сайта по HTTP-статусам + тип/глубина (визуальная карта) |
| executive_summary | **единый риск-движок 0–100** + вердикт/рекомендации над фазами; опц. LLM-нарратив (поле `narrative`) поверх детерминированного вердикта |
| intelligence | **Core + Advanced Intelligence (EPIC 7–11)**: confidence + priority + explanation per finding и обобщение на ВСЕ сущности (derive-on-read, без новых моделей/таблиц). `confidence`/`confidence_for` (корроборация+валидация+специфичность детекта для finding/technology/cve/asset/infrastructure/api/secret — **MODULE 1 Scan Accuracy**), `priority` (severity дисконтирован confidence + exposure/SLA + **asset-criticality бонус, EPIC 10**), `explain` (finding_knowledge). **EPIC 9** `asset_criticality`/`build_asset_criticality` (тип-вес + blast radius + находки + exposure → ранжирование активов). **EPIC 11** `build_attack_paths` (латеральные маршруты entry→pivot→targets по shared-infra). **Asset Exposure (likelihood-ось)** `exposure_score`/`build_exposure`/`load_exposure` (reachability + open findings + blast radius, **без тип-веса** — дополняет Criticality impact). `build_accuracy`/`accuracy_from_report` — единый rollup достоверности скана. Всё **display-метрики** (риск-вердикт не тронут). Переиспользует findings_store/correlation/asset_graph/findings_sla. Поверхности: report['intelligence'/'accuracy'/'asset_criticality'/'attack_paths'/'exposure'], web `/intelligence`+`/criticality`+`/attack-paths`+`/accuracy`+`/exposure`, GUI-вкладки «Priorities»/«Asset Criticality»/«Attack Paths»/«Scan Accuracy»/«Asset Exposure» |
| business_context | **Business Context Model (EPIC NEXT F1)**: user-declared важность актива (criticality + data sensitivity) — единый источник словаря/весов/резолва. Хранение = аддитивный ключ `business_context` в `metadata.json` (default + per-asset overrides по bare fingerprint; БЕЗ новой таблицы), `Project.get/set_business_context`. Augment-слой над `intelligence.asset_criticality` (риск-вердикт не тронут). Поверхности: report-карточка, web, `business_cli.py`, GUI-редактор в Criticality-вкладке (project default **+ per-asset override**, 2026-06-23) |
| remediation / iac_scanner / compliance | **EPIC NEXT** прочее: remediation work-items (event-sourced поверх `finding_events`, GUI-вкладка + CLI), Cloud/Container/IaC misconfig-скан (Dockerfile/Terraform/CFN, категория `iac`, GUI ad-hoc scan + CLI), OWASP Top 10 + CWE + framework-crosswalk (PCI/ISO/NIST/SOC2) compliance-отчёт (Markdown + SARIF-теги) |
| llm_summary | опц. LLM-резюме через **локальный Ollama** (stdlib urllib, graceful, ничего не уходит с машины) |
| report_charts | оффлайн inline-CSS бары для HTML-отчётов (без JS/зависимостей) |
| screenshot | опц. headless-скриншоты (Playwright, lazy, gated); **мульти-страничные** (home/login/admin/dashboard) через select_targets/capture_many |
| attack_surface | граф атак-поверхности (домен → категории); **интерактивный оффлайн** (CSS `:target`/`:hover`, без JS) + статический SVG + surface_score 0–100 |
| external_tools | опц. внешние бинари (nuclei/katana/amass): subprocess + нормализация |
| analyzer_plugins | SDK пользовательских аналитических плагинов (plugins/analyzers/) |
| anti_detect_engine / cloudflare_bypass | сессии с ротацией UA, retry, обход CF |
| scrapy_crawler / _scrapy_spider | deep-crawl в отдельном процессе |
| registry / config / paths / features | DataRegistry, единый конфиг, PathManager, детект опц. фич |

### utils/ — инфраструктура
`http_retry` (retry+backoff+gzip/deflate), `browser_utils` (SessionBuilder),
`sqlite_store`/`operation_registry`/`data_viewer`/`exporter`, `endpoint_index`,
`pattern_analyser`, `scan_cache` (TTL), `rate_limiter`, `system_logger`,
`file_compression`, `image_processor`, `video_processor`, `site_extractor`,
`task_manager`, `cloudflare_tools`.

### gui/ — PySide6/qfluent через qtpy (mixin-архитектура)
`main_window` — тонкий контейнер (~75 строк); каркас — mixin'ы `task_runner`
(единый раннер QThread), `window_chrome`, `window_helpers`; `workers`,
`plugin_manager` (реестр вкладок + авто-дискавери внешних), `ui_components`,
`dialogs`; модули `tab_*.py` (по вкладке), включая ASM-вкладки Findings/Assets/
**Priorities** (read-only Core Intelligence, EPIC 7 — `tab_intelligence`)/
**Asset Criticality** (EPIC 9 — `tab_criticality`)/**Attack Paths** (EPIC 11 —
`tab_attack_paths`)/**Scan Accuracy** (MODULE 1 — `tab_accuracy`)/Timeline/Overview.
Вкладки регистрируются из `BUILTIN_TABS` (секции nav-рельса), не хардкодятся;
кластер Intelligence (Priorities → Asset Criticality → Attack Paths → Scan Accuracy)
— в секции «Управление» после Findings. **Asset Criticality** несёт редактор
бизнес-контекста (project default **+ per-asset override** выбранного актива,
off-thread запись в `metadata.json` через `business_context`); EPIC NEXT GUI-
хвосты — вкладки **Remediation** и **IaC Config** (2026-06-23).

---

## 4. Что нового (платформа P1–P12)

Сессия закрыла весь реализуемый роадмап «Tools → Platform» + Next-Gen TIER B/C.
Каждая фича: оффлайн-тесты + живой прогон на реальном сайте + лог в
`PROJECT_STATUS.txt`. Без новых зависимостей на всём протяжении.

| # | Фича | Суть |
|---|---|---|
| P2 | Project Workspace | проект владеет таймстамп-сканами (`Projects/<slug>/`) |
| P3 | Unified Risk Engine | единый риск 0–100 + 5 уровней (executive_summary) |
| P4 | Dashboard 2.0 | агрегация из DataRegistry (+ takeovers/source maps) |
| P8 | **Scan Diff** | оффлайн-diff двух сканов проекта → HTML (`reports/diff_*.html`) |
| P9 | **Multi-page Screenshots** | home/login/admin/dashboard (Aquatone-style), галерея в отчёте |
| P10 | **Interactive Attack Graph** | клик/подсветка через чистый CSS (`:target`/`:hover`), без JS |
| P11 | **LLM Exec Summary** | опц. нарратив через локальный Ollama (graceful, ничего не уходит с машины) |
| P12 | **Secret Format Validation** | оффлайн-проверка формата ключей (без сети): отсев плейсхолдеров, vendor/JWT/Basic |

**Багов в этом feature-pass не внесено:** 504 теста зелёные, ruff чист,
оффлайн-контракт отчётов (нет `<script>`/CDN) проверяется тестами.

**Историческая справка (ранние ревью, см. PROJECT_STATUS §6):** закрыты
literal-tilde bug в `SettingsDialog` и 7 логических багов (recon/pwa_manifest,
циклический CSS `@import`, deflate-декод, provenance внешних JS, дубль
secret-regex в Capture, экранирование ResultsDisplay) + 4 «мёртвые» настройки.

**Статические проверки:** чисто (компиляция, ruff, нет bare-except, нет TODO).

---

## 5. Риски и технический долг

| Тема | Статус / заметка |
|---|---|
| Папка `~/` (литеральная) | [УДАЛЕНО] Маленький легаси-артефакт tilde-бага (gitignored). Прим.: ранняя оценка «~51 ГБ» была ошибкой измерения — `Get-ChildItem '~'` раскрылся в `$HOME`; реальная папка была небольшой. Дом. каталог не затронут. |
| Внешние сервисы (ip-api, crt.sh, …) | Обёрнуто в retry+backoff, мягкая деградация. Остаётся сетевая хрупкость. |
| Опц. тяжёлые зависимости | Playwright/yt-dlp/ffmpeg/fastapi/scrapy — guarded; на Windows yt-dlp/ffmpeg ставятся вручную (нет в .exe). |
| Web-консоль в LAN | Отдаёт найденные секреты по сети (by design для LAN-инструмента) — не выставлять наружу. |
| UA-профиль в dynamic/paywall | Paywall теперь honor-ит профиль; Playwright-перехват использует свой UA браузера (ожидаемо). |
| Security Audit вкладка | Нет кнопки Stop/прогресса (ограничена `max_scripts`, не критично). |
| LLM-нарратив (P11) | Строго opt-in, **только localhost-Ollama**; вердикт риска остаётся детерминированным (LLM лишь нарративит), текст запекается в отчёт → оффлайн сохраняется. Облачный LLM осознанно вне скоупа. |
| Secret-валидация (P12) | Только **оффлайн** структурная проверка формата — секреты не покидают машину. ЖИВАЯ сетевая валидация (отправка ключа провайдеру) сознательно НЕ реализована (dual-use/приватность). |

---

## 6. С чего начать (backlog / опции)

**Внутренний трек Platform P1–P12 + TIER S/A/B/C закрыт.** Но против ИСХОДНОГО
роадмапа (`2.txt`, приоритеты в строках 515–533) ещё есть непостроенные фазы —
ранее отчёт ошибочно называл их «исчерпанными». Реальный остаток по приоритету:
- **#8 Continuous Monitoring — [ГОТОВО]** `core/monitor.py` + CLI
  `monitor_cli.py` + GUI (вкладка Collection) + web-консоль: расписание
  daily/weekly/monthly, авто-Scan Diff, оффлайн, без новых зависимостей.
  Единая логика (`monitor.enable/disable/status/run_due`) под тремя тонкими
  поверхностями. Осталось опц.: фоновый scheduler внутри GUI/web-процесса
  (сейчас периодический прогон — через `monitor_cli.py watch`).
- **#9 Alert Center — [ГОТОВО]** `core/alerts.py`: события из авто-diff'а →
  Telegram/Discord/Email (stdlib), строго opt-in, конфиг в settings.json.
  Завязано в мониторинг (`run_due(alert_config=…)`); поверхности: CLI
  (`test-alert` + `run/watch`), GUI (Настройки → вкладка «Уведомления»: каналы +
  типы + тест), web-консоль (карточка Alert Center: статус без токенов + тест).
- **#11 OpenAPI Discovery — [ГОТОВО]** `core/openapi_discovery.py`: пробинг
  типовых путей спеки + парсер OpenAPI 3.x/Swagger 2.0 → карта эндпоинтов.
  Опц. фаза collection (чекбокс «OpenAPI / Swagger»), карточка в отчёте,
  категория APIs в графе, секция apis в Scan Diff. Stdlib, без новых
  зависимостей (YAML-спеки вне скоупа — нужен сторонний парсер).
- **#12 Historical Intelligence — [ГОТОВО]** `core/historical_intel.py`:
  архивные URL из Wayback CDX + классификация (admin/auth/api/config/…). Опц.
  фаза collection (чекбокс «Историч. URL (Wayback)»), карточка в отчёте,
  категория Historical в графе, секция historical в Scan Diff. Stdlib;
  Common Crawl / OTX вне скоупа (тяжелее / ключи), источник расширяем.
- **#13 OSINT-модули — [ГОТОВО]** DNS Intelligence **[ГОТОВО]**
  (`core/dns_intel.py`: A/AAAA/MX/TXT/NS/CAA + SPF/DMARC/DKIM через DoH, findings
  в риск-движок; опц. фаза collection «DNS / Email-auth», карточка, Scan Diff
  секция dns) · Email Intelligence **[ГОТОВО]** (`core/email_intel.py`: сбор
  адресов из homepage/robots/sitemap, группировка на домене/внешние + по ролям;
  фетч отделён от чистой экстракции; опц. фаза collection «Email-разведка»,
  карточка, Scan Diff секция emails) · Employee Intelligence **[ГОТОВО]**
  (`core/employee_intel.py`: имена со страниц team/about из JSON-LD Person +
  личных mailto, вывод корпоративного формата e-mail и достройка вероятных
  адресов; опц. фаза collection «Сотрудники», карточка, Scan Diff секция
  employees) · CT-история **[ГОТОВО]** (`core/ct_history.py`: история
  сертификатов из crt.sh — CA/сроки/первое-последнее появление/недавние+
  wildcard; опц. фаза collection «CT-история», карточка, Scan Diff секция ct).
  **Бандл #13 (DNS + Email + Employee + CT) закрыт.**
- **#14 / ASM F1 Findings Management — [ГОТОВО]** (`core/findings_store.py`,
  `core/findings_adapter.py`, `core/findings_sla.py`): SQLite lifecycle-стор,
  cross-scan dedup, auto-FIX со scope guard, sticky IGNORED/FALSE_POSITIVE,
  GUI-вкладка Findings и web endpoints. Legacy `findings_status.py` /
  `findings.json` удалены и заменены этим стором.

Осознанно вне скоупа (нарушают инварианты по своей природе):
- **C2 «живая» сетевая secret-валидация** (отправка ключа провайдеру) — dual-use/приватность.
- **REJECTED:** тяжёлый JS-AST-парсер, интерактивный граф через CDN-JS, любой облачный AI.

**Точечные улучшения — сделано в этой сессии:**
- [СДЕЛАНО] Security Audit: кнопка Stop + live-прогресс в статус-строке (`3e7dcba`).
- [СДЕЛАНО] Модель локального Ollama настраивается из GUI (Настройки → Сеть, `2eb9075`).
- [СДЕЛАНО] Web-консоль: job **Scan Diff** (паритет с GUI P8, `f4d0905`).
- [СДЕЛАНО] Dashboard «Очистить»: вопрос решён (`9f9c803`) — «Очистить вид»
  (безопасно) + отдельная «Очистить БД…» с диалогом подтверждения и реальным
  удалением из registry.db (`DataRegistry.clear()`).
- [ПОКРЫТО РАНЕЕ] Happy-path сетевых модулей: recon (`test_recon_engine`) и
  subdomain (`test_subdomain_cache`) уже тестируются на моках.
- [СДЕЛАНО] Scan Diff: секция **субдоменов** разблокирована — в collection
  добавлена опц. subdomain-фаза (passive + takeover), которая питает Scan Diff,
  риск-движок (takeover-сигнал) и граф (категория Subdomains).
- [СДЕЛАНО] Scan Diff: секция **сертификатов** разблокирована — опц. TLS-cert-
  фаза (`core/cert_info.py`, stdlib ssl) пишет issuer/срок/SAN/отпечаток;
  Scan Diff показывает смену сертификата (renewal/issuer/SAN) между сканами.

- [СДЕЛАНО] Харднинг: CI smoke-запускает собранный .exe (`main.py --self-check`
  строит окно headless и выходит 0) — ловит PyInstaller-регрессии (потерянный
  hidden-import / data-файл), которые юнит-тесты на исходниках не видят.

- [СДЕЛАНО] Web-консоль: **отмена выполняющегося job'а** — эндпоинт `POST /cancel`
  кооперативно сигналит активному движку (CollectionRunner/SubdomainScanner через
  `cancel()`, SecurityAuditor через cancel-Event, адаптируемый `_EventCanceller`);
  раннер регистрирует cancellable и сбрасывает его в `finally`. В UI — кнопка
  Cancel, активная только во время выполнения (состояние ведётся по реальному
  жизненному циклу job'а через SSE, без таймаут-хака).

**Осталось (маргинально):**
- Web-консоль: job экспорта Vuln-отчёта (избыточен — collection уже даёт полный отчёт).
- Security Audit: вынести `max_scripts`/таймауты в настройки; конфиг таймаутов dynamic-анализа (низкий спрос).

---

## EPIC EXT-OSINT — baseline РЕАЛИЗОВАН (2026-06-21)

> Раздел обновлён: модули ниже **существуют и доведены до рабочего baseline**
> (F1–F4 в `ROADMAP_ASM_2.0.md` помечены `[ВЫПОЛНЕНО 2026-06-21]`). Это НЕ
> «запланировано/не написано». Остаток — точечные расширения baseline; новый
> business-risk слой вынесен в **EPIC NEXT** (`ROADMAP_ASM_2.0.md`, статус
> ПЛАНИРОВАНИЕ).

- `core/bbot_adapter.py` **[РЕАЛИЗОВАН]** — внешний опциональный BBOT-адаптер через
  subprocess + JSON/NDJSON (BBOT под AGPL-3.0 — код НЕ копируется, не
  обязательная зависимость, не бандлится в `.exe`). Вывод нормализуется в
  AssetStore/FindingsStore. Детект — `features.has_bbot()` **[РЕАЛИЗОВАН]**.
- `core/document_intelligence.py` **[РЕАЛИЗОВАН]** — ядро document intelligence
  (offline-first контракт «документ → структурированные поля → DTO»).
- `core/document_providers/lift_adapter.py` **[РЕАЛИЗОВАН]** — опциональный провайдер
  (datalab-to/lift) через subprocess; тяжёлые `torch`/`vLLM`/HF-модели не
  импортируются/не бандлятся, мягкая деградация при отсутствии.
- `core/osint_catalog.py` **[РЕАЛИЗОВАН]** — offline derive-on-read каталог AI-OSINT
  воркфлоу (идеи из Awesome-AI-OSINT) поверх существующих движков.

Расширение baseline (или NEXT-слой) — строго по цепочке Epic → Feature → Task,
по одной задаче, после утверждения плана конкретной фичи. README обновляется
только по факту.

---

*Сгенерировано в ходе ревью. Детали и история изменений — `PROJECT_STATUS.txt`.*
> Update 2026-06-20: Epic 14 - Scope & Evidence Foundation is CLOSED.
> Completed: Scope Guard v1, Evidence Manifest v1, Evidence Integrity Hook,
> Finding Evidence Persistence v1, Scope CLI / Project Scope Management,
> Evidence Refs Coverage Expansion, Report / Export Traceability, Scope Guard
> Coverage Audit, Evidence Integrity Integration With Monitor/Export, and
> roadmap/status cleanup. Final verification: ruff clean; full pytest 1460
> passed with 1 existing Starlette/httpx warning.
> Update 2026-06-23: EPIC NEXT (business-risk слой, F0–F7) CLOSED 2026-06-22;
> GUI-хвосты добавлены 2026-06-23 — Remediation, IaC Config, и per-asset business
> context override в Criticality-вкладке (хранение прежнее: metadata.json →
> business_context → assets; risk-вердикт не тронут). Final verification: ruff
> clean; full pytest **1794 passed** с 1 существующим Starlette/httpx warning.
> Update 2026-06-28: Client-Safe Pentest Workbench closed locally: audit
> workflow/schema/validation/quality gates, safe ROE-gated checks, Audit Runs GUI,
> persistent audit_runs/audit_events, deterministic JSON/MD/HTML reports,
> timeline audit-run events, independent evidence verification, granular finding
> audit events, and project bundle portability for audit-run history. Backend
> release-hardening merge `fb862990` also verified. Final local checkpoint:
> `ruff check .` clean; full pytest **2020 passed** with 1 existing
> Starlette/httpx warning; `python main.py --self-check` = 29 tabs; PyInstaller
> build with `QT_API=pyside6` and frozen `dist/SiteAnalyzer.exe --self-check`
> passed. Remote git actions were not performed.
