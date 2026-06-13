# Advanced Site Analyzer — Отчёт о состоянии проекта

> Снимок на 2026-06-13. Это навигабельная «карта проекта»: здоровье, структура,
> найденные ошибки и с чего начинать работу. Подробный пофичный лог — в
> [`PROJECT_STATUS.txt`](PROJECT_STATUS.txt).

---

## 1. Здоровье (health dashboard)

| Метрика | Значение |
|---|---|
| Тесты | **513 passed, 1 skipped** (514 собрано; сетенезависимые, Qt headless) |
| Линтер (ruff) | ✅ чисто |
| Компиляция всех модулей | ✅ 0 ошибок |
| `except:` без типа | 0 |
| Маркеры TODO/FIXME/XXX | 0 |
| Своих модулей / тест-файлов | 80 (core 40 / utils 17 / gui 22 / remote 1) / 65 |
| CI | GitHub Actions: lint + test (3.11/3.12) + Windows .exe build |
| Git | ветка `master`, синхронна с `origin/master`; платформенные фичи P1–P12 закоммичены и запушены |

Вывод: кодовая база в хорошем состоянии — статика чистая, тесты зелёные.
Весь реализуемый роадмап закрыт (P1–P12 + TIER S/A/B + C1/C2 в безопасных
оффлайн/localhost-вариантах); см. §6.

---

## 2. Что это за проект

Десктопный инструмент (Python 3.11+/PyQt5) для авторизованной разведки и
анализа веб-сайтов: пассивная разведка, субдомены, перехват API-трафика, обход
paywall, оффлайн-клон фронтенда, извлечение медиа, анализ дизайна, аудиты
безопасности (cookie, секреты, source-map, уязвимости).

**Три точки входа:**
- `main.py` — GUI (PyQt5), 14 вкладок + внешний плагин Deep Crawl.
- `main_orchestrator.py` — CLI-пайплайн из 6 фаз (флаги `--dynamic/--paywall/--vulns/--dump-api/--web/--profile/--delay`).
- `remote/web_app.py` — FastAPI LAN-консоль (:5000), 12 job'ов с паритетом GUI.

---

## 3. Архитектура и структура

### core/ — движки анализа
| Модуль | Назначение |
|---|---|
| recon_engine | GeoIP + CMS-фингерпринт + tech-fingerprint + dependency-audit + infra + фавиконы + PWA-манифест |
| tech_fingerprint | расширенный оффлайн tech-fingerprint (CDN/server/backend/analytics + версии) |
| infrastructure | ASN/инфра-интеллидженс: цепочка Domain → ASN → IP → Provider |
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
| scan_diff | **оффлайн-diff двух сканов проекта** (страницы/секреты/тех/зависимости/заголовки/эндпоинты/findings + дельта риска), HTML-отчёт |
| collection_runner | «Full Collection» — все фазы в один скан проекта Projects/<slug>/scans/<id>/ |
| site_map | дерево путей сайта по HTTP-статусам + тип/глубина (визуальная карта) |
| executive_summary | **единый риск-движок 0–100** + вердикт/рекомендации над фазами; опц. LLM-нарратив (поле `narrative`) поверх детерминированного вердикта |
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

### gui/ — PyQt5 (mixin-архитектура)
`main_window` — тонкий контейнер (~75 строк); каркас — mixin'ы `task_runner`
(единый раннер QThread), `window_chrome`, `window_helpers`; `workers`,
`plugin_manager` (реестр вкладок + авто-дискавери внешних), `ui_components`,
`dialogs`; 14 модулей `tab_*.py` (по вкладке).

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

**Роадмап исчерпан:** весь реализуемый объём закрыт — Platform P1–P12, Next-Gen
TIER S/A/B, и TIER C в безопасных вариантах (C1 — localhost-Ollama, C2 —
оффлайн-валидация формата). Осознанно вне скоупа остаётся лишь то, что нарушает
инварианты по своей природе и требует отдельного явного решения:
- **C2 «живая» сетевая secret-валидация** (отправка ключа провайдеру) — dual-use/приватность.
- **REJECTED:** тяжёлый JS-AST-парсер, интерактивный граф через CDN-JS, любой облачный AI.

**Точечные улучшения — сделано в этой сессии:**
- [СДЕЛАНО] Security Audit: кнопка Stop + live-прогресс в статус-строке (`3e7dcba`).
- [СДЕЛАНО] Модель локального Ollama настраивается из GUI (Настройки → Сеть, `2eb9075`).
- [СДЕЛАНО] Web-консоль: job **Scan Diff** (паритет с GUI P8, `f4d0905`).
- [ПОКРЫТО РАНЕЕ] Happy-path сетевых модулей: recon (`test_recon_engine`) и
  subdomain (`test_subdomain_cache`) уже тестируются на моках.

**Осталось (маргинально / заблокировано / нужно решение):**
- Web-консоль: отмена выполняющегося job'а; job экспорта Vuln-отчёта (избыточен — collection уже даёт полный отчёт).
- Security Audit: вынести `max_scripts`/таймауты в настройки; конфиг таймаутов dynamic-анализа (низкий спрос).
- Scan Diff: секция субдоменов/сертификатов — **заблокировано** (collection их пока не собирает).
- Dashboard «Очистить»: очистка вида vs реальное удаление из registry.db —
  **открытый вопрос, требует решения пользователя**.

---

*Сгенерировано в ходе ревью. Детали и история изменений — `PROJECT_STATUS.txt`.*
