# Advanced Site Analyzer — Отчёт о состоянии проекта

> Снимок на 2026-06-13. Это навигабельная «карта проекта»: здоровье, структура,
> найденные ошибки и с чего начинать работу. Подробный пофичный лог — в
> [`PROJECT_STATUS.txt`](PROJECT_STATUS.txt).

---

## 1. Здоровье (health dashboard)

| Метрика | Значение |
|---|---|
| Тесты | **434 passed, 1 skipped** (сетенезависимые, Qt headless) |
| Линтер (ruff) | ✅ чисто |
| Компиляция всех модулей | ✅ 0 ошибок |
| `except:` без типа | 0 |
| Маркеры TODO/FIXME/XXX | 0 |
| Своих модулей / тест-файлов | 76 / 55 |
| CI | GitHub Actions: lint + test (3.11/3.12) + Windows .exe build |
| Git | ветка `master`, локальные feat-коммиты не запушены (Next-Gen TIER S/A) |

Вывод: кодовая база в хорошем состоянии — статика чистая, тесты зелёные.

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
| content_capture | обход и сохранение HTML-страниц |
| frontend_cloner | скачивание ассетов + переписывание ссылок → оффлайн-копия |
| design_analyzer | палитра/типографика + сравнение версий |
| secret_scanner | **единый** детектор секретов (источник правды) |
| source_map_parser | `.js.map` → исходники и утечки |
| security_auditor | оркестратор secret + source-map по странице и её JS |
| cookie_auditor | аудит флагов HttpOnly/Secure/SameSite |
| vuln_scanner / vuln_report | правила уязвимостей + экспорт HTML/JSON/PDF |
| api_key_extractor / api_dumper | поиск ключей / дамп API-ответов |
| project | Project workspace: Projects/<slug>/ (scans/reports/history/metadata.json) |
| collection_runner | «Full Collection» — все фазы в один скан проекта Projects/<slug>/scans/<id>/ |
| site_map | дерево путей сайта по HTTP-статусам (визуальная карта) |
| executive_summary | детерминир. вердикт риска + рекомендации над фазами (без LLM) |
| report_charts | оффлайн inline-CSS бары для HTML-отчётов (без JS/зависимостей) |
| screenshot | опц. headless-скриншот страницы (Playwright, lazy import, gated) |
| attack_surface | статический оффлайн-SVG граф атак-поверхности (домен → категории) |
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

## 4. Найденные ошибки (этот ревью)

**НОВОЕ — исправлено сейчас:**
- 🐞 **literal-tilde bug** (`b6d96d8`): `SettingsDialog` сохранял `output_dir`
  без раскрытия `~`, поэтому при вводе `~/SiteAnalyzer` сканы в той же сессии
  писали в папку, буквально названную `~`, в рабочем каталоге. **Это и есть
  причина папки `~\SiteAnalyzer` на ~51 ГБ** в корне репозитория. Исправлено
  (раскрытие `~` при сохранении) + тест.

**Статические проверки:** чисто (компиляция, ruff, нет bare-except, нет TODO).

**Ранее за сессию закрыто 7 логических багов** (см. PROJECT_STATUS §6):
recon-отчёт не урезал pwa_manifest; циклический CSS `@import` → рекурсия;
deflate не декодировался в AntiDetect/Cloudflare; provenance внешних JS;
дублирующий secret-regex в Capture; экранирование вывода в ResultsDisplay.
Плюс 4 «мёртвые» настройки доведены до рабочих.

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

---

## 6. С чего начать (backlog / опции)

**Гигиена:**
1. [СДЕЛАНО] Запушены локальные коммиты на `origin/master`.
2. [СДЕЛАНО] Удалена литеральная папка `~/` (легаси-артефакт tilde-бага;
   ранняя оценка «51 ГБ» была ошибкой измерения, см. §5).

**Возможные фичи/улучшения (выбрать по приоритету):**
- Security Audit: кнопка Stop + прогресс; вынести `max_scripts`/таймауты в настройки.
- Web-консоль: отмена выполняющегося job'а; job экспорта Vuln-отчёта.
- Конфиг профиля/таймаутов для dynamic-анализа из GUI-настроек.
- Опц. внешние бинари (subfinder/nuclei) как дополнительные источники.
- Happy-path тесты сетевых модулей (recon/subdomain) на моках.
- Решить вопрос с Dashboard «Очистить»: оставить как очистку вида или сделать
  реальное удаление из registry.db (с диалогом подтверждения) — открытый вопрос.

---

*Сгенерировано в ходе ревью. Детали и история изменений — `PROJECT_STATUS.txt`.*
