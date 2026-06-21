# Advanced Site Analyzer

Десктопный инструмент (Python 3.11+ / PySide6/qtpy) для комплексной разведки и анализа
веб-сайтов: пассивная разведка, перечисление субдоменов, перехват динамического
трафика и API-эндпоинтов, обход paywall, захват и оффлайн-клонирование
фронтенда, извлечение медиа, анализ дизайн-системы и аудит безопасности cookie —
всё в одном GUI, с CLI-пайплайном и опциональной web-консолью.

> Назначение — авторизованное тестирование безопасности, исследовательские и
> образовательные задачи. Используйте только на ресурсах, которые вам разрешено
> анализировать.

Текущий статус и план работ — см. [`PROJECT_STATUS.txt`](PROJECT_STATUS.txt).

## Возможности

GUI содержит 25 вкладок (встроенные ASM/CSM/Intelligence-поверхности + внешние плагины при наличии):

| Вкладка | Назначение |
|---|---|
| Recon & Intel | GeoIP, фингерпринт CMS/стека + расширенный tech-fingerprint (CDN/сервер/бэкенд/аналитика + версии), ASN/инфра-интеллидженс (Domain → ASN → IP → Provider → Cloud → Region), фавиконы, PWA-манифест; опц. paywall-bypass, перехват API (Playwright), vuln-scan, **CVE Intelligence** (OSV + NVD, оффлайн-кеш), дамп API-ответов |
| Subdomain Scanner | Пассивное (crt.sh, HackerTarget, AlienVault OTX, Anubis; опц. внешний amass) + brute-force перечисление с живой таблицей; опц. active-проверки (liveness + takeover) |
| API Key Scanner | Поиск утечек API-ключей/секретов на странице |
| Site Capture | Обход и сохранение HTML-страниц сайта (с отменой) + визуальная карта сайта (дерево путей с HTTP-статусами 2xx/3xx/4xx/5xx) в `site_map.json` и HTML-отчёте |
| Clone Frontend | Скачивание ассетов и переписывание ссылок → самодостаточная оффлайн-копия |
| Video Downloader | yt-dlp: пресеты до 4K (merge через ffmpeg), сессионные cookies |
| Image Extractor | Оригинальное разрешение без водяных знаков; Instagram/соцсети через yt-dlp |
| Design Lab | Извлечение палитры/типографики, сравнение версий |
| Cookie Security Audit | Аудит флагов HttpOnly / Secure / SameSite со скорингом и вердиктом |
| Security Audit | Нативный сканер секретов + source-map (страница и её JS): утечки ключей, эндпоинты, открытые .js.map + GraphQL-discovery (probe /graphql* + introspection) + **оффлайн-валидация формата** найденных ключей (структурная проверка без сети — отсев плейсхолдеров, подтверждение vendor-формата/JWT/Basic) |
| Final Report & Collection | «Run Full Collection» — прогон всех модулей в один скан проекта (`Projects/<домен>/scans/<timestamp>/`) + HTML/JSON/Markdown-отчёт (Executive Summary, интерактивный граф атак-поверхности, карта сайта, trends, Warnings по best-effort этапам; опц. Playwright/nuclei/katana/Ollama) + Scan Diff двух сканов проекта; каждый запуск журналируется в `operations.db` |
| Dashboard | Сводка реестра (субдомены / IP / медиа / API / **takeover-кандидаты** / **source maps**) с дедупом эндпоинтов и drill-down + Security Overview (вердикт риска + **0–100** / Attack Surface Score / секреты / findings из последнего Full Collection) |
| История операций | Журнал операций пайплайна (SQLite): Full Collection/alerts/etc., статус, длительность, warning-count и подсказка по warning-этапам |
| System | Очередь задач, экспорт данных, системные логи |

## Установка

```bash
pip install -r requirements.txt
```

Опциональные возможности (не входят в .exe-сборку, ставятся отдельно):

```bash
pip install playwright && python -m playwright install chromium   # Dynamic API Sniffing
pip install yt-dlp                                                # Video / Instagram
pip install "fastapi" "uvicorn[standard]"                          # web-консоль
# ffmpeg — внешний бинарь; нужен для merge 4K/1080p (видео+аудио)
# nuclei — внешний бинарь (projectdiscovery); опц. vuln-сканер в Full Collection
#          (https://github.com/projectdiscovery/nuclei). Детект — в System-вкладке.
# katana — внешний бинарь (projectdiscovery); опц. краулер эндпоинтов в Full Collection.
# amass  — внешний бинарь (owasp); опц. пассивный источник субдоменов в Subdomain-вкладке.
```

## Запуск

```bash
# GUI (основной режим)
python main.py

# CLI-пайплайн: Recon -> [Paywall] -> Capture -> [Dynamic] -> [Vulns] -> [API dump]
python main_orchestrator.py https://example.com --dynamic --paywall --vulns
python main_orchestrator.py https://example.com --max-pages 10 --output ./reports
python main_orchestrator.py https://example.com --profile firefox_windows --delay 1000

# Web-консоль (LAN, http://0.0.0.0:5000)
python main_orchestrator.py https://example.com --web
```

### Launcher & Dependency Management (единая точка)

`launcher.py` — отдельное приложение для Install / Repair / Update / Launch
(offline-first, **без обязательного сервера обновлений**). Логика — в чистом
`core/launcher.py` (переиспользует `core/features.py` для проверки зависимостей и
`PathManager` для путей; не дублирует их).

```bash
python launcher.py                 # окно Launcher (Qt): Launch / Check Health /
                                   #   Repair / View Components / Install Optional Tools
python launcher.py --health        # отчёт о здоровье (обязательные + опц. зависимости)
python launcher.py --components     # список опц. компонентов + как поставить
python launcher.py --install NAME  # установить опц. компонент (pip) или показать
                                   #   инструкцию+URL для внешнего бинарника
python launcher.py --repair        # переустановить обязательные (pip install -r requirements.txt)
python launcher.py --update        # локальное обновление зависимостей (pip --upgrade; без git pull)
python launcher.py --launch        # запустить основное приложение
```

- **Check Health** — Python-версия, обязательные деп (PySide6/qtpy/requests/bs4),
  опц. компоненты (через `features.summary()`), запись в data-root.
- **Install Optional Tools** — pip-модули ставятся через pip; внешние Go-бинарники
  (nuclei/katana/amass/subfinder/httpx/ffmpeg) **нельзя** поставить через pip →
  показывается инструкция + домашняя страница (положить на PATH).
- **Update** — только локальный `pip install --upgrade -r requirements.txt`.
  Удалённые git-операции (`git pull/fetch/push/clone`) запрещены правилами проекта
  без явного разового разрешения.

## Структура проекта

```
main.py                  # точка входа GUI
main_orchestrator.py     # CLI-пайплайн из 6 фаз
core/                    # движки анализа (recon, capture, clone, cookie_auditor,
                         #   collection_runner, dynamic_analyzer, vuln_scanner, …)
utils/                   # инфраструктура (SQLite-реестры, экспорт, медиа, паттерны)
gui/
  main_window.py         # тонкий контейнер: собирает окно из mixin'ов
  task_runner.py         # раннер фоновых задач _start_task (Signals/Slots)
  window_chrome.py       # меню, таб-бар из PluginManager, статус-бар
  window_helpers.py      # общие helpers (пути, архивация, busy-state)
  plugin_manager.py      # реестр вкладок-плагинов + авто-дискавери внешних
  tab_*.py               # по модулю на вкладку (mixin-классы)
  workers.py             # QObject-воркеры фоновых задач
remote/web_app.py        # FastAPI web-консоль
plugins/                 # внешние вкладки-плагины (см. plugins/README.md)
tests/                   # pytest-набор
```

### Архитектура многопоточности

Все фоновые задачи проходят через единый раннер `MainWindow._start_task()`
(паттерн Signals/Slots): каждый QObject-воркер живёт на своём QThread,
учитывается в реестре `self._tasks` и безопасно уничтожается (`deleteLater`)
только после завершения OS-потока. Это исключает краш «QThread destroyed while
running» и позволяет запускать несколько задач параллельно. Длительные задачи
(capture/clone/collection) поддерживают кооперативную отмену; число активных
задач отображается в статус-баре.

## Проекты (Project Workspace)

Каждый запуск **Full Collection** — это таймстамп-скан внутри постоянного
проекта цели. Под выбранной директорией вывода создаётся:

```
Projects/<домен>/
  scans/<timestamp>/   # отдельный скан (recon/ api/ capture/ … report.html)
  reports/  screenshots/  exports/  history/
  metadata.json        # индекс всех сканов + последний вердикт риска
```

`core/project.py` (`Project` / `ProjectStore`) — единственный источник правды по
сканам проекта; внутренняя раскладка скана не изменилась (обратная
совместимость). `metadata.json` хранит для каждого скана risk level/score,
attack-surface score, число секретов/находок — основа для Dashboard и истории.

### Scan Diff — что изменилось между сканами

На вкладке Final Report & Collection: выберите проект и два его скана →
«Сравнить». `core/scan_diff.py` (чистый stdlib, оффлайн) сравнивает два
`report.json`: новые/удалённые/изменённые **страницы** (статус/тип),
**секреты** (значения маскируются), **технологии** (вкл. смену версий),
**JS-зависимости** (вкл. появившиеся уязвимости), **HTTP-заголовки**,
**эндпоинты katana** и **findings**, плюс дельта риска `Low 4/100 → High
40/100`. Секция сравнивается только если её фаза успешна в обоих сканах
(упавшая фаза не выдаётся за «всё удалено»). Результат —
`Projects/<домен>/reports/diff_<A>_vs_<B>.html` (inline-CSS, без JS).

### CVE Intelligence (опц.)

Связывает обнаруженные JS-библиотеки с известными CVE. Включается опцией
**OSV/CVE** в Full Collection (активная разведка, поэтому off по умолчанию).
Пайплайн: детект библиотеки и версии → **OSV.dev** (какие CVE её затрагивают)
→ **NVD** (точный CVSS-балл, дата публикации, summary по каждому CVE) →
**персистентный кеш** (`data/cve_cache.db`) → находки в фазе vulns.

- **Оффлайн после загрузки базы.** Кеш заполняется лениво из живых источников
  (никакого бандла CVE-дампа в `.exe`); повторный скан использует кеш и работает
  без сети — а при недоступной сети показывает закешированное.
- **Без обязательных облачных зависимостей.** Оба источника keyless; опц. ключ
  NVD (`nvd_api_key` в настройках) лишь поднимает rate-limit.
- **Дедупликация.** Один CVE из nuclei + OSV + bundled-таблицы схлопывается в
  одну находку (по CVE id).
- **CVE Risk Score** — производная метрика (число CVE по severity + чип в
  Executive Headline), а не отдельное слагаемое риска: каждый CVE считается один
  раз через severity своей находки.
- Для каждой уязвимости: **CVE ID · severity · CVSS · дата публикации · summary**
  (в карточке Dependencies отчёта и в находках).

### Core Intelligence Framework (от обнаружения к объяснению)

`core/intelligence.py` (derive-on-read, без новых моделей) ранжирует находки по
**Priority** с оценкой **Confidence** и объяснением — «что чинить первым и почему».

- **Confidence (0–100)** — насколько находка реальна: `base(категория)` +
  корроборация (сколько независимых сканеров её подтвердили, `Finding.sources`) +
  валидация (высокоценный секрет точного формата). Band: high ≥80 / medium / low.
- **Priority (0–100)** — `severity_base × confidence/100` (низкая уверенность
  **дисконтирует** severity) + бонус exposure (находка на co-hosted/скоррелированном
  активе — blast radius) + бонус SLA (просрочен / скоро). Каждый score —
  с named-факторами (аудируемо, как «Из чего риск»).
- **Explanation** — impact/remediation из каталога `finding_knowledge` (F-O).
- Поверхности: карточка **Priorities** в HTML-отчёте, web `/intelligence`, метрики
  `top_priority`/`high_confidence_findings` в Executive Summary.

Переиспользует (не дублирует): Findings, Correlation/Asset Graph (exposure/blast
radius), Knowledge-каталог, SLA, severity — новых таблиц/моделей нет.

**Unified Scan Accuracy (MODULE 1)** — та же оценка достоверности обобщена с findings
на **все** сущности: `confidence_for(entity_type, entity)` отдаёт единый словарь
`{score, band, factors, evidence, source, verification}` для `finding / technology /
cve / asset / infrastructure / api / secret`. Каждый тип переиспользует свой готовый
сигнал верификации — структурная валидация секрета (`secret_validator`), способ
детекта технологии (header/cookie/script сильнее html-эвристики), CVSS+мульти-БД у
CVE, фаза-источник и активная проба у актива, RDAP vs passive у инфраструктуры,
2xx-ответ у API. `build_accuracy(...)` сворачивает разнотипные сущности в общий
rollup. Всё derive-on-read, без новых таблиц.

**Asset Criticality (EPIC 9)** — «какой актив важнее» (в пару к Priority «какую
находку чинить первой»): `asset_criticality(asset, …)` → `{score, band, factors}` из
тип-веса (apex-домен/ASN/netblock весомее одного эндпоинта или технологии) + blast
radius (сколько активов зависит — входящие рёбра графа + размер кластера общей инфры)
+ worst-severity привязанных находок + exposure (takeover / публично доступен).
`build_asset_criticality(...)` ранжирует, переиспользуя Correlation + Asset Graph.
Display-метрика (`critical_assets`/`top_asset_criticality` в Executive Summary,
карточка «Asset Criticality» в отчёте) — risk-вердикт не меняет. Criticality также
**усиливает Priority** (находка на критичном активе чинится раньше).

**Attack Paths (EPIC 11)** — «как это связано»: латеральные пути по общей
инфраструктуре. `build_attack_paths(...)` находит кластеры, где находко-несущий
exposed-хост (entry) делит ip/asn/netblock (pivot) с другими активами (targets), и
строит маршрут «entry → pivot → targets» со score по severity entry + размеру
кластера + числу критичных targets. Показывает blast radius как явный путь атаки.
Display-метрика (`attack_paths`/`critical_attack_paths` + карточка «Attack Paths»),
переиспользует Exposure-кластеры + Correlation + Criticality; вердикт не меняет.

**Asset Exposure (likelihood-ось)** — «насколько актив достижим/атакуем прямо
сейчас» (в пару к Criticality «насколько актив ценен»): `exposure_score(asset, …)` →
`{score, band, factors}` из reachability (takeover / публично-2xx / resolved) +
открытых находок + blast radius, **без тип-веса** (likelihood, не impact — reachable
низкоценный субдомен со свежей уязвимостью «горячее» дорогого, но закрытого apex).
`build_exposure(...)` ранжирует, переиспользуя те же входы, что Criticality.
Display-метрика (`exposed_assets`/`top_exposure` + карточка «Asset Exposure», web
`/exposure`, GUI-вкладка, CSV) — risk-вердикт не меняет.

**Cloud / Region (инфра-цепочка)** — `core/cloud_classifier.py` нормализует
хостинг-облако (AWS / Cloudflare / Azure / …) из уже собранных сигналов (provider/
ASN-строка, CDN-технологии, takeover-CNAME) — pure, offline, без догадок (unknown
остаётся unknown). Достраивает цепочку до **Domain → ASN → IP → Provider → Cloud →
Region**; `cloud`/`region` попадают в attrs активов (domain/ip/asn + per-subdomain
из CNAME) и в карточку инфраструктуры. Display-слой — в risk-score не входит.

### Asset Correlation Engine & Exposure Intelligence

Платформа не просто хранит активы, а **понимает отношения между ними**
(`core/asset_graph.py`, derive-on-read поверх Asset Inventory, без новой схемы):

- **Граф активов** — типизированные рёбра между активами: `domain→subdomain`
  (apex), `host→ip` (resolves), `ip→asn` (announces), `netblock∋ip` (contains,
  через stdlib `ipaddress`), `endpoint→host` (serves). Соседи актива —
  `asset_neighbors`.
- **Exposure Intelligence** — кластеры общей инфраструктуры: host-активы,
  делящие один IP / ASN / netblock («12 субдоменов резолвятся в один IP» =
  single point of exposure, blast radius на уровне активов, независимо от
  находок). `shared_infra`, worst-first по числу активов.
- Поверхности: карточка **Asset Relationships** в HTML-отчёте, web
  `/correlation` (поле `asset_graph`), метрика `exposure_clusters` + чип
  «N× co-hosted» в Executive Headline (**display-метрика**, не слагаемое
  risk-score — finding-концентрацию уже считает F-R4).

Дополняет finding-центричную корреляцию (`core/correlation.py`: Finding→Asset→
Infra, «Exposure by Asset»), не дублируя её — это asset-центричный слой.

### Тренды риска и история изменений (по проектам)

Платформа ведёт историю каждого проекта между сканами:

- **История изменений** — лента событий (`core/timeline.py`: новый секрет/находка,
  рост риска, изменение сертификата, новый CVE, OSINT-discovery…) из Scan Diff +
  Findings + Asset Inventory. Видна на вкладке Timeline, в web `/timeline` и
  экспортируется (`report_export.timeline_csv`).
- **Тренды риска** — метрик-серия по сканам (risk score / attack surface / secrets /
  high) рисуется sparkline'ами в HTML-отчёте (карточка Trends) и на вкладке Overview.
- **Аналитика тренда** (`core/trends.py`, derive-on-read поверх серии): по каждой
  метрике — направление (рост/спад/стабильно), значение vs первый скан, дельта,
  пик/минимум. Карточка Trends показывает вердикт «Риск: ↑ рост (4 → 12, +8 с
  первого скана)»; web `/timeline` отдаёт сводку `trend`; в портфолио у проекта —
  `risk_trend` (направление за всю историю, рядом с `risk_delta` = vs прошлый скан).
- **Экспорт risk-истории** — `report_export.history_csv` (одна строка на скан).

## Внешние плагины (вкладки)

Вкладки строятся из реестра `PluginManager`, а не захардкоженного списка. Можно
добавить свою вкладку, положив `*.py` в `plugins/` — без правки кода ядра.
Контракт и пример — [`plugins/README.md`](plugins/README.md).

### Analyzer-плагины

Помимо вкладок, можно подключить **аналитические плагины**: класс с `name` и
`run(self, results)`, который разбирает агрегированный отчёт Full Collection и
возвращает дополнительные findings (они вливаются в risk score, Executive
Summary и граф атак-поверхности). Положите `*.py` в `plugins/analyzers/` —
контракт и пример в [`plugins/analyzers/README.md`](plugins/analyzers/README.md).
Найденные плагины видны во вкладке **System**.

## Тесты

```bash
pip install -r requirements-dev.txt
pytest
```

Набор сетенезависимый (Qt в headless-режиме `offscreen`) и покрывает чистую
логику: cookie-скоринг, разрешение формата видео, нормализацию URL/srcset,
реестр плагинов и дискавери, кооперативную отмену и рендер отчёта.

## Сборка .exe (PyInstaller)

```bash
pip install pyinstaller
pyinstaller build.spec --clean --noconfirm
```
