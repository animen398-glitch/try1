# Advanced Site Analyzer

Десктопный инструмент (Python 3.11+ / PyQt5) для комплексной разведки и анализа
веб-сайтов: пассивная разведка, перечисление субдоменов, перехват динамического
трафика и API-эндпоинтов, обход paywall, захват и оффлайн-клонирование
фронтенда, извлечение медиа, анализ дизайн-системы и аудит безопасности cookie —
всё в одном GUI, с CLI-пайплайном и опциональной web-консолью.

> Назначение — авторизованное тестирование безопасности, исследовательские и
> образовательные задачи. Используйте только на ресурсах, которые вам разрешено
> анализировать.

Текущий статус и план работ — см. [`PROJECT_STATUS.txt`](PROJECT_STATUS.txt).

## Возможности

GUI содержит 14 встроенных вкладок (+ внешний плагин Deep Crawl при установленном Scrapy):

| Вкладка | Назначение |
|---|---|
| Recon & Intel | GeoIP, фингерпринт CMS/стека, фавиконы, PWA-манифест; опц. paywall-bypass, перехват API (Playwright), vuln-scan, дамп API-ответов |
| Subdomain Scanner | Пассивное (crt.sh, HackerTarget, AlienVault OTX, Anubis) + brute-force перечисление с живой таблицей; опц. active-проверки (liveness + takeover) |
| API Key Scanner | Поиск утечек API-ключей/секретов на странице |
| Site Capture | Обход и сохранение HTML-страниц сайта (с отменой) + визуальная карта сайта (дерево путей с HTTP-статусами 2xx/3xx/4xx/5xx) в `site_map.json` и HTML-отчёте |
| Clone Frontend | Скачивание ассетов и переписывание ссылок → самодостаточная оффлайн-копия |
| Video Downloader | yt-dlp: пресеты до 4K (merge через ffmpeg), сессионные cookies |
| Image Extractor | Оригинальное разрешение без водяных знаков; Instagram/соцсети через yt-dlp |
| Design Lab | Извлечение палитры/типографики, сравнение версий |
| Cookie Security Audit | Аудит флагов HttpOnly / Secure / SameSite со скорингом и вердиктом |
| Security Audit | Нативный сканер секретов + source-map (страница и её JS): утечки ключей, эндпоинты, открытые .js.map |
| Final Report & Collection | «Run Full Collection» — прогон всех модулей в единую директорию + HTML/JSON-отчёт (Executive Summary с вердиктом риска и рекомендациями + граф атак-поверхности (SVG) + визуальная карта сайта по HTTP-статусам + опц. скриншот через Playwright + опц. внешний nuclei-скан) |
| Dashboard | Сводка реестра, дедуп API-эндпоинтов, drill-down + Security Overview (вердикт риска / секреты / findings из последнего Full Collection) |
| История операций | Журнал операций пайплайна (SQLite) |
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
