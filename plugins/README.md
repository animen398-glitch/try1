# External tab plugins

Drop a Python module in this folder to add a tab to **Advanced Site Analyzer**
without touching the core code. Every top-level `*.py` file here (names not
starting with `_`) is imported at startup, in filename order, **after** the
built-in tabs.

## Plugin contract

A plugin module registers tabs in one of three ways (checked in this order):

1. **`register(manager)`** — a function called with the `PluginManager`:
   ```python
   def register(manager):
       manager.register(TabPlugin("my_id", "My Tab", build_fn))
   ```
2. **`TAB_PLUGINS`** — an iterable of `TabPlugin` objects.
3. **`TAB_PLUGIN`** — a single `TabPlugin`.

A `TabPlugin` is `TabPlugin(id, title, factory)` where:

- `id` — unique string (duplicate ids are rejected),
- `title` — text shown on the tab,
- `factory(window) -> QWidget` — builds the tab widget. `window` is the
  `MainWindow`, so the tab can reuse shared helpers such as `window._run_async`,
  `window._start_task`, `window._set_busy` and `window.settings`.

### Resolving file paths (`window.paths`)

For any file location — a database, a per-domain workspace, a report, scratch
space — use the injected `PathManager` at **`window.paths`** instead of building
paths from the current directory. It keeps a frozen `.exe` writing to a stable,
user-writable location (`%APPDATA%`) rather than next to the executable:

```python
db   = window.paths.get_db_path("my_plugin.db")         # under data/
work = window.paths.get_workspace_path("https://x.com")  # per-domain output dir
rpt  = window.paths.get_reports_path("my_plugin.html")   # under reports/
tmp  = window.paths.get_temp_path()                      # scratch dir
res  = window.paths.get_resource_path("templates/x")     # bundled, read-only
```

Each writable-path helper creates the directory for you. The same instance backs
the built-in tabs and the background task runner, so paths stay consistent across
the whole app.

A plugin that raises while loading is skipped (never crashes the app); the
failing filename is shown briefly in the status bar.

## Quick start

Copy `example_tab.py.example` to `example_tab.py` and restart the app — a new
**"Example Plugin"** tab appears.

## Real example: `scrapy_tab.py`

`scrapy_tab.py` is a shipped, working plugin — the **Deep Crawl (Scrapy)** tab.
It shows the pattern for a heavy, optional third-party tool: a `register()` hook,
a standalone `QWidget` that drives a core backend through `window._run_async`,
and graceful degradation (the module imports even when Scrapy is absent — the
crawl runs in a child process, so nothing here imports `scrapy` directly). It is
auto-discovered at startup like any plugin here.
