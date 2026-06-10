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

A plugin that raises while loading is skipped (never crashes the app); the
failing filename is shown briefly in the status bar.

## Quick start

Copy `example_tab.py.example` to `example_tab.py` and restart the app — a new
**"Example Plugin"** tab appears.
