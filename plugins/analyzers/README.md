# Analyzer plugins

Drop-in **post-analysis** plugins. Unlike the tab plugins in the parent
`plugins/` folder (which add GUI tabs), an analyzer plugin inspects the
aggregated **Full Collection** report and returns extra findings — those fold
into the report's vulnerabilities, and therefore into the risk score, the
Executive Summary and the Attack Surface graph.

## Contract

A plugin is a class with a `name` and a `run(self, results) -> dict`:

```python
from core.analyzer_plugins import AnalyzerPlugin

class MyAnalyzer(AnalyzerPlugin):
    name = "my-analyzer"

    def run(self, results: dict) -> dict:
        # results = {url, domain, phases: {recon, api, capture, cookies, vulns, ...}}
        return {"findings": [
            {"severity": "Info", "title": "...", "detail": "..."},
        ]}

ANALYZER_PLUGIN = MyAnalyzer        # or ANALYZER_PLUGINS = [...], or register_analyzers(registry)
```

Findings must have `severity` in `High|Medium|Info` and a non-empty `title`;
malformed entries are dropped. Each finding is tagged with `source = <plugin name>`.

## Discovery & isolation

Every top-level `*.py` here (excluding `_`-prefixed) is imported in filename
order. A module exposes plugins via, in priority order:

- `register_analyzers(registry)` — call `registry.register(plugin_or_class)`;
- `ANALYZER_PLUGINS` — an iterable of plugin instances/classes;
- `ANALYZER_PLUGIN` — a single instance/class.

A module that fails to import — or a plugin that raises in `run` — is recorded
and skipped. A broken plugin never crashes a collection.

Discovered plugins are listed in the **System** tab. See
[`example_analyzer.py.example`](example_analyzer.py.example).
