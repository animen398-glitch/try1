"""core/analyzer_plugins.py
Analyzer Plugin SDK — user-supplied post-analysis plugins.

This is a *second, deliberately small* extension point that mirrors the
tab-PluginManager's discovery contract but serves a different purpose: instead
of adding UI tabs, an analyzer plugin inspects the aggregated collection
``results`` and returns extra findings. Keeping the same discovery shape (and
the same isolation guarantees) avoids inventing an unfamiliar mechanism.

Contract — a plugin is a class:

    class AnalyzerPlugin:
        name = "my-analyzer"
        def run(self, results: dict) -> dict:
            # inspect the aggregated collection report; return findings/data
            return {"findings": [
                {"severity": "Info", "title": "...", "detail": "..."},
            ]}

Drop a module in ``plugins/analyzers/`` exposing one of (priority order):
``register_analyzers(registry)``, ``ANALYZER_PLUGINS`` (iterable) or
``ANALYZER_PLUGIN`` (single) — each a plugin instance or class. Plugins are
isolated: a module that fails to import, or a plugin that raises at run time, is
recorded and skipped — it never crashes a collection.
"""

import importlib.util
from pathlib import Path
from typing import Callable, Dict, List, Optional, Union

# A finding must look like this to be merged into the report's vuln findings.
_VALID_SEVERITIES = {'High', 'Medium', 'Info'}


class AnalyzerPlugin:
    """Base class for analysis plugins. Subclass and override ``run``."""

    name: str = 'unnamed-analyzer'

    def run(self, results: Dict) -> Dict:  # noqa: D401
        """Inspect ``results`` and return a dict (optionally with 'findings')."""
        return {}


class AnalyzerRegistry:
    """Ordered registry of analyzer plugins (instances)."""

    def __init__(self) -> None:
        self._plugins: List[AnalyzerPlugin] = []

    def register(self, plugin: Union[AnalyzerPlugin, type]) -> None:
        """Register a plugin instance or class (classes are instantiated)."""
        if isinstance(plugin, type):
            plugin = plugin()
        if not hasattr(plugin, 'run') or not callable(plugin.run):
            raise TypeError('analyzer plugin must define a callable run(results)')
        if not getattr(plugin, 'name', None):
            raise ValueError('analyzer plugin must define a non-empty name')
        self._plugins.append(plugin)

    def names(self) -> List[str]:
        return [p.name for p in self._plugins]

    def __iter__(self):
        return iter(self._plugins)

    def __len__(self) -> int:
        return len(self._plugins)


def _load_module(path: Path):
    spec = importlib.util.spec_from_file_location(f"saa_analyzer_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load analyzer plugin from {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def discover_analyzers(directory: Union[str, Path],
                       on_error: Optional[Callable[[str, Exception], None]] = None
                       ) -> List[AnalyzerPlugin]:
    """Import analyzer plugins from ``directory`` and return the instances.

    Every top-level ``*.py`` (excluding ``_``-prefixed) is imported in filename
    order and may register plugins via ``register_analyzers(registry)``,
    ``ANALYZER_PLUGINS`` or ``ANALYZER_PLUGIN``. A broken module is skipped and
    reported through ``on_error(filename, exc)`` — never fatal.
    """
    directory = Path(directory)
    registry = AnalyzerRegistry()
    if not directory.is_dir():
        return []

    for path in sorted(directory.glob('*.py')):
        if path.name.startswith('_'):
            continue
        before = len(registry)
        try:
            module = _load_module(path)
            if hasattr(module, 'register_analyzers') and callable(module.register_analyzers):
                module.register_analyzers(registry)
            elif hasattr(module, 'ANALYZER_PLUGINS'):
                for plugin in module.ANALYZER_PLUGINS:
                    registry.register(plugin)
            elif hasattr(module, 'ANALYZER_PLUGIN'):
                registry.register(module.ANALYZER_PLUGIN)
            else:
                raise AttributeError(
                    'analyzer plugin must define register_analyzers(registry), '
                    'ANALYZER_PLUGIN or ANALYZER_PLUGINS')
        except Exception as e:  # noqa: BLE001 — isolate untrusted plugin code
            del registry._plugins[before:]   # roll back partial registration
            if on_error is not None:
                on_error(path.name, e)
            continue
    return list(registry)


def _clean_findings(raw, default_source: str) -> List[Dict]:
    """Keep only well-formed findings; tag each with its source plugin."""
    out: List[Dict] = []
    if not isinstance(raw, list):
        return out
    for f in raw:
        if not isinstance(f, dict):
            continue
        title = f.get('title')
        severity = f.get('severity')
        if not title or severity not in _VALID_SEVERITIES:
            continue
        out.append({
            'severity': severity,
            'title': str(title),
            'detail': str(f.get('detail', '')),
            'source': f.get('source') or default_source,
        })
    return out


def run_analyzers(analyzers: List[AnalyzerPlugin], results: Dict) -> Dict:
    """Run each analyzer over ``results``; aggregate findings and errors.

    Returns ``{'results': {name: output}, 'findings': [...], 'errors': [...]}``.
    A plugin that raises is recorded in ``errors`` and skipped.
    """
    by_name: Dict[str, Dict] = {}
    findings: List[Dict] = []
    errors: List[Dict] = []
    for plugin in analyzers:
        name = getattr(plugin, 'name', plugin.__class__.__name__)
        try:
            output = plugin.run(results)
        except Exception as e:  # noqa: BLE001 — one bad plugin must not abort
            errors.append({'plugin': name, 'error': str(e)})
            continue
        if not isinstance(output, dict):
            output = {}
        by_name[name] = output
        findings.extend(_clean_findings(output.get('findings'), default_source=name))
    return {'results': by_name, 'findings': findings, 'errors': errors}
