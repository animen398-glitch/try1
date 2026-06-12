"""Analyzer Plugin SDK — registry, discovery, isolation and collection merge."""

from core.analyzer_plugins import (
    AnalyzerPlugin, AnalyzerRegistry, discover_analyzers, run_analyzers,
)
from core.collection_runner import CollectionRunner


class _Good(AnalyzerPlugin):
    name = 'good'

    def run(self, results):
        return {'findings': [
            {'severity': 'High', 'title': 'boom', 'detail': 'd'}]}


# ── AnalyzerRegistry ────────────────────────────────────────────────────────

def test_registry_accepts_class_or_instance():
    reg = AnalyzerRegistry()
    reg.register(_Good)              # class → instantiated
    reg.register(_Good())           # instance
    assert reg.names() == ['good', 'good']
    assert len(reg) == 2


def test_registry_rejects_invalid_plugins():
    reg = AnalyzerRegistry()

    class NoRun:
        name = 'x'
    try:
        reg.register(NoRun())
        assert False, "should reject plugin without run()"
    except TypeError:
        pass

    class NoName(AnalyzerPlugin):
        name = ''
    try:
        reg.register(NoName)
        assert False, "should reject plugin without a name"
    except ValueError:
        pass


# ── run_analyzers ───────────────────────────────────────────────────────────

def test_run_aggregates_and_tags_findings():
    agg = run_analyzers([_Good()], {'phases': {}})
    assert len(agg['findings']) == 1
    f = agg['findings'][0]
    assert f['title'] == 'boom'
    assert f['source'] == 'good'        # tagged with the plugin name
    assert agg['errors'] == []
    assert 'good' in agg['results']


def test_run_isolates_crashing_plugin():
    class Boom(AnalyzerPlugin):
        name = 'boom'

        def run(self, results):
            raise RuntimeError('kaboom')

    agg = run_analyzers([Boom(), _Good()], {})
    # The crash is recorded; the healthy plugin still contributes.
    assert agg['errors'] == [{'plugin': 'boom', 'error': 'kaboom'}]
    assert len(agg['findings']) == 1


def test_run_drops_malformed_findings():
    class Messy(AnalyzerPlugin):
        name = 'messy'

        def run(self, results):
            return {'findings': [
                {'severity': 'Critical', 'title': 'bad-sev'},   # invalid severity
                {'severity': 'Info'},                            # no title
                'not-a-dict',
                {'severity': 'Medium', 'title': 'ok'},           # valid
            ]}

    agg = run_analyzers([Messy()], {})
    assert [f['title'] for f in agg['findings']] == ['ok']


def test_run_tolerates_non_dict_output():
    class Weird(AnalyzerPlugin):
        name = 'weird'

        def run(self, results):
            return None

    agg = run_analyzers([Weird()], {})
    assert agg['findings'] == []
    assert agg['results']['weird'] == {}


# ── discovery (filesystem) ──────────────────────────────────────────────────

def test_discover_loads_plugins(tmp_path):
    (tmp_path / 'a_plugin.py').write_text(
        "from core.analyzer_plugins import AnalyzerPlugin\n"
        "class A(AnalyzerPlugin):\n"
        "    name = 'disk-analyzer'\n"
        "    def run(self, results): return {'findings': []}\n"
        "ANALYZER_PLUGIN = A\n",
        encoding='utf-8')
    plugins = discover_analyzers(tmp_path)
    assert [p.name for p in plugins] == ['disk-analyzer']


def test_discover_isolates_broken_module(tmp_path):
    (tmp_path / 'broken.py').write_text("raise RuntimeError('bad import')\n",
                                        encoding='utf-8')
    (tmp_path / 'fine.py').write_text(
        "from core.analyzer_plugins import AnalyzerPlugin\n"
        "class B(AnalyzerPlugin):\n"
        "    name = 'fine'\n"
        "    def run(self, results): return {}\n"
        "ANALYZER_PLUGIN = B\n",
        encoding='utf-8')
    errors = []
    plugins = discover_analyzers(tmp_path, on_error=lambda n, e: errors.append(n))
    assert [p.name for p in plugins] == ['fine']
    assert errors == ['broken.py']


def test_discover_skips_underscore_and_missing_dir(tmp_path):
    (tmp_path / '_helper.py').write_text("x = 1\n", encoding='utf-8')
    assert discover_analyzers(tmp_path) == []
    assert discover_analyzers(tmp_path / 'nope') == []


# ── collection integration ──────────────────────────────────────────────────

def test_collection_phase_merges_findings(monkeypatch):
    import core.collection_runner as cr
    monkeypatch.setattr(cr, 'discover_analyzers', lambda d, on_error=None: [_Good()])

    runner = CollectionRunner()
    report = {'phases': {'vulns': {
        'status': 'Success',
        'findings': [{'severity': 'Info', 'title': 'native'}],
        'summary': {'high': 0, 'medium': 0, 'info': 1, 'total': 1, 'risk_score': 1},
    }}}
    phase = runner._phase_analyzers(report)
    assert phase['status'] == 'Success'
    assert phase['findings_added'] == 1
    # Folded into vulns → summary recomputed (now 1 High).
    vulns = report['phases']['vulns']
    assert len(vulns['findings']) == 2
    assert vulns['summary']['high'] == 1
    assert vulns['summary']['risk_score'] == 6   # High(5) + Info(1)


def test_collection_phase_skipped_without_plugins(monkeypatch):
    import core.collection_runner as cr
    monkeypatch.setattr(cr, 'discover_analyzers', lambda d, on_error=None: [])
    phase = CollectionRunner()._phase_analyzers({'phases': {}})
    assert phase['status'] == 'Skipped'
