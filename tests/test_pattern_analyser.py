"""PatternAnalyser — pattern matching, dedup, endpoint typing, registry writes."""

from utils.pattern_analyser import PatternAnalyser


class _FakeRegistry:
    def __init__(self):
        self.records = []

    def add_record(self, source, data_type, content, metadata=None):
        self.records.append((source, data_type, content, metadata))


def test_relative_endpoint_typed_as_api_endpoint():
    reg = _FakeRegistry()
    pa = PatternAnalyser(data_registry=reg)
    out = pa.analyze("see /api/v1/users for data", "page1")
    eps = [f for f in out if f["data_type"] == "api_endpoint"]
    assert any(f["match"] == "/api/v1/users" for f in eps)


def test_duplicate_match_recorded_once():
    reg = _FakeRegistry()
    pa = PatternAnalyser(data_registry=reg)
    out = pa.analyze("/api/v1/users and again /api/v1/users", "page1")
    matches = [f for f in out if f["match"] == "/api/v1/users"]
    assert len(matches) == 1
    # And only one registry write for that match.
    assert sum(1 for r in reg.records if r[2] == "/api/v1/users") == 1


def test_custom_pattern_and_context_window():
    reg = _FakeRegistry()
    pa = PatternAnalyser(patterns={"tok": r"TOKEN-\d+"},
                         data_registry=reg, context_chars=5)
    out = pa.analyze("xxxxxTOKEN-42yyyyy", "p")
    assert len(out) == 1
    f = out[0]
    assert f["pattern"] == "tok"
    assert f["data_type"] == "pattern_match"
    assert f["match"] == "TOKEN-42"
    # 5 chars of context on each side.
    assert f["context"] == "xxxxxTOKEN-42yyyyy"


def test_empty_text_returns_no_findings():
    pa = PatternAnalyser(data_registry=_FakeRegistry())
    assert pa.analyze("", "p") == []


def test_registry_failure_does_not_break_analysis():
    class Boom:
        def add_record(self, *a, **k):
            raise RuntimeError("db down")

    pa = PatternAnalyser(patterns={"tok": r"TOKEN-\d+"}, data_registry=Boom())
    out = pa.analyze("TOKEN-1", "p")
    assert out and out[0]["match"] == "TOKEN-1"
