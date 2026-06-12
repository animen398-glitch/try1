"""EndpointIndex — URL normalization and dedup/aggregation."""

from utils.endpoint_index import EndpointIndex


def test_normalize_absolute_lowercases_host_keeps_path_case():
    assert EndpointIndex.normalize(
        "https://API.Example.com/v1/Users/") == "https://api.example.com/v1/Users"


def test_normalize_strips_query_and_fragment():
    assert EndpointIndex.normalize("https://x.com/a?b=1#c") == "https://x.com/a"


def test_normalize_root_path_preserved():
    assert EndpointIndex.normalize("https://example.com/") == "https://example.com/"


def test_normalize_relative_path_trailing_slash():
    assert EndpointIndex.normalize("/api/v1/") == "/api/v1"


def test_normalize_empty_and_whitespace():
    assert EndpointIndex.normalize("") == ""
    assert EndpointIndex.normalize("   ") == ""


class _FakeRegistry:
    def __init__(self, records):
        self._records = records

    def get_records(self, data_type=None, limit=0):
        return list(self._records)


def test_get_unique_endpoints_aggregates_and_sorts():
    records = [
        {"content": "https://x.com/api/a", "source": "p1",
         "metadata": {"pattern": "api_endpoint"}},
        {"content": "https://x.com/api/a/", "source": "p2",
         "metadata": {"pattern": "api_endpoint"}},   # same after normalize
        {"content": "https://x.com/api/b", "source": "p1", "metadata": {}},
    ]
    idx = EndpointIndex(registry=_FakeRegistry(records))
    unique = idx.get_unique_endpoints()

    # /api/a seen twice from two sources, sorts first by count.
    assert unique[0]["endpoint"] == "https://x.com/api/a"
    assert unique[0]["count"] == 2
    assert unique[0]["source_count"] == 2
    assert unique[0]["patterns"] == ["api_endpoint"]
    assert len(unique) == 2


def test_get_summary_counts_records_and_unique():
    records = [
        {"content": "https://x.com/api/a", "source": "p1", "metadata": {}},
        {"content": "https://x.com/api/a/", "source": "p1", "metadata": {}},
        {"content": "", "source": "p1", "metadata": {}},   # dropped
    ]
    idx = EndpointIndex(registry=_FakeRegistry(records))
    summary = idx.get_summary()
    assert summary == {"total_records": 2, "unique_endpoints": 1}
