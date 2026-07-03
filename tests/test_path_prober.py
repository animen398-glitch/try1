"""Offline tests for the path prober (Roadmap E5 increment 2)."""

from core.path_prober import classify_status, probe_paths


# --- classify_status ---------------------------------------------------------

def test_classify_found_for_2xx_3xx():
    assert classify_status(200) == "found"
    assert classify_status(301) == "found"
    assert classify_status(399) == "found"


def test_classify_protected_for_auth_gated():
    assert classify_status(401) == "protected"
    assert classify_status(403) == "protected"


def test_classify_absent_for_404_410():
    assert classify_status(404) == "absent"
    assert classify_status(410) == "absent"


def test_classify_other_and_error():
    assert classify_status(500) == "other"
    assert classify_status(None) == "error"
    assert classify_status("nonsense") == "error"


# --- probe_paths -------------------------------------------------------------

def _fetch_map(mapping):
    return lambda url: mapping.get(url)


def test_probe_paths_classifies_and_collects_found():
    base = "https://x.com"
    mapping = {
        "https://x.com/robots.txt": 200,
        "https://x.com/wp-login.php": 403,
        "https://x.com/missing": 404,
    }
    out = probe_paths(base, ["/robots.txt", "/wp-login.php", "/missing"],
                      fetch=_fetch_map(mapping))
    assert out["summary"]["probed"] == 3
    assert out["summary"]["present"] == 2
    found = {r["path"] for r in out["found"]}
    assert found == {"/robots.txt", "/wp-login.php"}
    assert out["summary"]["by_state"]["absent"] == 1


def test_probe_paths_records_transport_error_and_continues():
    def boom(url):
        if url.endswith("/boom"):
            raise RuntimeError("connection reset")
        return 200

    out = probe_paths("https://x.com", ["/boom", "/ok"], fetch=boom)
    states = {r["path"]: r["state"] for r in out["results"]}
    assert states["/boom"] == "error"
    assert states["/ok"] == "found"
    assert out["summary"]["present"] == 1


def test_probe_paths_max_paths_caps_walk():
    calls = []

    def fetch(url):
        calls.append(url)
        return 200

    out = probe_paths("https://x.com", ["/a", "/b", "/c"], fetch=fetch,
                      max_paths=2)
    assert out["summary"]["probed"] == 2
    assert len(calls) == 2


def test_probe_paths_empty_is_safe():
    out = probe_paths("https://x.com", [], fetch=lambda u: 200)
    assert out["results"] == [] and out["found"] == []
    assert out["summary"]["probed"] == 0
