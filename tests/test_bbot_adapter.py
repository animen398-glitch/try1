"""Offline tests for the optional BBOT external-recon adapter (EXT-OSINT F1 T1.3).

No real binary or network: the parser is pure and the runner's subprocess seam +
availability probe are injected with canned NDJSON.
"""

import json

from core import bbot_adapter


def _line(**kw) -> str:
    return json.dumps(kw)


# A representative NDJSON stream covering every ingested type, scope filtering,
# the two finding tiers, defensive data shapes and ignored OSINT events.
_SAMPLE = "\n".join([
    "not json — log noise",                                   # skipped
    _line(type="DNS_NAME", data="www.evilcorp.com", scope_distance=0),
    _line(type="DNS_NAME", data="api.evilcorp.com", scope_distance=0),
    _line(type="DNS_NAME", data="WWW.evilcorp.com", scope_distance=0),  # dup (case)
    _line(type="DNS_NAME", data="partner.example.net", scope_distance=2),  # affiliate
    _line(type="IP_ADDRESS", data="1.2.3.4", scope_distance=0),
    _line(type="IP_RANGE", data="1.2.3.0/24", scope_distance=0),
    _line(type="ASN", data="AS12345", scope_distance=0),
    _line(type="TECHNOLOGY",
          data={"technology": "nginx", "version": "1.24.0"}, scope_distance=0),
    _line(type="URL", data="https://www.evilcorp.com/login", scope_distance=0),
    _line(type="URL_UNVERIFIED", data="https://www.evilcorp.com/admin",
          scope_distance=0),
    _line(type="VULNERABILITY",
          data={"description": "SQL injection in /search", "severity": "HIGH",
                "url": "https://www.evilcorp.com/search"},
          host="www.evilcorp.com", module="bbot", scope_distance=0),
    _line(type="FINDING",
          data={"description": "Interesting header exposed"},
          host="api.evilcorp.com", scope_distance=0),
    _line(type="EMAIL_ADDRESS", data="ceo@evilcorp.com", scope_distance=0),  # ignored
])


def test_parse_buckets_and_scope_filtering():
    out = bbot_adapter.parse_bbot_jsonl(_SAMPLE)
    # in-scope hosts de-duped case-insensitively; the distance-2 affiliate dropped
    assert out["hosts"] == ["www.evilcorp.com", "api.evilcorp.com"]
    assert out["ips"] == ["1.2.3.4"]
    assert out["netblocks"] == ["1.2.3.0/24"]
    assert out["asns"] == ["AS12345"]
    assert out["technologies"] == [{"name": "nginx", "version": "1.24.0"}]
    # endpoints carry the unverified flag only for URL_UNVERIFIED
    assert {"url": "https://www.evilcorp.com/login"} in out["endpoints"]
    assert {"url": "https://www.evilcorp.com/admin",
            "unverified": True} in out["endpoints"]


def test_parse_stats():
    stats = bbot_adapter.parse_bbot_jsonl(_SAMPLE)["stats"]
    assert stats["affiliates_skipped"] == 1          # the distance-2 host
    assert stats["in_scope"] >= 9
    # the EMAIL_ADDRESS event is outside scope vocabulary → not even counted
    assert stats["events"] == stats["in_scope"] + stats["affiliates_skipped"]


def test_parse_findings_severity_tiers():
    findings = bbot_adapter.parse_bbot_jsonl(_SAMPLE)["findings"]
    vuln = next(f for f in findings if "SQL injection" in f["title"])
    finding = next(f for f in findings if "Interesting header" in f["title"])
    # vuln-phase scale is VulnScanner's 3 buckets (High/Medium/Info), so a folded
    # BBOT finding counts in summarize/risk like nuclei/OSV do.
    assert vuln["severity"] == "High" and vuln["source"] == "bbot"
    assert vuln["location"] == "https://www.evilcorp.com/search"
    # a FINDING is the less-confirmed tier → Info regardless of any severity
    assert finding["severity"] == "Info"


def test_parse_finding_flows_through_findings_adapter():
    # The emitted raw dict must be consumable unchanged by the unified adapter,
    # and a CVE in the text must canonicalize to the cross-scanner identity.
    from core import findings_adapter
    raw = bbot_adapter.parse_bbot_jsonl(
        _line(type="VULNERABILITY",
              data={"description": "Outdated lib CVE-2021-44228",
                    "severity": "CRITICAL"},
              host="x.evilcorp.com", scope_distance=0))["findings"][0]
    # CRITICAL collapses to the vuln scale's 'High' (same as a critical nuclei/OSV
    # finding — the 3-level contract); from_raw keeps the raw label, normalizing
    # to lowercase only at to_store() time.
    f = findings_adapter.from_raw(raw)
    assert f.severity == "High"
    assert f.to_store()["severity"] == "high"
    assert f.category == "vuln" and f.rule_id == "cve-2021-44228"


def test_parse_tolerates_malformed_and_missing_fields():
    stream = "\n".join([
        "",                                              # blank
        "plain text line",                               # non-JSON
        "{not valid json",                               # broken JSON
        json.dumps([1, 2, 3]),                           # JSON, but not a dict
        _line(type="DNS_NAME"),                          # no data/host → dropped
        _line(data="orphan"),                            # no type → skipped
        _line(type="IP_ADDRESS", data="9.9.9.9", scope_distance=0),
    ])
    out = bbot_adapter.parse_bbot_jsonl(stream)
    assert out["ips"] == ["9.9.9.9"]
    assert out["hosts"] == []


def test_scalar_reads_dict_and_host_fallback():
    # data as a dict → primary scalar key; otherwise top-level host.
    out = bbot_adapter.parse_bbot_jsonl("\n".join([
        _line(type="IP_ADDRESS", data={"ip": "5.5.5.5"}, scope_distance=0),
        _line(type="DNS_NAME", data={"unknown": "x"}, host="fallback.evilcorp.com",
              scope_distance=0),
    ]))
    assert out["ips"] == ["5.5.5.5"]
    assert out["hosts"] == ["fallback.evilcorp.com"]


def test_build_command_safe_passive_default():
    cmd = bbot_adapter.build_command("evilcorp.com")
    assert cmd[:5] == ["bbot", "-t", "evilcorp.com", "-p", "subdomain-enum"]
    assert "-rf" in cmd and "passive" in cmd
    assert "--strict-scope" in cmd
    assert cmd[cmd.index("-om") + 1] == "json"
    assert "--silent" in cmd


def test_build_command_active_and_extra_args():
    cmd = bbot_adapter.build_command("x.com", passive=False,
                                     extra_args=["-y", "--foo"])
    assert "-rf" not in cmd                       # passive restriction omitted
    assert cmd[-2:] == ["-y", "--foo"]


def test_runner_unavailable_degrades():
    r = bbot_adapter.BBOTRunner(detector=lambda: False)
    res = r.run("evilcorp.com")
    assert res["status"] == "Unavailable"
    assert "not installed" in res["error"]


def test_runner_success_with_injected_output():
    calls = []

    def fake_run(cmd, timeout, input_text=None):
        calls.append(cmd)
        return {"rc": 0, "stdout": _SAMPLE, "stderr": "", "timed_out": False}

    r = bbot_adapter.BBOTRunner(detector=lambda: True, runner=fake_run)
    res = r.run("evilcorp.com")
    assert res["status"] == "Success"
    assert res["data"]["ips"] == ["1.2.3.4"]
    assert len(res["data"]["findings"]) == 2
    assert res["truncated"] is False
    # the safe-passive contract was actually used
    assert "--strict-scope" in calls[0] and "json" in calls[0]


def test_runner_error_path():
    def fake_run(cmd, timeout, input_text=None):
        return {"rc": None, "stdout": "", "stderr": "", "timed_out": False,
                "error": "binary not found on PATH"}

    r = bbot_adapter.BBOTRunner(detector=lambda: True, runner=fake_run)
    res = r.run("evilcorp.com")
    assert res["status"] == "Error" and "binary not found" in res["error"]


def test_runner_nonzero_exit_is_error():
    logs = []

    def fake_run(cmd, timeout, input_text=None):
        return {"rc": 2, "stdout": "", "stderr": "invalid preset",
                "timed_out": False}

    r = bbot_adapter.BBOTRunner(detector=lambda: True, runner=fake_run)
    r.set_progress_callback(logs.append)
    res = r.run("evilcorp.com")
    assert res["status"] == "Error"
    assert "invalid preset" in res["error"]
    assert any("failed" in line and "invalid preset" in line for line in logs)
