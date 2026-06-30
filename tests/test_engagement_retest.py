"""core/engagement_retest.py — engagement retest view (offline)."""

import json

from core import engagement as eng
from core import engagement_retest as er
from core.findings_adapter import Finding
from core.findings_store import FindingsStore


def _finding(rule_id, location, *, status=None):
    fs = FindingsStore()
    fid = fs.upsert("shop.io", Finding(
        category="vuln", rule_id=rule_id, title=f"f-{rule_id}", severity="high",
        location=location).to_store(), scan_id="s1")["finding"]["id"]
    if status:
        fs.set_status(fid, status)
    return fid


def test_retest_classifies_outcomes():
    fixed = _finding("r1", "https://shop.io/1", status="FIXED")
    open_ = _finding("r2", "https://shop.io/2")                 # OPEN
    accepted = _finding("r3", "https://shop.io/3", status="FALSE_POSITIVE")
    e = eng.create_engagement("Acme", "shop.io")
    for fid in (fixed, open_, accepted):
        e = eng.link_finding(e, fid)
    e = eng.link_finding(e, "ghost-finding")                    # missing

    out = er.build_retest(e)
    by_id = {f["finding_id"]: f for f in out["findings"]}
    assert by_id[fixed]["outcome"] == "fixed"
    assert by_id[open_]["outcome"] == "open"
    assert by_id[accepted]["outcome"] == "accepted"
    assert by_id["ghost-finding"]["outcome"] == "missing"
    assert out["summary"] == {"total": 4, "fixed": 1, "open": 1,
                              "accepted": 1, "missing": 1}


def test_retest_renderers():
    fid = _finding("r1", "https://shop.io/1", status="FIXED")
    e = eng.link_finding(eng.create_engagement("Acme Corp", "shop.io"), fid)
    out = er.build_retest(e)
    md = er.render_markdown(out)
    assert md.startswith("# Engagement Retest ")
    assert "Fixed: 1" in md
    assert json.loads(er.render_json(out))["summary"]["fixed"] == 1


def test_retest_empty():
    e = eng.create_engagement("Acme", "shop.io")
    out = er.build_retest(e)
    assert out["summary"]["total"] == 0
    assert "No findings linked" in er.render_markdown(out)
