"""Offline tests for the optional lift document provider (EXT-OSINT F2 T2.4).

No real model/GPU/network: the subprocess seam writes canned JSON into lift's
output dir, and the availability probe is injected.
"""

import json
import os

from core.document_providers import lift_adapter as la

_AWS = "AKIAIOSFODNN7EXAMPLE"


def test_available_delegates_to_features(monkeypatch):
    monkeypatch.setattr(la, "has_lift", lambda: True)
    assert la.LiftRunner().available() is True
    monkeypatch.setattr(la, "has_lift", lambda: False)
    assert la.LiftRunner().available() is False


def test_build_command_shape():
    cmd = la.build_command("in.pdf", "/out", "/s.json")
    assert cmd[0] == "lift_extract"
    assert "in.pdf" in cmd and "/out" in cmd
    assert cmd[cmd.index("--schema") + 1] == "/s.json"


def test_parse_output_secrets_and_sensitive():
    payload = {
        "secrets": [
            {"type": "AWS Access Key", "value": _AWS},
            {"type": "Generic API Key", "value": "your_api_key_here_xx"},  # drop
        ],
        "sensitive_data": [
            {"title": "SSN", "detail": "social security number", "severity": "high"},
            {"title": "", "detail": "ignored — no title"},
        ],
    }
    findings = la.parse_output(payload, "https://x.com/doc.pdf")
    secrets = [f for f in findings if f["category"] == "secret"]
    sensitive = [f for f in findings if f["category"] == "vuln"]
    assert len(secrets) == 1                      # placeholder dropped
    assert secrets[0]["source"] == "document"
    assert _AWS not in str(secrets[0])            # masked, no plaintext
    assert len(sensitive) == 1                    # empty-title item dropped
    assert sensitive[0]["severity"] == "High" and "SSN" in sensitive[0]["title"]


def test_parse_output_tolerates_garbage():
    assert la.parse_output({}, "loc") == []
    assert la.parse_output({"secrets": ["nope", 1], "sensitive_data": [None]},
                           "loc") == []
    assert la.parse_output("not a dict", "loc") == []


def test_runner_unavailable_degrades():
    r = la.LiftRunner(detector=lambda: False)
    res = r.extract("doc.pdf")
    assert res["status"] == "Unavailable" and "not installed" in res["error"]


def test_runner_success_reads_output_dir(monkeypatch):
    payload = {"secrets": [{"type": "AWS Access Key", "value": _AWS}],
               "sensitive_data": []}

    def fake_run(cmd, timeout, input_text=None):
        # lift writes its JSON into the output dir (the arg before --schema's pair)
        out_dir = cmd[2]
        with open(os.path.join(out_dir, "result.json"), "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
        return {"rc": 0, "stdout": "", "stderr": "", "timed_out": False}

    r = la.LiftRunner(detector=lambda: True, runner=fake_run)
    res = r.extract("doc.pdf", location="https://x.com/doc.pdf")
    assert res["status"] == "Success"
    assert len(res["findings"]) == 1
    assert res["findings"][0]["location"] == "https://x.com/doc.pdf"


def test_runner_falls_back_to_stdout(monkeypatch):
    payload = {"secrets": [{"type": "Stripe Secret",
                            "value": "sk_live_" + "a" * 30}]}

    def fake_run(cmd, timeout, input_text=None):
        return {"rc": 0, "stdout": json.dumps(payload), "stderr": "",
                "timed_out": False}

    r = la.LiftRunner(detector=lambda: True, runner=fake_run)
    res = r.extract("doc.pdf")
    assert res["status"] == "Success" and len(res["findings"]) == 1


def test_runner_error_path():
    def fake_run(cmd, timeout, input_text=None):
        return {"rc": None, "stdout": "", "stderr": "", "timed_out": False,
                "error": "binary not found on PATH"}

    r = la.LiftRunner(detector=lambda: True, runner=fake_run)
    res = r.extract("doc.pdf")
    assert res["status"] == "Error" and "binary not found" in res["error"]


def test_runner_cleans_temp_dir(monkeypatch):
    seen = {}

    def fake_run(cmd, timeout, input_text=None):
        seen["out_dir"] = cmd[2]
        return {"rc": 0, "stdout": "{}", "stderr": "", "timed_out": False}

    r = la.LiftRunner(detector=lambda: True, runner=fake_run)
    r.extract("doc.pdf")
    # the temp output dir (which could hold plaintext) is deleted after parsing
    assert not os.path.exists(seen["out_dir"])
