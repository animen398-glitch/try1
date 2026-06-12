"""Web console exposes a Security Audit job wired to SecurityAuditor."""

import remote.web_app as wa


def test_security_job_registered():
    assert "security" in wa.JOBS
    spec = wa.JOBS["security"]
    assert spec["label"] == "Security Audit"
    assert callable(spec["fn"])


def test_security_job_runs_offline(monkeypatch):
    # Stub the auditor's only network call so the job is hermetic: a page that
    # leaks an AWS key and references an API endpoint.
    page = ('<html><script>var k="AKIAIOSFODNN7EXAMPLE";'
            'fetch("/api/v1/users")</script></html>')
    monkeypatch.setattr(
        wa.SecurityAuditor, "_fetch",
        lambda self, url: page if url.endswith(("com", "com/")) else None,
    )

    msgs = []
    result = wa.JOBS["security"]["fn"]("https://example.com", msgs.append)

    assert result["status"] == "Success"
    assert result["summary"]["secrets"] >= 1
    assert any("AKIA" in s["match"] for s in result["secrets"])


def test_dashboard_renders_security_summary_metrics():
    # The metrics card must know how to display the audit summary counts.
    assert "data.summary.secrets" in wa._DASHBOARD
