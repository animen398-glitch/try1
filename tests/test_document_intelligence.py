"""Offline tests for the Document Intelligence core (EXT-OSINT F2 T2.3).

Pure/offline: only the always-available stdlib tier is exercised; optional
provider tiers (pdf-text/ocr) are verified via their graceful-degradation path
without installing heavy deps.
"""

from core import document_intelligence as di

# A real-shaped AWS key (validates) and a placeholder generic key (rejected).
_AWS = "AKIAIOSFODNN7EXAMPLE"
_TEXT_WITH_SECRET = f"config\naws_key = {_AWS}\nnote: ok\n"
_TEXT_PLACEHOLDER = 'const api_key = "your_api_key_here_xx";'


def _write(tmp_path, name, content, *, binary=False):
    p = tmp_path / name
    if binary:
        p.write_bytes(content)
    else:
        p.write_text(content, encoding="utf-8")
    return p


def test_file_metadata_basic(tmp_path):
    p = _write(tmp_path, "a.txt", "hello")
    meta = di.file_metadata(p)
    assert meta["name"] == "a.txt" and meta["ext"] == ".txt"
    assert meta["size"] == 5
    assert len(meta["sha256"]) == 64
    assert "error" not in meta


def test_file_metadata_missing_file_degrades(tmp_path):
    meta = di.file_metadata(tmp_path / "nope.txt")
    assert "error" in meta and meta["ext"] == ".txt"


def test_extract_text_stdlib_text_file(tmp_path):
    p = _write(tmp_path, "a.txt", "some text here")
    out = di.extract_text(p)
    assert out["provider"] == "stdlib" and out["status"] == "ok"
    assert "some text" in out["text"]


def test_extract_text_html_strips_tags(tmp_path):
    p = _write(tmp_path, "a.html", "<p>hello <b>world</b></p>")
    out = di.extract_text(p)
    assert "<" not in out["text"]
    assert "hello" in out["text"] and "world" in out["text"]


def test_extract_text_pdf_without_provider_is_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(di, "has_pdf_text", lambda: False)
    p = _write(tmp_path, "a.pdf", b"%PDF-1.4 fake", binary=True)
    out = di.extract_text(p)
    assert out["provider"] == "pdf-text" and out["status"] == "unavailable"
    assert out["text"] == ""


def test_extract_text_image_without_ocr_is_unavailable(tmp_path, monkeypatch):
    monkeypatch.setattr(di, "has_ocr", lambda: False)
    p = _write(tmp_path, "a.png", b"\x89PNG\r\n", binary=True)
    out = di.extract_text(p)
    assert out["provider"] == "ocr" and out["status"] == "unavailable"


def test_extract_text_unsupported_type(tmp_path):
    p = _write(tmp_path, "a.bin", b"\x00\x01\x02", binary=True)
    out = di.extract_text(p)
    assert out["status"] == "unsupported" and out["provider"] == "none"


def test_secret_findings_from_text_detects_and_masks():
    findings = di.secret_findings_from_text(_TEXT_WITH_SECRET, "doc.txt")
    assert len(findings) == 1
    f = findings[0]
    assert f["category"] == "secret" and f["source"] == "document"
    assert f["severity"] == "High" and f["location"] == "doc.txt"
    assert _AWS not in str(f)               # no plaintext leaks into the finding
    assert f["discriminator"]               # non-empty masked discriminator


def test_secret_findings_drops_placeholders():
    assert di.secret_findings_from_text(_TEXT_PLACEHOLDER, "doc.txt") == []


def test_analyze_document_text_with_secret(tmp_path):
    p = _write(tmp_path, "creds.txt", _TEXT_WITH_SECRET)
    doc = di.analyze_document(p, location="https://x.com/creds.txt")
    assert doc["status"] == "ok" and doc["provider"] == "stdlib"
    assert doc["text_chars"] > 0
    assert doc["metadata"]["sha256"]
    assert len(doc["findings"]) == 1
    assert doc["findings"][0]["location"] == "https://x.com/creds.txt"


def test_analyze_document_missing_file_degrades(tmp_path):
    doc = di.analyze_document(tmp_path / "ghost.txt")
    # metadata records the OS error but analysis still returns cleanly (no text)
    assert doc["text_chars"] == 0 and doc["findings"] == []
    assert doc["status"] == "ok"


def test_analyze_documents_batch_summary(tmp_path):
    p1 = _write(tmp_path, "a.txt", _TEXT_WITH_SECRET)
    p2 = _write(tmp_path, "b.txt", "nothing interesting")
    p3 = _write(tmp_path, "c.bin", b"\x00\x01", binary=True)
    out = di.analyze_documents([p1, p2, p3])
    assert out["summary"]["documents"] == 3
    assert out["summary"]["with_text"] == 2      # both .txt decoded; .bin did not
    assert out["summary"]["findings"] == 1       # only a.txt has a real secret
    assert len(out["findings"]) == 1
