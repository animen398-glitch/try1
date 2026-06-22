"""core/document_intelligence.py
Document Intelligence core — extract data from documents into our lifecycle
(EPIC EXT-OSINT, F2 T2.3).

Pure, offline-first orchestrator over a ladder of optional providers (per the
T2.1 contract). It turns a document (PDF / image / text file already captured in
a scan) into text, then mines that text for credentials using the project's
**single source of truth** for secrets (``secret_scanner`` + ``secret_validator``)
and emits raw finding dicts that flow through the existing pipeline
(``findings_adapter`` → FindingsStore → risk), exactly like the api/security
secret folders. No new data model, no new asset type (a document binds to its
finding via the evidence layer at wiring time — T2.5).

Provider tiers (selected by availability; degrade downward):
  * tier 0 ``stdlib`` — always: file metadata (name/ext/size/sha256/mtime) for
    any file, plus decoded text for text-like formats (txt/json/xml/csv/html…).
  * tier 1 ``pdf-text`` — optional light PDF parser (pypdf / pdfminer / fitz).
  * tier 2 ``ocr`` — optional local OCR for images (pytesseract + tesseract).
  * tier 3 ``lift`` — optional heavy schema→JSON extraction; added in T2.4 as a
    separate provider (NOT here — it never imports into our process).

Invariants: pure/offline (no network), never raises (a bad file degrades to a
status, never sinks a caller), heavy/optional imports are lazy and guarded so the
GUI process never pulls them in. Mirrors the seam style of ``bbot_adapter`` /
``external_tools``.
"""

import hashlib
import os
import re
from typing import Dict, List, Optional

from core.features import has_ocr, has_pdf_text
from core.finding_fingerprint import mask_value, secret_discriminator
from core.secret_scanner import scan_text
from core.secret_validator import INVALID, validate

# Text-like formats tier 0 can decode directly (lower-cased extensions).
TEXT_EXTENSIONS = {
    '.txt', '.md', '.markdown', '.json', '.xml', '.csv', '.tsv', '.html',
    '.htm', '.log', '.yaml', '.yml', '.ini', '.cfg', '.conf', '.env', '.properties',
}
PDF_EXTENSIONS = {'.pdf'}
IMAGE_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.tif', '.tiff', '.webp',
}

# What the 'documents' phase treats as a candidate document to mine. PDFs +
# images + plain config/text/document formats. Deliberately EXCLUDES
# .html/.htm/.json/.xml (markup + our own scan artifacts, already covered by the
# api/security phases) so the phase targets genuine documents, not web text.
DOCUMENT_SCAN_EXTENSIONS = PDF_EXTENSIONS | IMAGE_EXTENSIONS | {
    '.txt', '.md', '.markdown', '.csv', '.tsv', '.log', '.env', '.ini',
    '.cfg', '.conf', '.yaml', '.yml', '.properties',
}

# Read caps — keep a hostile/huge document from eating memory (pure-stdlib tier).
_MAX_TEXT_BYTES = 5 * 1024 * 1024      # decode at most 5 MB of a text file
_HASH_CHUNK = 1024 * 1024

_TAG_RE = re.compile(r'<[^>]+>')
_WS_RE = re.compile(r'[ \t]+')


def file_metadata(path) -> Dict:
    """Metadata for any file: ``{name, ext, size, sha256, mtime}``.

    Always available (tier 0). Never raises — an unreadable file yields whatever
    could be gathered plus an ``error``."""
    p = str(path)
    meta: Dict = {'name': os.path.basename(p),
                  'ext': os.path.splitext(p)[1].lower()}
    try:
        st = os.stat(p)
        meta['size'] = st.st_size
        meta['mtime'] = int(st.st_mtime)
    except OSError as e:
        meta['error'] = str(e)
        return meta
    try:
        h = hashlib.sha256()
        with open(p, 'rb') as fh:
            for chunk in iter(lambda: fh.read(_HASH_CHUNK), b''):
                h.update(chunk)
        meta['sha256'] = h.hexdigest()
    except OSError as e:
        meta['error'] = str(e)
    return meta


def _read_text_file(path) -> str:
    """Decode a text-like file (utf-8, replacement on error), capped."""
    with open(path, 'rb') as fh:
        raw = fh.read(_MAX_TEXT_BYTES)
    text = raw.decode('utf-8', errors='replace')
    ext = os.path.splitext(str(path))[1].lower()
    if ext in ('.html', '.htm'):
        text = _WS_RE.sub(' ', _TAG_RE.sub(' ', text))
    return text


def _extract_pdf_text(path) -> Optional[str]:
    """Best-effort PDF text via whatever light parser is installed (lazy import).
    Returns ``None`` if no parser is available or extraction fails."""
    try:
        import pypdf
        reader = pypdf.PdfReader(str(path))
        return '\n'.join((page.extract_text() or '') for page in reader.pages)
    except Exception:   # noqa: BLE001 — try the next parser / degrade
        pass
    try:
        from pdfminer.high_level import extract_text as _pm_extract
        return _pm_extract(str(path)) or ''
    except Exception:   # noqa: BLE001
        pass
    try:
        import fitz   # PyMuPDF
        with fitz.open(str(path)) as doc:
            return '\n'.join(page.get_text() for page in doc)
    except Exception:   # noqa: BLE001
        return None


def _extract_ocr_text(path) -> Optional[str]:
    """Best-effort OCR of an image (lazy import). ``None`` on any failure."""
    try:
        import pytesseract
        from PIL import Image
        with Image.open(str(path)) as img:
            return pytesseract.image_to_string(img) or ''
    except Exception:   # noqa: BLE001
        return None


def extract_text(path) -> Dict:
    """Extract text from a document via the best available provider tier.

    Returns ``{text, provider, status}`` where ``status`` is ``ok`` (text
    obtained), ``empty`` (provider ran, no text), ``unavailable`` (the optional
    provider for this type is not installed) or ``unsupported`` (no tier handles
    this type). Never raises."""
    ext = os.path.splitext(str(path))[1].lower()
    try:
        if ext in TEXT_EXTENSIONS:
            text = _read_text_file(path)
            return {'text': text, 'provider': 'stdlib',
                    'status': 'ok' if text.strip() else 'empty'}
        if ext in PDF_EXTENSIONS:
            if not has_pdf_text():
                return {'text': '', 'provider': 'pdf-text', 'status': 'unavailable'}
            text = _extract_pdf_text(path)
            if text is None:
                return {'text': '', 'provider': 'pdf-text', 'status': 'unavailable'}
            return {'text': text, 'provider': 'pdf-text',
                    'status': 'ok' if text.strip() else 'empty'}
        if ext in IMAGE_EXTENSIONS:
            if not has_ocr():
                return {'text': '', 'provider': 'ocr', 'status': 'unavailable'}
            text = _extract_ocr_text(path)
            if text is None:
                return {'text': '', 'provider': 'ocr', 'status': 'unavailable'}
            return {'text': text, 'provider': 'ocr',
                    'status': 'ok' if text.strip() else 'empty'}
        return {'text': '', 'provider': 'none', 'status': 'unsupported'}
    except Exception as e:   # noqa: BLE001 — extraction must never raise
        return {'text': '', 'provider': 'none', 'status': 'error', 'error': str(e)}


def secret_finding(ktype, value, location, *,
                   validation: Optional[Dict] = None,
                   source: str = 'document') -> Optional[Dict]:
    """One masked secret finding dict, or ``None`` for a clear placeholder.

    The single constructor for document/config-sourced secret findings (reused by
    the text path, the lift provider and the IaC scanner), so the finding shape
    stays identical to the api/security secret folders: ``category='secret'``, a
    non-leaking ``discriminator`` (vendor + masked prefix + length) and a masked
    detail — no plaintext ever enters the finding. ``source`` tags the producing
    phase (``document`` / ``iac`` …) so the auto-FIX scope-guard ties it to the
    right phase. Pass ``validation`` to reuse a structural check already done (e.g.
    ``scan_text``); otherwise it is computed."""
    value = str(value or '')
    if not value:
        return None
    status = (validation if isinstance(validation, dict)
              else validate(str(ktype), value)).get('status')
    if status == INVALID:
        return None   # placeholder / example value — not a real secret
    ktype = str(ktype)
    return {
        'severity': 'High',
        'title': f'Leaked secret: {ktype}',
        'detail': f'{location} — exposed {ktype} ({mask_value(value)}).',
        'source': source, 'category': 'secret', 'location': str(location),
        'discriminator': secret_discriminator(ktype, value),
    }


def secret_findings_from_text(text: str, location: str, *,
                              source: str = 'document') -> List[Dict]:
    """Raw secret finding dicts for credentials in ``text`` (SSOT-based).

    Runs the single secret rule set (``secret_scanner.scan_text``), drops clear
    placeholders/false-positives via the structural validator already attached to
    each hit, and builds findings via :func:`secret_finding`. ``source`` tags the
    producing phase (default ``document``; the IaC scanner passes ``iac``). De-dup
    across files happens later by fingerprint."""
    out: List[Dict] = []
    for hit in scan_text(text or '', source=location):
        f = secret_finding(hit.get('type', ''), hit.get('match', ''), location,
                           validation=hit.get('validation'), source=source)
        if f:
            out.append(f)
    return out


def analyze_document(path, *, location: Optional[str] = None,
                     scan_secrets: bool = True) -> Dict:
    """Analyse one document: metadata + extracted text + secret findings.

    ``location`` is the identity used on findings (an artifact URL / relative
    path); defaults to ``path``. Never raises — any failure is captured in the
    returned ``status``."""
    loc = location or str(path)
    try:
        meta = file_metadata(path)
        extracted = extract_text(path)
        text = extracted.get('text') or ''
        findings = (secret_findings_from_text(text, loc)
                    if scan_secrets and text else [])
        return {
            'path': str(path), 'location': loc, 'metadata': meta,
            'provider': extracted.get('provider'),
            'text_status': extracted.get('status'),
            'text_chars': len(text),
            'findings': findings,
            'status': 'ok',
        }
    except Exception as e:   # noqa: BLE001 — one bad doc must not sink a batch
        return {'path': str(path), 'location': loc, 'metadata': {},
                'provider': 'none', 'text_status': 'error', 'text_chars': 0,
                'findings': [], 'status': 'error', 'error': str(e)}


def iter_candidate_documents(roots, *, limit: int = 300,
                             max_size: int = 20 * 1024 * 1024) -> List[str]:
    """Walk ``roots`` and collect candidate document files to mine.

    Only files whose extension is in :data:`DOCUMENT_SCAN_EXTENSIONS`, under the
    per-file ``max_size`` cap, de-duplicated by real path, capped at ``limit``.
    Tolerant of missing/non-directory roots. Pure/offline."""
    out: List[str] = []
    seen: set = set()
    for root in roots or []:
        root = str(root) if root else ''
        if not root or not os.path.isdir(root):
            continue
        for dirpath, _dirs, files in os.walk(root):
            for name in sorted(files):
                if os.path.splitext(name)[1].lower() not in DOCUMENT_SCAN_EXTENSIONS:
                    continue
                p = os.path.join(dirpath, name)
                try:
                    if os.path.getsize(p) > max_size:
                        continue
                except OSError:
                    continue
                rp = os.path.realpath(p)
                if rp in seen:
                    continue
                seen.add(rp)
                out.append(p)
                if len(out) >= limit:
                    return out
    return out


def analyze_documents(paths, *, locations: Optional[Dict] = None) -> Dict:
    """Analyse many documents → ``{documents, findings, summary}``.

    ``locations`` optionally maps a path → its finding location (e.g. the original
    URL). ``findings`` is the flattened raw list ready to fold into the vuln phase
    (T2.5); ``summary`` carries compact counts for the report card."""
    locations = locations or {}
    documents: List[Dict] = []
    findings: List[Dict] = []
    with_text = 0
    for path in paths or []:
        doc = analyze_document(path, location=locations.get(str(path)))
        documents.append(doc)
        if doc.get('text_chars'):
            with_text += 1
        findings.extend(doc.get('findings') or [])
    return {
        'documents': documents,
        'findings': findings,
        'summary': {
            'documents': len(documents),
            'with_text': with_text,
            'findings': len(findings),
        },
    }
