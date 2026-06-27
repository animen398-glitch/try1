"""T17: secret redaction guards — the non-leaking primitives never carry a full
secret, and the operations journal never receives report secret content. Pins the
redaction posture so a future change can't regress it. Offline.

Audit note: secret findings persist a masked discriminator (mask_value); raw
values live only in local scan artifacts and the LAN console, both documented
by-design. operations.db metadata and logs do not carry raw secrets.
"""
import json

from core.collection_runner import CollectionRunner
from core.finding_fingerprint import mask_value, secret_discriminator

_RAW = 'AKIAZ7QWUNIQUE0SECRETTAIL1234567890ABCDEF'  # long; no placeholder words


def test_mask_value_never_contains_full_secret():
    masked = mask_value(_RAW)
    assert _RAW not in masked
    assert masked.endswith(str(len(_RAW)))  # only a short prefix + length hint
    assert len(masked) < len(_RAW)


def test_secret_discriminator_has_no_plaintext():
    disc = secret_discriminator('AWS Access Key', _RAW)
    assert _RAW not in disc
    assert disc.startswith('aws access key:')


def test_operation_metadata_excludes_report_secrets():
    report = {
        'scan_id': 's1', 'domain': 'x.com', 'status': 'Success',
        'phases': {'api': {'status': 'Success',
                           'secrets': [{'type': 'AWS', 'match': _RAW}]}},
        'warnings': [],
    }
    meta = CollectionRunner._operation_metadata(report)
    # operations.db keeps only counts/status — never report secret content.
    assert _RAW not in json.dumps(meta, default=str)
