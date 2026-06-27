"""T15: start_scan never reuses a directory — two runs in the same second get
distinct, fresh scan dirs (no mixed artifacts). Offline."""
from core.project import ProjectStore


def test_start_scan_unique_same_second(tmp_path):
    proj = ProjectStore(tmp_path).get_or_create('https://example.com')
    d1 = proj.start_scan('20260628_120000')
    d2 = proj.start_scan('20260628_120000')  # same stamp → must not collide
    d3 = proj.start_scan('20260628_120000')

    assert len({d1, d2, d3}) == 3
    assert d1.name == '20260628_120000'
    assert d2.name == '20260628_120000-2'
    assert d3.name == '20260628_120000-3'
    assert d1.is_dir() and d2.is_dir() and d3.is_dir()


def test_start_scan_default_stamp(tmp_path):
    proj = ProjectStore(tmp_path).get_or_create('https://example.com')
    d = proj.start_scan()
    assert d.is_dir()
    assert d.parent.name == 'scans'
