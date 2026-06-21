"""Tests for the optional-feature detection module."""

from core import features


def test_summary_has_all_features():
    s = features.summary()
    assert set(s) == set(features.OPTIONAL_FEATURES)
    for entry in s.values():
        assert isinstance(entry["available"], bool)
        assert isinstance(entry["enables"], str) and entry["enables"]


def test_detectors_return_bool():
    for fn in (features.has_playwright, features.has_ytdlp, features.has_ffmpeg,
               features.has_fastapi, features.has_lxml, features.has_bbot):
        assert isinstance(fn(), bool)


def test_bbot_registered_as_optional_external():
    # BBOT (AGPL) is an optional, external tool — present in the feature registry
    # and classified as a manual (non-pip) component in the launcher.
    assert 'bbot' in features.OPTIONAL_FEATURES
    assert features.OPTIONAL_FEATURES['bbot'][1] is features.has_bbot
    from core import launcher
    comp = launcher.installable_components()
    assert comp['bbot']['method'] == 'manual'
    assert 'github.com/blacklanternsecurity/bbot' in comp['bbot']['url']


def test_missing_is_subset_of_features():
    miss = features.missing()
    assert isinstance(miss, list)
    assert set(miss).issubset(set(features.OPTIONAL_FEATURES))


def test_summary_consistent_with_missing():
    s = features.summary()
    miss = set(features.missing())
    for name, entry in s.items():
        assert (name in miss) == (not entry["available"])


def test_stdlib_module_detected():
    # A guaranteed-present stdlib module resolves True via the helper.
    assert features._has_module("json") is True
    assert features._has_module("definitely_not_a_real_module_xyz") is False
