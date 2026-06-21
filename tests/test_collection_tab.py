"""Collection tab presentation helpers."""

from gui.tab_collection import FinalReportTabMixin


def test_collection_warning_formatter_includes_stage_message_and_error():
    warning = {
        'stage': 'findings_sync',
        'message': 'Findings sync failed',
        'error': 'db down',
    }

    assert (FinalReportTabMixin._format_collection_warning(warning)
            == 'findings_sync: Findings sync failed — db down')


def test_collection_warning_formatter_tolerates_plain_values():
    assert FinalReportTabMixin._format_collection_warning('plain warning') == 'plain warning'
